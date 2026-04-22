"""Freedium scraper and RAG processor for the Script Writer skill.

This module provides two classes:

* ``FreediumScraper`` – fetches Medium articles through the
  ``freedium-mirror.cfd`` paywall-bypass proxy.  Uses ``DrissionPage``
  (``SessionPage``) by default with an automatic fallback to
  ``Playwright`` when the dependency is unavailable or the request fails.

* ``RAGProcessor`` – chunks scraped text and stores sentence-transformer
  embeddings in a FAISS vector index for retrieval-augmented generation.
  Falls back gracefully when optional heavy dependencies
  (``faiss``, ``sentence_transformers``) are not installed.
"""

from __future__ import annotations

import logging
from typing import List

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional heavy dependencies – all guarded so the module can be imported
# even in a minimal environment without these packages.
# ---------------------------------------------------------------------------

try:
    # Canonical import casing per Context7/DrissionPage docs: capital D
    from DrissionPage import SessionPage  # type: ignore[import]
    _HAS_DRISSION = True
except ImportError:
    _HAS_DRISSION = False

try:
    from playwright.sync_api import sync_playwright  # type: ignore[import]
    _HAS_PLAYWRIGHT = True
except ImportError:
    _HAS_PLAYWRIGHT = False

try:
    import faiss  # type: ignore[import]
    import numpy as np  # type: ignore[import]
    _HAS_FAISS = True
except ImportError:
    _HAS_FAISS = False

try:
    from sentence_transformers import SentenceTransformer  # type: ignore[import]
    _HAS_ST = True
except ImportError:
    _HAS_ST = False


# ---------------------------------------------------------------------------
# FreediumScraper
# ---------------------------------------------------------------------------


class FreediumScraper:
    """Fetches Medium articles via the Freedium paywall-bypass proxy.

    Parameters
    ----------
    use_playwright:
        Force the Playwright back-end instead of DrissionPage.
    """

    _FREEDIUM_BASE = "https://freedium-mirror.cfd/"
    _USER_AGENT = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )

    def __init__(self, use_playwright: bool = False) -> None:
        self.use_playwright = use_playwright

    def scrape(self, medium_url: str) -> str:
        """Scrape *medium_url* via Freedium and return the article text.

        Falls back from DrissionPage → Playwright → requests in order of
        availability.  Returns an empty string on total failure.
        """
        freedium_url = self._FREEDIUM_BASE + medium_url.lstrip("/")
        logger.info("Initiating scrape for: %s", freedium_url)

        if self.use_playwright or not _HAS_DRISSION:
            return self._playwright_fallback(freedium_url)

        try:
            page = SessionPage()
            page.get(freedium_url)
            article_ele = page.ele("xpath://article")
            if article_ele:
                return article_ele.text
            logger.warning("Article element not found via DrissionPage.")
            return self._playwright_fallback(freedium_url)
        except Exception as exc:  # noqa: BLE001
            logger.warning("DrissionPage failed: %s. Falling back to Playwright.", exc)
            return self._playwright_fallback(freedium_url)

    def _playwright_fallback(self, url: str) -> str:
        """Playwright fallback with basic stealth headers."""
        if not _HAS_PLAYWRIGHT:
            logger.error("Playwright not installed; cannot scrape %s", url)
            return ""

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(user_agent=self._USER_AGENT)
                page = context.new_page()
                page.goto(url, wait_until="networkidle")
                content = page.inner_text("article")
                browser.close()
                return content
        except Exception as exc:  # noqa: BLE001
            logger.error("Playwright fallback failed for %s: %s", url, exc)
            return ""


# ---------------------------------------------------------------------------
# RAGProcessor
# ---------------------------------------------------------------------------


class RAGProcessor:
    """Chunks text and stores embeddings in a FAISS vector index.

    Falls back to a plain in-memory list search when ``faiss`` or
    ``sentence_transformers`` are not installed.
    """

    def __init__(self) -> None:
        self.chunks: List[str] = []
        self._faiss_available = _HAS_FAISS and _HAS_ST

        if self._faiss_available:
            self._model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
            # get_sentence_embedding_dimension() is the legacy name; the current
            # API is get_embedding_dimension().  We try the modern name first and
            # fall back for older installs (Context7 / sentence-transformers docs).
            if hasattr(self._model, "get_embedding_dimension"):
                self._dim = self._model.get_embedding_dimension()
            else:
                self._dim = self._model.get_sentence_embedding_dimension()
            self._index = faiss.IndexFlatL2(self._dim)
        else:
            logger.warning(
                "faiss or sentence_transformers not installed; "
                "falling back to keyword-based retrieval."
            )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def chunk_and_embed(self, text: str, chunk_size: int = 1500) -> None:
        """Split *text* into word-chunks and add them to the index."""
        words = text.split()
        for i in range(0, len(words), chunk_size):
            chunk = " ".join(words[i : i + chunk_size])
            self.chunks.append(chunk)
            if self._faiss_available:
                embedding = self._model.encode([chunk])
                self._index.add(np.array(embedding).astype("float32"))

    def retrieve(self, query: str, top_k: int = 3) -> List[str]:
        """Return the *top_k* most relevant chunks for *query*.

        Uses FAISS nearest-neighbour search when available, otherwise falls
        back to a simple substring match on stored chunks.
        """
        if not self.chunks:
            return []

        if self._faiss_available:
            query_emb = self._model.encode([query])
            _distances, indices = self._index.search(
                np.array(query_emb).astype("float32"), top_k
            )
            return [
                self.chunks[i] for i in indices[0] if i < len(self.chunks)
            ]

        # Keyword fallback
        lower_query = query.lower()
        scored = [
            (c.lower().count(lower_query), c)
            for c in self.chunks
        ]
        scored.sort(key=lambda x: x[0], reverse=True)
        return [c for _, c in scored[:top_k] if _]

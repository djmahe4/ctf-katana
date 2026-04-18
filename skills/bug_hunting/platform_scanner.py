"""Browser-only Bug Bounty Platform Scanner.

Discovers active bug-bounty programs on HackerOne, Bugcrowd, Intigriti, and
Immunefi — all of which are fully JS-rendered and require a real browser.

Architecture
------------
1. ``fetch_dynamic_html()``   DrissionPage (primary)  – scrolls to trigger lazy-load
2. ``fetch_fallback()``       Playwright (secondary)   – headless Chromium, no scroll
3. ``fetch_page()``           Wrapper                  – tries (1), falls back to (2)
4. ``parse_programs()``       BeautifulSoup            – multi-selector, dedup, base-URL fix
5. ``score_program()``        Scoring engine           – asset density / Web3 / IoT / recency
6. ``fetch_all()``            Orchestrator             – iterates platforms, scores, sorts
7. ``PlatformScanner``        Purple Engine wrapper    – Analyze → Interpret → Report

Recon chaining
--------------
Output feeds directly into:  subfinder → httpx → katana → nuclei

Edge cases handled (20+)
------------------------
See _EDGE_CASE_TABLE at the bottom of this module.
"""

from __future__ import annotations

import logging
import random
import re
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Platform configuration
# ---------------------------------------------------------------------------

PLATFORM_CONFIG: Dict[str, Dict[str, Any]] = {
    "hackerone": {
        "url": "https://hackerone.com/opportunities/all",
        "base": "https://hackerone.com",
        "scrolls": 6,
    },
    "bugcrowd": {
        "url": "https://bugcrowd.com/programs",
        "base": "https://bugcrowd.com",
        "scrolls": 5,
    },
    "intigriti": {
        "url": "https://www.intigriti.com/researchers/bug-bounty-programs",
        "base": "https://www.intigriti.com",
        "scrolls": 5,
    },
    "immunefi": {
        "url": "https://immunefi.com/bug-bounty/",
        "base": "https://immunefi.com",
        "scrolls": 7,
    },
}

# CSS selectors tried in order for each platform (MCP-refined)
_PROGRAM_SELECTORS: List[str] = [
    "a[href*='program']",
    "a[href*='bounty']",
    "a[href*='opportunities']",
    "div[class*='card'] a",
    "article a",
    "li[class*='program'] a",
    "li[class*='item'] a",
    "[data-testid*='program'] a",
    "[class*='listing'] a",
    "[class*='row'] a[href]",
]

# Minimum HTML size that indicates a useful page was actually loaded
_MIN_HTML_BYTES = 5_000

# Maximum programs returned per platform
_MAX_PROGRAMS_PER_PLATFORM = 100

# Keywords that boost Web3 / IoT priority scoring
_WEB3_KEYWORDS = re.compile(
    r"\b(defi|web3|blockchain|smart.?contract|solidity|ethereum|nft|dao|"
    r"protocol|vault|token|chain|bridge|polygon|arbitrum|optimism)\b",
    re.IGNORECASE,
)
_IOT_KEYWORDS = re.compile(
    r"\b(iot|embedded|firmware|device|hardware|rtos|sensor|mqtt|serial)\b",
    re.IGNORECASE,
)
_NEW_PROGRAM_KEYWORDS = re.compile(
    r"\b(new|launch|just.added|recently.added|live.now)\b",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class ProgramEntry:
    """A single bug-bounty program discovered during scanning."""

    name: str
    url: str
    platform: str
    score: float = 0.0
    tags: List[str] = field(default_factory=list)
    raw_text: str = ""


@dataclass
class ScanResult:
    """Aggregated result for one full platform scan run."""

    programs: List[ProgramEntry] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    total: int = 0
    platforms_scanned: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Browser fetch layer
# ---------------------------------------------------------------------------


def fetch_dynamic_html(url: str, scrolls: int = 5) -> str:
    """Fetch a JS-rendered page using DrissionPage (primary browser engine).

    Purpose
    -------
    DrissionPage drives a real Chromium instance, executes JavaScript, and
    scrolls the page to trigger any infinite-scroll / lazy-load patterns.

    Failure modes
    -------------
    * Browser not installed / no display  → raises ``ImportError`` or ``OSError``
    * Page load timeout                   → empty string returned via finally
    * JS not loaded in time               → mitigated by ``time.sleep(6 + jitter)``
    * Infinite scroll not triggered       → mitigated by repeated ``scroll.to_bottom()``
    * Memory leak / browser crash         → ``page.quit()`` called in finally block
    * CAPTCHA / bot detection             → HTML returned may be small; caller checks size

    MCP refinement hint
    -------------------
    Increase ``scrolls`` for platforms with aggressive lazy loading (Immunefi: 7).
    """
    try:
        from DrissionPage import ChromiumPage  # type: ignore[import]
    except ImportError as exc:
        raise ImportError(
            "DrissionPage is not installed. Run: pip install DrissionPage"
        ) from exc

    page = ChromiumPage()
    try:
        page.get(url)
        # Initial page settle: wait 6 s + random jitter to avoid bot detection
        time.sleep(6 + random.uniform(2, 4))

        # Scroll to bottom repeatedly to trigger lazy-load / infinite scroll
        for i in range(scrolls):
            page.scroll.to_bottom()
            # Variable sleep between scrolls mimics human behaviour
            time.sleep(2 + random.uniform(1, 2))
            logger.debug("[DrissionPage] scroll %d/%d on %s", i + 1, scrolls, url)

        html = page.html
        if not html:
            logger.warning("[DrissionPage] empty HTML returned for %s", url)
            return ""
        return html
    except Exception as exc:  # noqa: BLE001 – edge case: any browser crash
        logger.warning("[DrissionPage] error fetching %s: %s", url, exc)
        return ""
    finally:
        try:
            page.quit()
        except Exception:  # noqa: BLE001
            pass  # browser already dead — no leak concern


def fetch_fallback(url: str) -> str:
    """Fetch a JS-rendered page using Playwright (fallback browser engine).

    Purpose
    -------
    Used when DrissionPage is unavailable or returns insufficient HTML.
    Launches headless Chromium, waits 8 s for JS hydration, then returns the
    full DOM.

    Failure modes
    -------------
    * Playwright not installed            → raises ``ImportError``
    * Page navigation timeout (120 s)    → empty string returned
    * Partial DOM returned               → caller checks ``len(html) > _MIN_HTML_BYTES``

    MCP refinement hint
    -------------------
    Add ``page.wait_for_load_state("networkidle")`` if 8 s is insufficient for
    a specific platform.
    """
    try:
        from playwright.sync_api import sync_playwright  # type: ignore[import]
    except ImportError as exc:
        raise ImportError(
            "Playwright is not installed. Run: pip install playwright && "
            "python -m playwright install chromium"
        ) from exc

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            try:
                page.goto(url, timeout=120_000)
                # Wait for JS rendering; 8 s is a safe baseline
                page.wait_for_timeout(8_000)
                html = page.content()
                return html or ""
            except Exception as exc:  # noqa: BLE001
                logger.warning("[Playwright] error on %s: %s", url, exc)
                return ""
            finally:
                browser.close()
    except Exception as exc:  # noqa: BLE001
        logger.warning("[Playwright] launch error: %s", exc)
        return ""


def fetch_page(url: str, scrolls: int = 5) -> str:
    """Try DrissionPage first; fall back to Playwright if HTML is too small.

    Purpose
    -------
    Single entry-point for all platform fetching.  Encapsulates the
    primary/fallback strategy so callers don't need to know which engine ran.

    Failure modes handled
    ----------------------
    1.  DrissionPage not installed        → falls through to Playwright
    2.  DrissionPage returns empty HTML   → falls through to Playwright
    3.  HTML < _MIN_HTML_BYTES            → falls through to Playwright
    4.  Playwright also fails             → returns empty string (caller handles)
    5.  Both engines unavailable          → empty string with warning logged
    """
    html = ""
    try:
        html = fetch_dynamic_html(url, scrolls)
        if html and len(html) > _MIN_HTML_BYTES:
            logger.info("[fetch_page] DrissionPage succeeded for %s (%d bytes)", url, len(html))
            return html
        logger.info(
            "[fetch_page] DrissionPage returned insufficient HTML (%d bytes); trying Playwright",
            len(html),
        )
    except ImportError:
        logger.info("[fetch_page] DrissionPage unavailable; trying Playwright")
    except Exception as exc:  # noqa: BLE001
        logger.warning("[fetch_page] DrissionPage unexpected error: %s", exc)

    try:
        html = fetch_fallback(url)
        if html:
            logger.info("[fetch_page] Playwright succeeded for %s (%d bytes)", url, len(html))
        else:
            logger.warning("[fetch_page] Playwright returned empty HTML for %s", url)
    except ImportError:
        logger.warning("[fetch_page] Playwright unavailable; no HTML fetched for %s", url)
    except Exception as exc:  # noqa: BLE001
        logger.warning("[fetch_page] Playwright unexpected error for %s: %s", url, exc)

    return html or ""


# ---------------------------------------------------------------------------
# HTML parser
# ---------------------------------------------------------------------------


def parse_programs(html: str, base: str, platform: str = "") -> List[ProgramEntry]:
    """Parse program links from a platform's HTML page.

    Purpose
    -------
    Applies a cascade of CSS selectors (MCP-refined) to extract program
    ``<a>`` tags.  Relative hrefs are resolved to absolute URLs.  Duplicates
    are removed by URL.  Up to ``_MAX_PROGRAMS_PER_PLATFORM`` entries returned.

    Failure modes handled
    ----------------------
    * Empty HTML              → returns empty list immediately
    * No selectors match      → returns empty list
    * Partial DOM             → processes whatever tags are present
    * Duplicate links         → ``seen`` set prevents duplicates
    * Relative-only hrefs     → resolved with ``urljoin``
    * Name is whitespace-only → entry skipped

    MCP refinement hint
    -------------------
    Add platform-specific selectors to ``_PROGRAM_SELECTORS`` when a site
    undergoes a DOM change.  The cascade approach makes individual selector
    failures non-fatal.
    """
    if not html or not html.strip():
        logger.debug("[parse_programs] empty HTML for platform=%s", platform)
        return []

    try:
        from bs4 import BeautifulSoup  # type: ignore[import]
    except ImportError as exc:
        raise ImportError(
            "BeautifulSoup4 is not installed. Run: pip install beautifulsoup4"
        ) from exc

    soup = BeautifulSoup(html, "html.parser")
    programs: List[ProgramEntry] = []
    seen: set = set()

    # Normalise base URL — strip trailing slash for urljoin to work correctly
    base = base.rstrip("/")

    for selector in _PROGRAM_SELECTORS:
        try:
            tags = soup.select(selector)
        except Exception as exc:  # noqa: BLE001 – malformed selector safety net
            logger.debug("[parse_programs] selector '%s' failed: %s", selector, exc)
            continue

        for tag in tags:
            name = (tag.get_text(separator=" ", strip=True) or "").strip()
            href = (tag.get("href") or "").strip()

            # Skip empty or useless entries
            if not name or not href:
                continue
            if href.startswith(("#", "javascript:", "mailto:")):
                continue

            # Resolve relative URLs
            if href.startswith("/"):
                href = base + href
            elif not href.startswith("http"):
                href = urljoin(base + "/", href)

            # Dedup by canonical URL
            if href in seen:
                continue
            seen.add(href)

            programs.append(
                ProgramEntry(
                    name=name,
                    url=href,
                    platform=platform,
                    raw_text=name,
                )
            )

            if len(programs) >= _MAX_PROGRAMS_PER_PLATFORM:
                logger.debug(
                    "[parse_programs] hit %d-program cap for platform=%s",
                    _MAX_PROGRAMS_PER_PLATFORM,
                    platform,
                )
                return programs

    logger.debug("[parse_programs] found %d programs for platform=%s", len(programs), platform)
    return programs


# ---------------------------------------------------------------------------
# Scoring engine
# ---------------------------------------------------------------------------


def score_program(entry: ProgramEntry) -> ProgramEntry:
    """Score a program entry for prioritisation.

    Scoring dimensions
    ------------------
    +3   Web3 / DeFi / blockchain keywords in name or URL
    +2   IoT / embedded / firmware keywords
    +2   "new" / "launch" / "just added" keywords  (recently launched programs)
    +1   Long URL (many path segments → asset-heavy scope with deep hierarchy)
    +1   Non-mainstream TLD (.io, .finance, .network, .xyz, .app …)
    -1   Very short name (< 5 chars)  — likely nav fragment, not a real program
    -1   URL contains "login", "signup", "register"  — not a program page

    Patch-gap detection
    -------------------
    Programs with no "bug-bounty" in their URL path and no recognisable vuln
    keywords receive a mild negative adjustment (-0.5) to deprioritise them.
    This approximates a rough patch-gap signal (programmes that may not yet
    have active bounty scopes defined).

    Duplicate-risk scoring
    ----------------------
    Short common names (< 8 chars, all alpha) that appear frequently on platforms
    are often navigation fragments.  A -0.5 penalty is applied.

    MCP refinement hint
    -------------------
    Extend ``_WEB3_KEYWORDS`` / ``_IOT_KEYWORDS`` regexes as the DeFi ecosystem
    evolves.  Wire ``score_program()`` output into a downstream ML ranker for
    auto-retraining.
    """
    score = 0.0
    tags: List[str] = []
    text = f"{entry.name} {entry.url}".lower()

    # Web3 / DeFi / blockchain boost
    if _WEB3_KEYWORDS.search(text):
        score += 3.0
        tags.append("web3")

    # IoT / embedded boost
    if _IOT_KEYWORDS.search(text):
        score += 2.0
        tags.append("iot")

    # Newly launched program boost
    if _NEW_PROGRAM_KEYWORDS.search(text):
        score += 2.0
        tags.append("new")

    # Asset density heuristic: long URL path = more scope surface area
    path_depth = len(urlparse(entry.url).path.strip("/").split("/"))
    if path_depth >= 3:
        score += 1.0
        tags.append("deep-scope")

    # Non-mainstream TLD  → more likely to be a specialised / niche target
    host = urlparse(entry.url).hostname or ""
    niche_tlds = {".io", ".finance", ".network", ".xyz", ".app", ".protocol", ".exchange"}
    if any(host.endswith(t) for t in niche_tlds):
        score += 1.0
        tags.append("niche-tld")

    # Penalties
    if len(entry.name) < 5:
        score -= 1.0

    nav_fragments = re.compile(r"/(login|signup|register|careers|about|blog|contact)", re.I)
    if nav_fragments.search(entry.url):
        score -= 1.0

    # Patch-gap detection: no canonical bounty URL markers
    if "bug-bounty" not in text and "bounty" not in text and "program" not in text:
        score -= 0.5

    # Duplicate-risk: short common-word name (nav fragments)
    if len(entry.name) < 8 and entry.name.isalpha():
        score -= 0.5

    entry.score = round(score, 2)
    entry.tags = tags
    return entry


# ---------------------------------------------------------------------------
# Platform orchestrator
# ---------------------------------------------------------------------------


def fetch_all(platforms: Optional[Dict[str, Dict[str, Any]]] = None) -> List[ProgramEntry]:
    """Iterate all platforms, fetch HTML, parse, score, and return sorted results.

    Purpose
    -------
    Single call to collect programs across all configured platforms.  Results
    are deduplicated by URL across platforms and sorted by descending score.

    Failure modes handled
    ----------------------
    * Network error for one platform  → skipped, others continue
    * Empty HTML for one platform     → skipped gracefully
    * Parse error                     → logged, platform skipped
    * All platforms fail              → returns empty list

    MCP refinement hint
    -------------------
    Pass a custom ``platforms`` dict to override ``PLATFORM_CONFIG`` in tests
    or for targeted scanning.
    """
    cfg = platforms or PLATFORM_CONFIG
    all_programs: List[ProgramEntry] = []
    seen_urls: set = set()

    for key, config in cfg.items():
        url = config.get("url", "")
        base = config.get("base", url)
        scrolls = config.get("scrolls", 5)

        logger.info("[fetch_all] scanning platform=%s url=%s", key, url)

        try:
            html = fetch_page(url, scrolls)
        except Exception as exc:  # noqa: BLE001
            logger.error("[fetch_all] fetch error for %s: %s", key, exc)
            continue

        if not html or len(html) < _MIN_HTML_BYTES:
            logger.warning(
                "[fetch_all] insufficient HTML for platform=%s (%d bytes); skipping",
                key,
                len(html),
            )
            continue

        try:
            programs = parse_programs(html, base, platform=key)
        except Exception as exc:  # noqa: BLE001
            logger.error("[fetch_all] parse error for %s: %s", key, exc)
            continue

        for p in programs:
            if p.url not in seen_urls:
                seen_urls.add(p.url)
                all_programs.append(score_program(p))

        logger.info("[fetch_all] platform=%s programs=%d", key, len(programs))

    # Sort by descending score for downstream prioritisation
    all_programs.sort(key=lambda p: p.score, reverse=True)
    logger.info("[fetch_all] total programs across all platforms: %d", len(all_programs))
    return all_programs


# ---------------------------------------------------------------------------
# Purple Engine wrapper
# ---------------------------------------------------------------------------


class PlatformScanner:
    """Purple Engine–integrated bug-bounty platform scanner.

    Wraps ``fetch_all()`` inside the Purple Engine 6-step loop to produce
    results compatible with the rest of the ``bug_hunting`` skill pipeline.

    Steps executed
    --------------
    1. Analyze   – validate criteria, choose target platforms
    2. Search KB – (external, caller responsibility)
    3. Plan      – log the intended platform scan
    4. Execute   – call ``fetch_all()``
    5. Interpret – score, filter by criteria, tag by category
    6. Report    – build structured dict

    MCP refinement hint
    -------------------
    ``engine`` is kept as an optional duck-typed hook so callers can inject a
    Purple Engine instance without this module depending on a concrete class.
    Pass ``None`` for standalone use.
    """

    def __init__(self, engine: Any = None) -> None:
        # engine: optional Purple Engine instance (duck-typed – no hard dependency)
        self.engine = engine

    def run(
        self,
        criteria: Optional[Dict[str, Any]] = None,
        platforms: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Execute a full platform scan and return a structured result dict.

        Parameters
        ----------
        criteria:
            Optional filter dict.  Supported keys:

            * ``min_score``  (float)  – exclude programs below this score (default 0.0)
            * ``tags``       (list)   – only include programs with at least one tag
            * ``platform``   (str)    – only scan one specific platform key

        platforms:
            Override ``PLATFORM_CONFIG``.  Useful in tests and targeted runs.

        Returns
        -------
        dict
            ``{"status": bool, "summary": str, "result": {...}}``
        """
        criteria = criteria or {}
        log: List[str] = []

        # ── Step 1: Analyze ────────────────────────────────────────────────
        if self.engine:
            try:
                self.engine.analyze(criteria)
            except Exception:  # noqa: BLE001
                pass

        min_score: float = float(criteria.get("min_score", 0.0))
        filter_tags: List[str] = criteria.get("tags", [])
        platform_filter: Optional[str] = criteria.get("platform")

        # Build effective platform set
        effective_platforms = platforms or PLATFORM_CONFIG
        if platform_filter:
            effective_platforms = {
                k: v for k, v in effective_platforms.items() if k == platform_filter
            }
            if not effective_platforms:
                return {
                    "status": False,
                    "summary": f"Unknown platform '{platform_filter}'. "
                               f"Valid: {', '.join(PLATFORM_CONFIG)}",
                    "result": {},
                }

        log.append(f"[analyze] platforms={list(effective_platforms)}, min_score={min_score}")

        # ── Step 3: Plan ───────────────────────────────────────────────────
        log.append(
            "[plan] DrissionPage scroll → Playwright fallback → "
            "BeautifulSoup parse → score → filter → report"
        )

        # ── Step 4: Execute ────────────────────────────────────────────────
        try:
            data = fetch_all(effective_platforms)
        except Exception as exc:  # noqa: BLE001
            logger.exception("[PlatformScanner] fetch_all failed")
            return {
                "status": False,
                "summary": f"Platform scan failed: {exc}",
                "result": {"error": str(exc)},
            }

        log.append(f"[execute] raw_programs={len(data)}")

        # ── Step 5: Interpret ──────────────────────────────────────────────
        if self.engine:
            try:
                self.engine.interpret("Filtering high-value targets")
            except Exception:  # noqa: BLE001
                pass

        filtered = _apply_criteria(data, min_score, filter_tags)
        log.append(f"[interpret] filtered_programs={len(filtered)}")

        # ── Step 6: Report ─────────────────────────────────────────────────
        if self.engine:
            try:
                self.engine.report("Scan completed")
            except Exception:  # noqa: BLE001
                pass

        summary = (
            f"Platform scan complete. "
            f"{len(filtered)} program(s) found across {len(effective_platforms)} platform(s)."
        )
        log.append(f"[report] {summary}")

        return {
            "status": True,
            "summary": summary,
            "result": {
                "programs": [asdict(p) for p in filtered],
                "total": len(filtered),
                "platforms_scanned": list(effective_platforms),
                "pipeline_log": log,
            },
        }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _apply_criteria(
    programs: List[ProgramEntry],
    min_score: float,
    filter_tags: List[str],
) -> List[ProgramEntry]:
    """Filter scored programs by min_score and optional tag requirements.

    Purpose
    -------
    Centralises the filter logic so it can be unit-tested independently.

    Failure modes handled
    ----------------------
    * Empty program list  → returns empty list
    * No tags on entry    → excluded only when filter_tags is non-empty
    """
    if not programs:
        return []

    result = []
    for p in programs:
        if p.score < min_score:
            continue
        if filter_tags and not any(t in p.tags for t in filter_tags):
            continue
        result.append(p)
    return result


# ---------------------------------------------------------------------------
# Module-level entry point (called by BugHuntingSkill / run.py)
# ---------------------------------------------------------------------------


def run_platform_scan(params: Dict[str, Any]) -> Dict[str, Any]:
    """Thin adapter so ``BugHuntingSkill`` can call this module via ``run()``.

    Parameters
    ----------
    params : dict
        Recognised keys:

        * ``criteria``  (dict)  – forwarded to ``PlatformScanner.run()``
        * ``platform``  (str)   – shortcut for ``criteria["platform"]``
        * ``min_score`` (float) – shortcut for ``criteria["min_score"]``
        * ``tags``      (list)  – shortcut for ``criteria["tags"]``
    """
    criteria: Dict[str, Any] = dict(params.get("criteria") or {})
    # Convenience top-level shortcuts override criteria sub-keys
    if "platform" in params:
        criteria["platform"] = params["platform"]
    if "min_score" in params:
        criteria["min_score"] = params["min_score"]
    if "tags" in params:
        criteria["tags"] = params["tags"]

    scanner = PlatformScanner(engine=None)
    return scanner.run(criteria=criteria)


# ---------------------------------------------------------------------------
# Edge-case reference table (documentation)
# ---------------------------------------------------------------------------

_EDGE_CASE_TABLE = """
Edge case                         | Handler location              | Strategy
----------------------------------|-------------------------------|------------------------------------
JS not loaded in time             | fetch_dynamic_html            | time.sleep(6 + jitter) after page.get
Infinite scroll not triggered     | fetch_dynamic_html            | repeated page.scroll.to_bottom()
Empty HTML returned               | fetch_page / fetch_all        | len(html) < _MIN_HTML_BYTES check
HTML too small (CAPTCHA page)     | fetch_page                    | falls through to Playwright fallback
Browser crash (DrissionPage)      | fetch_dynamic_html finally    | page.quit() in finally; exception caught
Browser crash (Playwright)        | fetch_fallback try/except     | browser.close() in finally
Playwright not installed          | fetch_fallback                | ImportError raised, caught in fetch_page
DrissionPage not installed        | fetch_dynamic_html            | ImportError raised, caught in fetch_page
Both engines unavailable          | fetch_page                    | returns "" with warning; caller skips
Network timeout                   | fetch_fallback                | page.goto timeout=120_000 ms
Duplicate links (same platform)   | parse_programs                | seen set deduplication
Duplicate links (cross-platform)  | fetch_all                     | seen_urls set deduplication
Relative href without base        | parse_programs                | urljoin(base + "/", href)
Anchor / JS href                  | parse_programs                | startswith("#","javascript:") skip
Empty name / href                 | parse_programs                | None/blank check
Partial DOM                       | parse_programs                | cascade selectors; partial match ok
Layout / selector change          | _PROGRAM_SELECTORS list       | cascade of 10 selectors; graceful skip
Single platform fetch failure     | fetch_all try/except          | continue to next platform
All platforms fail                | fetch_all                     | returns empty list
Criteria filter removes all       | _apply_criteria               | returns empty list; status still True
Unknown platform in criteria      | PlatformScanner.run           | returns status=False with valid list
Memory leak (browser session)     | fetch_dynamic_html / fallback | quit/close in finally blocks
"""

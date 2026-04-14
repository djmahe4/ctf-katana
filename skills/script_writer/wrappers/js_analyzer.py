"""JSAnalyzer – extracts and validates endpoints from JavaScript files.

Parses JS content for relative URL strings, then validates each endpoint with
a lightweight HEAD request to identify live resources.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List
from urllib.parse import urljoin

import requests

logger = logging.getLogger(__name__)

# Matches string literals that look like relative URL paths,
# e.g.  "/api/v1/users"  "/admin/dashboard?id=1"
_ENDPOINT_RE = re.compile(r'"(/[a-zA-Z0-9_/?=&\-\.#%+]+)"')

# Matches bearer tokens, API keys, and generic secrets in JS source
_SECRET_RE = re.compile(
    r'(?:api[_-]?key|token|secret|password|apikey|auth)\s*[:=]\s*'
    r'["\']([A-Za-z0-9\-_]{10,})["\']',
    re.IGNORECASE,
)


class JSAnalyzer:
    """Analyzes JavaScript files for hardcoded secrets and live endpoints.

    Parameters
    ----------
    base_url:
        The base URL used to resolve relative endpoint paths.
    timeout:
        HTTP request timeout in seconds (default ``5``).
    valid_statuses:
        HTTP status codes considered as "the endpoint exists"
        (default ``{200, 401, 403}``).
    """

    def __init__(
        self,
        base_url: str,
        timeout: int = 5,
        valid_statuses: frozenset[int] | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.valid_statuses = valid_statuses or frozenset({200, 401, 403})
        self._session = requests.Session()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze_file(self, js_content: str) -> Dict[str, Any]:
        """Extract endpoints and secrets from *js_content*.

        Returns
        -------
        dict
            ``{"endpoints": [...], "secrets": [...]}``

            Each endpoint entry is ``{"url": "...", "status": <int>}``.
            Each secret entry is the raw matched string (redacted to 4 chars).
        """
        endpoints = self._validate_endpoints(
            self._extract_endpoints(js_content)
        )
        secrets = self._extract_secrets(js_content)
        return {"endpoints": endpoints, "secrets": secrets}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _extract_endpoints(self, js_content: str) -> List[str]:
        """Return a deduplicated list of relative endpoint paths found in JS."""
        raw = _ENDPOINT_RE.findall(js_content)
        return list(dict.fromkeys(raw))  # preserve order, remove duplicates

    def _validate_endpoints(
        self, endpoints: List[str]
    ) -> List[Dict[str, Any]]:
        """HEAD-request each endpoint and return those that respond.

        Uses ThreadPoolExecutor for parallel validation.
        """
        from concurrent.futures import ThreadPoolExecutor

        valid: List[Dict[str, Any]] = []

        def check_ep(ep: str) -> Optional[Dict[str, Any]]:
            full_url = urljoin(self.base_url + "/", ep.lstrip("/"))
            try:
                resp = self._session.head(
                    full_url, timeout=self.timeout, allow_redirects=True
                )
                if resp.status_code in self.valid_statuses:
                    return {"url": full_url, "status": resp.status_code}
            except requests.RequestException as exc:
                logger.debug("HEAD %s failed: %s", full_url, exc)
            return None

        with ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(check_ep, endpoints))

        for res in results:
            if res:
                valid.append(res)

        return valid

    @staticmethod
    def _extract_secrets(js_content: str) -> List[str]:
        """Return potentially hardcoded secrets found in JS source."""
        matches = _SECRET_RE.findall(js_content)
        # Redact to first 4 characters for safety
        return [m[:4] + "****" for m in matches]

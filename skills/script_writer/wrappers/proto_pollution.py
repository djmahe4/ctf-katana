"""PrototypePollutionVerifier – Playwright-based DOM verification.

Injects a ``__proto__`` payload into a target URL and evaluates whether the
property was successfully set on the ``window`` object, confirming client-side
prototype pollution.
"""

from __future__ import annotations

import logging
from urllib.parse import urlencode, urlparse, urlunparse, parse_qs

logger = logging.getLogger(__name__)

try:
    from playwright.sync_api import sync_playwright  # type: ignore[import]
    _HAS_PLAYWRIGHT = True
except ImportError:
    _HAS_PLAYWRIGHT = False

_PAYLOAD_KEY = "pp_verify_key"
_PAYLOAD_VAL = "pp_verify_value"


class PrototypePollutionVerifier:
    """Verifies client-side prototype pollution using a headless browser.

    Uses Playwright to inject a ``__proto__[key]=value`` query parameter and
    evaluates whether ``window[key]`` equals the expected value, confirming
    that the application passes ``__proto__`` properties through unsafely.

    Falls back gracefully when Playwright is not installed.
    """

    def __init__(self) -> None:
        if not _HAS_PLAYWRIGHT:
            logger.warning(
                "Playwright is not installed; "
                "PrototypePollutionVerifier will always return False.  "
                "Install with: pip install playwright && playwright install chromium"
            )

    def verify(self, target_url: str) -> bool:
        """Inject a prototype-pollution payload and evaluate the DOM.

        Parameters
        ----------
        target_url:
            Base URL to test (query parameters will be appended).

        Returns
        -------
        bool
            ``True`` if the prototype pollution was confirmed, else ``False``.
        """
        if not _HAS_PLAYWRIGHT:
            return False

        payload_url = self._build_payload_url(target_url)
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                try:
                    page.goto(
                        payload_url, wait_until="networkidle", timeout=10_000
                    )
                    is_vulnerable: bool = page.evaluate(
                        f"() => window['{_PAYLOAD_KEY}'] === '{_PAYLOAD_VAL}'"
                    )
                    if is_vulnerable:
                        logger.critical(
                            "Prototype pollution confirmed at %s", target_url
                        )
                    return is_vulnerable
                except Exception as exc:  # noqa: BLE001
                    logger.error(
                        "Navigation failed for %s: %s", payload_url, exc
                    )
                    return False
                finally:
                    browser.close()
        except Exception as exc:  # noqa: BLE001
            logger.error("Playwright error: %s", exc)
            return False

    @staticmethod
    def _build_payload_url(base_url: str) -> str:
        """Append the ``__proto__`` test parameters to *base_url*."""
        parsed = urlparse(base_url)
        params = parse_qs(parsed.query)
        params[f"__proto__[{_PAYLOAD_KEY}]"] = [_PAYLOAD_VAL]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

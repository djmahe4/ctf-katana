"""OOBValidator – asynchronous Out-of-Band (SSRF) interaction polling.

Polls an ``interactsh``-compatible server for HTTP/DNS callbacks that confirm
Server-Side Request Forgery vulnerabilities.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class OOBValidator:
    """Validates SSRF by polling an Out-of-Band interaction server.

    Parameters
    ----------
    interactsh_url:
        Hostname of the interactsh (or compatible) server,
        e.g. ``"oast.pro"``.
    token:
        Bearer authentication token for the server API.
    max_retries:
        Number of polling attempts before giving up (default ``10``).
    retry_interval:
        Seconds to wait between attempts (default ``5``).
    """

    def __init__(
        self,
        interactsh_url: str,
        token: str,
        max_retries: int = 10,
        retry_interval: float = 5.0,
    ) -> None:
        self.server = interactsh_url
        self.token = token
        self.max_retries = max_retries
        self.retry_interval = retry_interval

    async def poll_interactions(self, correlation_id: str) -> bool:
        """Poll for a specific OOB correlation ID.

        Returns ``True`` as soon as an interaction is confirmed, or ``False``
        after all retries are exhausted.

        Parameters
        ----------
        correlation_id:
            The unique identifier embedded in the SSRF payload URL.
        """
        try:
            import aiohttp  # type: ignore[import]
        except ImportError:
            logger.error(
                "aiohttp is not installed; cannot poll OOB server.  "
                "Install it with: pip install aiohttp"
            )
            return False

        headers = {"Authorization": f"Bearer {self.token}"}
        url = (
            f"https://{self.server}/api/interactions"
            f"?correlationId={correlation_id}"
        )

        # Context7/aiohttp: create one session for all retry attempts to enable
        # connection reuse ("reusing sessions for optimal performance").
        async with aiohttp.ClientSession() as session:
            for attempt in range(1, self.max_retries + 1):
                try:
                    async with session.get(
                        url,
                        headers=headers,
                        timeout=aiohttp.ClientTimeout(total=10),
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            if data.get("data"):
                                logger.info(
                                    "SSRF confirmed! Correlation ID: %s",
                                    correlation_id,
                                )
                                return True
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "Polling attempt %d/%d failed: %s",
                        attempt,
                        self.max_retries,
                        exc,
                    )
                await asyncio.sleep(self.retry_interval)

        logger.info(
            "No OOB interaction detected for correlation ID: %s", correlation_id
        )
        return False

    def poll_sync(self, correlation_id: str) -> bool:
        """Synchronous wrapper around :meth:`poll_interactions`."""
        return asyncio.run(self.poll_interactions(correlation_id))

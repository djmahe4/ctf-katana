"""Web exploitation skill – common web CTF checks."""

from __future__ import annotations

import re
import urllib.parse

from katana.utils import safe_run


def check_robots_txt(url: str) -> str:
    """Fetch ``/robots.txt`` from a URL."""
    base = url.rstrip("/")
    return safe_run(["curl", "-sS", f"{base}/robots.txt"], timeout=10)


def dir_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt") -> str:
    """Run ``dirb`` or ``gobuster`` against a URL."""
    # Prefer gobuster if available, fall back to dirb
    result = safe_run(
        ["gobuster", "dir", "-u", url, "-w", wordlist, "-q"],
        timeout=120,
    )
    if "Command not found" in result:
        result = safe_run(["dirb", url, wordlist, "-S"], timeout=120)
    return result


def check_headers(url: str) -> str:
    """Fetch HTTP headers from *url*."""
    return safe_run(["curl", "-sSI", url], timeout=10)


def sql_injection_test(url: str) -> str:
    """Run a basic ``sqlmap`` scan against *url*."""
    return safe_run([
        "sqlmap", "-u", url,
        "--batch", "--level=1", "--risk=1",
        "--output-dir=/tmp/sqlmap_out",
    ], timeout=120)


def decode_jwt(token: str) -> dict:
    """Decode a JWT without verification (for inspection)."""
    import base64
    import json

    parts = token.split(".")
    if len(parts) < 2:
        return {"error": "Not a valid JWT"}

    result: dict = {}
    for i, name in enumerate(["header", "payload"]):
        if i >= len(parts):
            break
        padded = parts[i] + "=" * (-len(parts[i]) % 4)
        try:
            decoded = base64.urlsafe_b64decode(padded)
            result[name] = json.loads(decoded)
        except Exception as exc:
            result[name] = {"error": str(exc)}
    return result


def url_decode(encoded: str) -> str:
    """URL-decode a string."""
    return urllib.parse.unquote(encoded)


def url_encode(raw: str) -> str:
    """URL-encode a string."""
    return urllib.parse.quote(raw)

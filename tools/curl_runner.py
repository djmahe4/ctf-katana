"""Curl wrapper for HTTP requests."""

from tools import safe_run


def fetch_url(url: str, *, headers_only: bool = False, timeout: int = 10) -> str:
    """Fetch a URL with ``curl``."""
    flags = ["-sSI"] if headers_only else ["-sS"]
    return safe_run(["curl"] + flags + [url], timeout=timeout)


def check_robots_txt(url: str) -> str:
    """Fetch ``/robots.txt`` from a URL."""
    base = url.rstrip("/")
    return safe_run(["curl", "-sS", f"{base}/robots.txt"], timeout=10)


def check_headers(url: str) -> str:
    """Fetch HTTP response headers."""
    return safe_run(["curl", "-sSI", url], timeout=10)


def dir_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt") -> str:
    """Run ``gobuster`` or ``dirb`` against a URL."""
    result = safe_run(
        ["gobuster", "dir", "-u", url, "-w", wordlist, "-q"],
        timeout=120,
    )
    if "Command not found" in result:
        result = safe_run(["dirb", url, wordlist, "-S"], timeout=120)
    return result

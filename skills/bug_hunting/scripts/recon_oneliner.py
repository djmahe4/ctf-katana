#!/usr/bin/env python3
"""Extended recon one-liners for the bug_hunting skill.

These helpers wrap the canonical shell pipelines from the Purple Engine
knowledge base into Python subprocesses.  All tool invocations are designed
to be run with the actual tools installed (subfinder, dnsx, naabu, httpx,
katana, nuclei).

Usage
-----
::

    python recon_oneliner.py --target example.com --workspace /tmp/hunt

The workspace directory will contain:

* ``subs.txt``     – raw subdomains (subfinder output)
* ``resolved.txt`` – DNS-verified live subdomains
* ``ports.txt``    – open ports (naabu)
* ``alive.txt``    – HTTP/HTTPS alive endpoints (httpx)
* ``urls.txt``     – crawled URL corpus (katana)
* ``nuclei.txt``   – vulnerability scan results (nuclei)
"""

from __future__ import annotations

import argparse
import logging
import subprocess
import sys
from pathlib import Path
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)


def _run(
    cmd: List[str],
    *,
    timeout: int = 120,
    stdin: Optional[str] = None,
) -> Tuple[int, str, str]:
    """Run *cmd* and return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=stdin,
        )
        return result.returncode, result.stdout or "", result.stderr or ""
    except FileNotFoundError as exc:
        return 127, "", f"Tool not found: {exc}"
    except subprocess.TimeoutExpired:
        return 124, "", f"Timed out after {timeout}s"


def _append(path: Path, lines: str) -> None:
    """Append *lines* to *path*, deduplicating against existing content."""
    existing: set[str] = set()
    if path.exists():
        existing = set(path.read_text(encoding="utf-8").splitlines())
    new_lines = [l for l in lines.splitlines() if l.strip() and l not in existing]
    if new_lines:
        with path.open("a", encoding="utf-8") as fh:
            fh.write("\n".join(new_lines) + "\n")


def run_master_recon(target: str, workspace: str = ".") -> dict:
    """Execute the full Master Recon Pipeline against *target*.

    Parameters
    ----------
    target:
        Domain to hunt (e.g. ``"example.com"``).
    workspace:
        Directory where output files will be written.

    Returns
    -------
    dict
        ``{"status": bool, "files": {name: path}, "summary": str}``
    """
    ws = Path(workspace)
    ws.mkdir(parents=True, exist_ok=True)

    subs_file = ws / "subs.txt"
    resolved_file = ws / "resolved.txt"
    ports_file = ws / "ports.txt"
    alive_file = ws / "alive.txt"
    urls_file = ws / "urls.txt"
    nuclei_file = ws / "nuclei.txt"

    log: List[str] = []

    # Stage 1a: Passive subdomain enumeration (subfinder)
    rc, stdout, stderr = _run(
        ["subfinder", "-d", target, "-all", "-silent"], timeout=180
    )
    if rc == 0:
        _append(subs_file, stdout)
        log.append(f"subfinder: {len(stdout.splitlines())} subs found")
    else:
        log.append(f"subfinder: skipped ({stderr[:80]})")

    # Stage 1b: Active subdomain brute-forcing (shuffledns)
    # shuffledns requires a wordlist; skip gracefully if not found.
    # Canonical: shuffledns -d target.com -r resolvers.txt -w wordlist.txt
    wordlist_candidates = [
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
        "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
        "n0kovo_subdomains_huge.txt",
    ]
    resolvers_candidates = ["resolvers.txt", "/tmp/resolvers.txt"]
    shuffledns_wordlist = next((w for w in wordlist_candidates if Path(w).exists()), None)
    shuffledns_resolvers = next((r for r in resolvers_candidates if Path(r).exists()), None)
    if shuffledns_wordlist and shuffledns_resolvers:
        rc, stdout, _ = _run(
            [
                "shuffledns",
                "-d", target,
                "-r", shuffledns_resolvers,
                "-w", shuffledns_wordlist,
                "-silent",
            ],
            timeout=300,
        )
        if rc == 0:
            _append(subs_file, stdout)
            log.append(f"shuffledns: {len(stdout.splitlines())} subs found")
        else:
            log.append("shuffledns: skipped (non-zero exit)")
    else:
        log.append("shuffledns: skipped (resolvers.txt or wordlist not found)")

    # Stage 2: DNS resolution (dnsx)
    # Canonical: dnsx -l subs.txt -r resolvers.txt
    # * No -resp-only: that strips domain names to raw IPs, breaking naabu SNI.
    # * Input fed via stdin; first token of each output line is the domain name.
    subs_list = subs_file.read_text(encoding="utf-8") if subs_file.exists() else ""
    rc, stdout, _ = _run(
        ["dnsx", "-l", "-", "-silent"], timeout=120, stdin=subs_list
    )
    if rc == 0:
        # dnsx outputs "domain [ip]" – keep only the domain (first token)
        resolved_domains = "\n".join(
            line.split()[0] for line in stdout.splitlines() if line.strip()
        )
        _append(resolved_file, resolved_domains)
        log.append(f"dnsx: {len(resolved_domains.splitlines())} resolved")
    else:
        _append(resolved_file, subs_list)  # fall back to raw subs
        log.append("dnsx: skipped (falling back to raw subs)")

    # Stage 3: Port scan (naabu)
    resolved_list = (
        resolved_file.read_text(encoding="utf-8") if resolved_file.exists() else ""
    )
    rc, stdout, _ = _run(
        ["naabu", "-silent", "-rate", "1000", "-list", "-"],
        timeout=300,
        stdin=resolved_list,
    )
    if rc == 0:
        _append(ports_file, stdout)
        log.append(f"naabu: {len(stdout.splitlines())} ports found")
    else:
        log.append("naabu: skipped")

    # Stage 4: HTTP alive check (httpx)
    ports_list = ports_file.read_text(encoding="utf-8") if ports_file.exists() else ""
    rc, stdout, _ = _run(
        ["httpx", "-silent", "-l", "-"],
        timeout=180,
        stdin=ports_list,
    )
    if rc == 0:
        _append(alive_file, stdout)
        log.append(f"httpx: {len(stdout.splitlines())} alive")
    else:
        log.append("httpx: skipped")

    # Stage 5: URL crawl (katana)
    # Flags (Context7/katana confirmed):
    #   -jc       – parse JS files for additional endpoints
    #   -kf all   – crawl robots.txt, sitemap.xml and other known files
    #   -fx       – extract form/input/select elements
    #   -aff      – automatic form filling (experimental)
    #   -nc       – no-colour ANSI-safe output
    #   -ef       – extension filter (skip binary assets)
    # Note: -xhr (XHR extraction) is HEADLESS-only per Context7 docs;
    #       it is intentionally omitted here to avoid no-op errors.
    alive_list = (
        alive_file.read_text(encoding="utf-8") if alive_file.exists() else ""
    )
    rc, stdout, _ = _run(
        [
            "katana",
            "-list", "-",
            "-silent", "-nc",
            "-jc",
            "-kf", "all",
            "-fx",
            "-aff",
            "-ef", "woff,css,png,svg,jpg,woff2,jpeg,gif",
        ],
        timeout=300,
        stdin=alive_list,
    )
    if rc == 0:
        _append(urls_file, stdout)
        log.append(f"katana: {len(stdout.splitlines())} URLs collected")
    else:
        log.append("katana: skipped")

    # Stage 5b: Historical URL supplement via gau / waybackurls
    # gau aggregates URLs from AlienVault OTX, Wayback Machine, and Common Crawl.
    # waybackurls is a simpler Wayback-only alternative used as fallback.
    # Canonical: cat alive.txt | gau >> urls.txt
    # We try gau first; fall back to waybackurls if gau is unavailable.
    for url_tool in ("gau", "waybackurls"):
        rc, stdout, _ = _run([url_tool, target], timeout=120)
        if rc == 0 and stdout.strip():
            _append(urls_file, stdout)
            log.append(f"{url_tool}: {len(stdout.splitlines())} historical URLs added")
            break
        if rc == 127:  # tool not installed
            log.append(f"{url_tool}: not installed")

    # Stage 6: Vulnerability scan (nuclei)
    # Flags (Context7/nuclei confirmed):
    #   -l -          read targets from stdin
    #   -es info,unknown  exclude informational/unknown findings
    #   -ept ssl      exclude ssl protocol templates
    #   -silent       suppress progress; emit findings only
    # NOTE: -ss / --scan-strategy does NOT exist in the official nuclei CLI
    #       (verified via Context7/projectdiscovery/nuclei docs).  Removed.
    urls_list = urls_file.read_text(encoding="utf-8") if urls_file.exists() else ""
    rc, stdout, _ = _run(
        [
            "nuclei",
            "-l", "-",
            "-es", "info,unknown",
            "-ept", "ssl",
            "-silent",
        ],
        timeout=600,
        stdin=urls_list,
    )
    if rc == 0:
        _append(nuclei_file, stdout)
        log.append(f"nuclei: {len(stdout.splitlines())} findings")
    else:
        log.append("nuclei: skipped")

    return {
        "status": True,
        "files": {
            "subs": str(subs_file),
            "resolved": str(resolved_file),
            "ports": str(ports_file),
            "alive": str(alive_file),
            "urls": str(urls_file),
            "nuclei": str(nuclei_file),
        },
        "summary": "; ".join(log),
    }


def main() -> None:
    """CLI entry point."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = argparse.ArgumentParser(description="Bug Hunting Extended Recon One-Liner")
    parser.add_argument("target", help="Target domain (e.g. example.com)")
    parser.add_argument("--workspace", "-w", default=".", help="Output directory")
    args = parser.parse_args()

    result = run_master_recon(args.target, args.workspace)
    print(result["summary"])
    for name, path in result["files"].items():
        print(f"  {name}: {path}")


if __name__ == "__main__":
    main()

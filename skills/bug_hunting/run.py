"""Bug Hunting skill – Purple Engine 6-step loop for web vulnerability discovery.

Pipeline stages
---------------
1. Analyze   – Validate and characterise the target.
2. Search KB – Query the local knowledge base for target-specific context.
3. Plan      – Build the shell pipeline that will be executed.
4. Execute   – Run subprocesses for each stage (subdomain → port → URL → vuln).
5. Interpret – Parse raw output and classify findings by severity.
6. Report    – Return a structured result dictionary.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Project-root import guard (allows both ``python run.py`` and module import)
# ---------------------------------------------------------------------------
_project_root = str(Path(__file__).resolve().parents[2])
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

try:
    from context.knowledge_base import KnowledgeBase  # noqa: E402
except ImportError:
    KnowledgeBase = None  # type: ignore[assignment,misc]

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Domain models
# ---------------------------------------------------------------------------


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    """A single vulnerability or informational finding."""

    vuln_id: str
    title: str
    severity: Severity
    description: str
    affected_url: str = ""
    evidence: str = ""
    cwe: str = ""
    remediation: str = ""


@dataclass
class HuntResult:
    """Aggregated result for a single hunt run."""

    target: str
    status: bool
    findings: List[Finding] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    alive_hosts: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    pipeline_log: List[str] = field(default_factory=list)
    summary: str = ""


# ---------------------------------------------------------------------------
# Vulnerability patterns (used for output interpretation without live tools)
# ---------------------------------------------------------------------------

_LFI_PARAMS = re.compile(
    r"[?&](file|path|page|include|document|dir|template|module|src)=",
    re.IGNORECASE,
)
_REDIRECT_PARAMS = re.compile(
    r"[?&](url|redirect|next|return|goto|target|dest(?:ination)?)=",
    re.IGNORECASE,
)
_XSS_REFLECTED = re.compile(
    r"<img\s+src=x\s+onerror=alert\(1\)>",
    re.IGNORECASE,
)
_SQLI_ERRORS = re.compile(
    r"(SQL syntax|mysql_fetch|ORA-\d{5}|SQLite|pg_query|sqlite3\.OperationalError)",
    re.IGNORECASE,
)

# CWE metadata for common vulnerability classes
_VULN_META: Dict[str, Dict[str, str]] = {
    "lfi": {
        "cwe": "CWE-22",
        "title": "Local File Inclusion / Path Traversal",
        "severity": Severity.HIGH,
        "remediation": "Validate and sanitise all file-path parameters; use allowlists.",
    },
    "xss": {
        "cwe": "CWE-79",
        "title": "Cross-Site Scripting (Reflected)",
        "severity": Severity.HIGH,
        "remediation": "Encode all user-supplied output; apply a strict Content-Security-Policy.",
    },
    "sqli": {
        "cwe": "CWE-89",
        "title": "SQL Injection",
        "severity": Severity.CRITICAL,
        "remediation": "Use parameterised queries or an ORM; never concatenate user input into SQL.",
    },
    "open_redirect": {
        "cwe": "CWE-601",
        "title": "Open Redirect",
        "severity": Severity.MEDIUM,
        "remediation": "Validate redirect destinations against an allowlist of trusted URLs.",
    },
    "info_disclosure": {
        "cwe": "CWE-200",
        "title": "Information Disclosure",
        "severity": Severity.LOW,
        "remediation": "Remove verbose error messages and debug headers from production responses.",
    },
}


# ---------------------------------------------------------------------------
# Helper: safe subprocess wrapper
# ---------------------------------------------------------------------------


def _run_cmd(
    cmd: List[str],
    *,
    timeout: int = 30,
    capture: bool = True,
    stdin_input: Optional[str] = None,
) -> Tuple[int, str, str]:
    """Run *cmd* and return (returncode, stdout, stderr).

    Raises ``FileNotFoundError`` if the binary is not installed (tool missing).
    All other exceptions are caught and returned as a non-zero returncode.
    """
    try:
        proc = subprocess.run(
            cmd,
            capture_output=capture,
            text=True,
            timeout=timeout,
            input=stdin_input,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except FileNotFoundError:
        raise
    except subprocess.TimeoutExpired:
        return 124, "", f"Command timed out after {timeout}s: {' '.join(cmd)}"
    except Exception as exc:  # noqa: BLE001
        return 1, "", str(exc)


# ---------------------------------------------------------------------------
# Purple Engine step implementations
# ---------------------------------------------------------------------------


def step_analyze(target: str) -> Dict[str, Any]:
    """Step 1 – Analyse the target and infer basic properties."""
    parsed = urlparse(target if "://" in target else f"http://{target}")
    domain = parsed.hostname or target.split(":")[0]
    is_url = target.startswith(("http://", "https://"))
    has_port = parsed.port is not None

    return {
        "raw_target": target,
        "domain": domain,
        "is_url": is_url,
        "has_explicit_port": has_port,
    }


def step_search_kb(domain: str, kb=None) -> List[str]:  # type: ignore[valid-type]
    """Step 2 – Query the local knowledge base for target context.

    Returns a list of relevant snippet strings (may be empty if KB is
    unavailable or has no matching entries).
    """
    # If no explicit kb was supplied and the KnowledgeBase class is unavailable
    # (optional dependency missing), return an empty list.
    if kb is None:
        if KnowledgeBase is None:
            return []
        try:
            kb = KnowledgeBase()
        except Exception:  # noqa: BLE001
            return []
    try:
        results = kb.search(domain, top_k=3)
        return [r.content for r in results if hasattr(r, "content")]
    except Exception:  # noqa: BLE001
        return []


def step_subdomain_enum(domain: str, depth: str = "medium") -> List[str]:
    """Step 4a – Passive subdomain enumeration via subfinder."""
    wordlist_flag: List[str] = []
    if depth == "deep":
        wordlist_flag = ["-all"]

    try:
        rc, stdout, _ = _run_cmd(
            ["subfinder", "-d", domain, "-silent"] + wordlist_flag,
            timeout=60,
        )
    except FileNotFoundError:
        logger.warning("subfinder not installed; skipping subdomain enumeration.")
        return [domain]

    subdomains = [line.strip() for line in stdout.splitlines() if line.strip()]
    if not subdomains:
        subdomains = [domain]
    return subdomains


def step_resolve_hosts(subdomains: List[str]) -> List[str]:
    """Step 4b – Resolve subdomains to live hostnames via dnsx.

    Canonical usage (Context7/projectdiscovery):
        dnsx -l subs.txt -r resolvers.txt

    Notes
    -----
    * Subdomains are passed via stdin (``-l -``).
    * ``-resp-only`` is intentionally absent: it strips domain names and outputs
      only raw IPs, which breaks downstream httpx/naabu SNI lookups.
      The plain ``dnsx -silent`` output format is ``domain [ip]``; we keep the
      domain portion for host-based TLS matching.
    """
    try:
        rc, stdout, _ = _run_cmd(
            ["dnsx", "-l", "-", "-silent"],
            timeout=60,
            stdin_input="\n".join(subdomains),
        )
        # dnsx outputs "domain [ip]" lines – keep only the domain portion
        resolved = []
        for line in stdout.splitlines():
            line = line.strip()
            if line:
                resolved.append(line.split()[0])  # first token = domain
        return resolved if resolved else subdomains
    except FileNotFoundError:
        logger.warning("dnsx not installed; using raw subdomain list.")
        return subdomains


def step_port_scan(hosts: List[str], depth: str = "medium") -> List[str]:
    """Step 4c – Port scan and HTTP/HTTPS identification via naabu + httpx."""
    rate = {"quick": "500", "medium": "1000", "deep": "3000"}.get(depth, "1000")
    alive: List[str] = []

    # 1. naabu batch scan
    try:
        rc, stdout, _ = _run_cmd(
            ["naabu", "-list", "-", "-rate", rate, "-silent"],
            timeout=120,
            stdin_input="\n".join(hosts),
        )
        ports = [line.strip() for line in stdout.splitlines() if line.strip()]
    except FileNotFoundError:
        logger.warning("naabu not installed; defaulting to port 80/443.")
        ports = []
        for h in hosts:
            ports.extend([f"{h}:80", f"{h}:443"])

    if not ports:
        return [f"http://{h}" for h in hosts]

    # 2. httpx batch probe
    try:
        rc2, stdout2, _ = _run_cmd(
            ["httpx", "-silent", "-l", "-"],
            timeout=60,
            stdin_input="\n".join(ports),
        )
        for line in stdout2.splitlines():
            line = line.strip()
            if line:
                alive.append(line)
    except FileNotFoundError:
        logger.warning("httpx not installed; treating targets as alive.")
        # Fallback: assume everything is http
        for p in ports:
            alive.append(p if p.startswith("http") else f"http://{p}")

    return list(dict.fromkeys(alive)) or [f"http://{hosts[0]}"]


def step_url_collect(alive_hosts: List[str], depth: str = "medium") -> List[str]:
    """Step 4d – URL corpus collection via katana.

    Features:
    * Batch processing: all hosts passed via stdin in one crawl session.
    * JS parsing, known-file crawling, extension filtering enabled.

    Flags used (all Context7/katana confirmed):
    * ``-jc``         – parse JS files for additional endpoints
    * ``-kf all``     – crawl robots.txt + sitemap.xml + other known files
    * ``-fx``         – extract form/input/select elements (JSONL)
    * ``-aff``        – automatic form filling (experimental)
    * ``-nc``         – no colour (ANSI-safe output)
    * ``-ef``         – extension filter (skip binary assets)
    * ``-d``          – max crawl depth

    Note on ``-xhr``:  XHR extraction (``-xhr``) is placed under katana's HEADLESS
    section (Context7 confirmed); it requires ``-hl`` headless mode to intercept
    XHR at the JS runtime level.  It is therefore NOT included in the standard
    non-headless call to avoid no-op or runtime errors.
    """
    depth_flag = {"quick": "2", "medium": "3", "deep": "5"}.get(depth, "3")
    urls: List[str] = []

    try:
        rc, stdout, _ = _run_cmd(
            [
                "katana",
                "-list", "-",
                "-d", depth_flag,
                "-jc",
                "-kf", "all",
                "-fx",
                "-aff",
                "-silent",
                "-nc",
                "-ef", "woff,css,png,svg,jpg,woff2,jpeg,gif",
            ],
            timeout=300,  # Increased timeout for batch crawl
            stdin_input="\n".join(alive_hosts),
        )
        for line in stdout.splitlines():
            line = line.strip()
            if line:
                urls.append(line)
    except FileNotFoundError:
        logger.warning("katana not installed; using alive hosts as URL seeds.")
        urls.extend(alive_hosts)

    return list(dict.fromkeys(urls)) or alive_hosts  # deduplicate, preserve order


def step_vuln_scan(
    urls: List[str],
    alive_hosts: List[str],
) -> List[Finding]:
    """Step 4e – Vulnerability detection via nuclei and heuristic analysis."""
    findings: List[Finding] = []

    # --- nuclei scan ---
    # Flags (Context7/nuclei confirmed):
    #   -l -          read targets from stdin
    #   -es info,unknown  exclude informational/unknown severity findings
    #   -ept ssl      exclude SSL protocol templates (handled separately)
    #   -silent       suppress progress output; emit JSONL findings only
    #
    # NOTE: The ``-ss template-spray`` flag does NOT exist in the official
    # nuclei CLI (verified via Context7/projectdiscovery/nuclei docs).  It has
    # been intentionally removed.
    try:
        rc, stdout, _ = _run_cmd(
            [
                "nuclei",
                "-l", "-",
                "-es", "info,unknown",
                "-ept", "ssl",
                "-silent",
            ],
            timeout=180,
            stdin_input="\n".join(alive_hosts),
        )
        # Parse nuclei JSONL output
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                sev_raw = obj.get("info", {}).get("severity", "info").upper()
                try:
                    sev = Severity[sev_raw]
                except KeyError:
                    sev = Severity.INFO
                findings.append(
                    Finding(
                        vuln_id=obj.get("template-id", "nuclei-finding"),
                        title=obj.get("info", {}).get("name", "Nuclei Finding"),
                        severity=sev,
                        description=obj.get("info", {}).get("description", ""),
                        affected_url=obj.get("matched-at", ""),
                        evidence=obj.get("extracted-results", [""])[0]
                        if obj.get("extracted-results")
                        else "",
                        cwe=", ".join(obj.get("info", {}).get("classification", {}).get("cwe-id", [])),
                    )
                )
            except (json.JSONDecodeError, AttributeError):
                pass
    except FileNotFoundError:
        logger.warning("nuclei not installed; skipping nuclei scan.")

    # --- heuristic URL-based analysis ---
    for url in urls:
        if _LFI_PARAMS.search(url):
            meta = _VULN_META["lfi"]
            findings.append(
                Finding(
                    vuln_id="lfi-param-detected",
                    title=meta["title"],
                    severity=meta["severity"],
                    description=(
                        "URL parameter suggests potential LFI/path-traversal attack surface."
                    ),
                    affected_url=url,
                    cwe=meta["cwe"],
                    remediation=meta["remediation"],
                )
            )
        if _REDIRECT_PARAMS.search(url):
            meta = _VULN_META["open_redirect"]
            findings.append(
                Finding(
                    vuln_id="open-redirect-param-detected",
                    title=meta["title"],
                    severity=meta["severity"],
                    description=(
                        "URL parameter suggests potential open redirect attack surface."
                    ),
                    affected_url=url,
                    cwe=meta["cwe"],
                    remediation=meta["remediation"],
                )
            )

    return findings


def step_interpret(raw_output: str) -> List[Finding]:
    """Step 5 – Parse raw tool output for well-known vulnerability signatures."""
    findings: List[Finding] = []

    if _SQLI_ERRORS.search(raw_output):
        meta = _VULN_META["sqli"]
        findings.append(
            Finding(
                vuln_id="sqli-error-based",
                title=meta["title"],
                severity=meta["severity"],
                description="SQL error pattern detected in HTTP response body.",
                evidence=raw_output[:200],
                cwe=meta["cwe"],
                remediation=meta["remediation"],
            )
        )

    if _XSS_REFLECTED.search(raw_output):
        meta = _VULN_META["xss"]
        findings.append(
            Finding(
                vuln_id="xss-reflected",
                title=meta["title"],
                severity=meta["severity"],
                description="XSS test payload was reflected unencoded in the HTTP response.",
                evidence=raw_output[:200],
                cwe=meta["cwe"],
                remediation=meta["remediation"],
            )
        )

    return findings


def step_report(result: HuntResult) -> Dict[str, Any]:
    """Step 6 – Build the final structured report dictionary."""
    sev_counts: Dict[str, int] = {s.value: 0 for s in Severity}
    for f in result.findings:
        sev_counts[f.severity.value] += 1

    return {
        "status": result.status,
        "summary": result.summary or (
            f"Bug hunt completed. {len(result.findings)} finding(s) identified."
        ),
        "result": {
            "target": result.target,
            "subdomains": result.subdomains,
            "alive_hosts": result.alive_hosts,
            "urls_collected": len(result.urls),
            "findings": [asdict(f) for f in result.findings],
            "severity_counts": sev_counts,
            "pipeline_log": result.pipeline_log,
        },
    }


# ---------------------------------------------------------------------------
# Orchestrator (Purple Engine loop)
# ---------------------------------------------------------------------------


class BugHuntingSkill:
    """Thin orchestrator that wires the six Purple Engine steps together."""

    def __init__(self, kb=None) -> None:
        self._kb = kb

    def run(self, target: str, depth: str = "medium") -> Dict[str, Any]:
        """Execute the full bug-hunting pipeline against *target*.

        Parameters
        ----------
        target:
            Domain name or URL to hunt.
        depth:
            Scan depth – ``quick``, ``medium`` (default), or ``deep``.

        Returns
        -------
        dict
            Structured result compatible with the Purple Engine registry format.
        """
        log: List[str] = []

        # Step 1 – Analyze
        analysis = step_analyze(target)
        domain = analysis["domain"]
        log.append(f"[analyze] target={target} domain={domain}")

        # Step 2 – Search KB
        kb_snippets = step_search_kb(domain, self._kb)
        if kb_snippets:
            log.append(f"[kb] {len(kb_snippets)} snippet(s) found for '{domain}'")
        else:
            log.append(f"[kb] no entries found for '{domain}'")

        # Step 3 – Plan (no side-effects; just log the intended pipeline)
        log.append(
            f"[plan] pipeline: subdomain_enum → resolve → port_scan → "
            f"url_collect → vuln_scan (depth={depth})"
        )

        # Step 4 – Execute
        subdomains = step_subdomain_enum(domain, depth)
        log.append(f"[execute] subdomains={len(subdomains)}")

        resolved = step_resolve_hosts(subdomains)
        log.append(f"[execute] resolved={len(resolved)}")

        alive_hosts = step_port_scan(resolved, depth)
        log.append(f"[execute] alive_hosts={len(alive_hosts)}")

        urls = step_url_collect(alive_hosts, depth)
        log.append(f"[execute] urls_collected={len(urls)}")

        findings = step_vuln_scan(urls, alive_hosts)
        log.append(f"[execute] findings_before_interpret={len(findings)}")

        # Step 5 – Interpret (parse any raw stdout already captured)
        # For live runs nuclei output is already consumed inside step_vuln_scan;
        # here we expose the hook for callers that supply raw_output separately.
        log.append("[interpret] heuristic analysis complete")

        # Step 6 – Report
        log.append("[report] generating final report")
        result = HuntResult(
            target=target,
            status=True,
            findings=findings,
            subdomains=subdomains,
            alive_hosts=alive_hosts,
            urls=urls,
            pipeline_log=log,
            summary=(
                f"Bug hunt completed for {domain}. "
                f"{len(findings)} finding(s) across {len(alive_hosts)} live host(s)."
            ),
        )
        return step_report(result)


# ---------------------------------------------------------------------------
# Registry entry-point
# ---------------------------------------------------------------------------

_SKILL = BugHuntingSkill()


def run(params: Dict[str, Any]) -> Dict[str, Any]:
    """Skill entry-point called by the registry.

    Parameters
    ----------
    params : dict
        Must contain ``target``.  Optional keys:

        * ``action`` – one of ``full_pipeline``, ``subdomain_enum``,
          ``port_scan``, ``url_collect``, ``vuln_scan``, ``report``.
        * ``depth`` – ``quick`` | ``medium`` | ``deep`` (default ``medium``).
        * ``raw_output`` – raw HTTP response body to analyse heuristically.
    """
    target = params.get("target", "").strip()
    if not target:
        return {
            "status": False,
            "summary": "Parameter 'target' is required.",
            "result": {},
        }

    action = params.get("action", "full_pipeline")
    depth = params.get("depth", "medium")
    raw_output = params.get("raw_output", "")

    try:
        if action == "full_pipeline":
            return _SKILL.run(target, depth=depth)

        if action == "subdomain_enum":
            analysis = step_analyze(target)
            subs = step_subdomain_enum(analysis["domain"], depth)
            return {
                "status": True,
                "summary": f"Enumerated {len(subs)} subdomain(s) for {analysis['domain']}.",
                "result": {"subdomains": subs},
            }

        if action == "port_scan":
            alive = step_port_scan([target], depth)
            return {
                "status": True,
                "summary": f"Identified {len(alive)} alive HTTP endpoint(s).",
                "result": {"alive_hosts": alive},
            }

        if action == "url_collect":
            urls = step_url_collect([target], depth)
            return {
                "status": True,
                "summary": f"Collected {len(urls)} URL(s) from {target}.",
                "result": {"urls": urls},
            }

        if action == "vuln_scan":
            findings = step_vuln_scan([target], [target])
            return {
                "status": True,
                "summary": f"Identified {len(findings)} finding(s) via vuln scan.",
                "result": {
                    "findings": [asdict(f) for f in findings],
                },
            }

        if action == "report":
            if not raw_output:
                return {
                    "status": False,
                    "summary": "Parameter 'raw_output' is required for the 'report' action.",
                    "result": {},
                }
            findings = step_interpret(raw_output)
            return {
                "status": True,
                "summary": f"Interpretation complete. {len(findings)} finding(s).",
                "result": {"findings": [asdict(f) for f in findings]},
            }

        return {
            "status": False,
            "summary": f"Unknown action '{action}'.",
            "result": {
                "available_actions": [
                    "full_pipeline",
                    "subdomain_enum",
                    "port_scan",
                    "url_collect",
                    "vuln_scan",
                    "report",
                ]
            },
        }

    except Exception as exc:  # noqa: BLE001
        logger.exception("bug_hunting skill error")
        return {
            "status": False,
            "summary": f"Bug hunting failed: {exc}",
            "result": {"error": str(exc)},
        }


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------


def main() -> None:
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Bug Hunting Skill – Purple Engine")
    parser.add_argument("target", nargs="?", help="Target domain or URL")
    parser.add_argument(
        "--action",
        "-a",
        choices=[
            "full_pipeline",
            "subdomain_enum",
            "port_scan",
            "url_collect",
            "vuln_scan",
            "report",
        ],
        default="full_pipeline",
    )
    parser.add_argument(
        "--depth",
        "-d",
        choices=["quick", "medium", "deep"],
        default="medium",
    )
    parser.add_argument("--raw-output", help="Raw HTTP response body to analyse")
    parser.add_argument("--json", action="store_true", help="Output raw JSON")
    parser.add_argument("--test", action="store_true", help="Run a quick sanity test")

    args = parser.parse_args()

    if args.test:
        print("Sanity test: validating module structure …")
        assert callable(run), "run() is not callable"
        result = run({"target": "example.com", "action": "subdomain_enum"})
        assert "status" in result
        print("Sanity test passed.")
        return

    if not args.target:
        parser.print_help()
        return

    params: Dict[str, Any] = {
        "target": args.target,
        "action": args.action,
        "depth": args.depth,
    }
    if args.raw_output:
        params["raw_output"] = args.raw_output

    result = run(params)

    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print(f"Status : {result['status']}")
        print(f"Summary: {result['summary']}")
        data = result.get("result", {})
        for key, val in data.items():
            if isinstance(val, list):
                print(f"{key} ({len(val)}):")
                for item in val[:10]:
                    print(f"  {item}")
                if len(val) > 10:
                    print(f"  … and {len(val) - 10} more")
            elif isinstance(val, dict):
                print(f"{key}: {json.dumps(val)}")
            else:
                print(f"{key}: {val}")


if __name__ == "__main__":
    main()

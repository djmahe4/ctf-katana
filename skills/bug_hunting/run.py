"""Bug Hunting skill – 5-Pillar Bug Bounty Roadmap (AI-Augmented Purple Engine).

Based on the methodology from "The Bug Bounty Roadmap I'd Follow If I Started Over (With AI)".

Pillar 1 – Foundations
    Prerequisite knowledge: HTTP, OWASP Top 10, Burp/Caido interception.
    Bug classes to master first: IDOR, XSS (especially Blind XSS), Broken Access Control.

Pillar 2 – Learning Loop  (action='learning_loop')
    Read-Ask-Quiz-Apply loop. Paste writeups into AI, ask for explanations,
    follow-up questions, quizzes, and similar challenges. AI is a tutor, not a substitute.

Pillar 3 – Recon & Target Selection  (action='recon' or 'subdomain_enum' / 'port_scan' / 'url_collect')
    Tool stack: subfinder → httpx → alterx (non-negotiable backbone).
    AI use-cases:
      - Categorise subdomain lists by function (auth / admin / API / internal).
      - Generate payload variations for custom auth flows.
      - Write custom recon scripts via precise specification.
    Target selection: wide scope, newer programs, messy attack surfaces.

Pillar 4 – The Hunt  (action='feature_map' | 'request_analysis' | 'js_review' | 'vuln_scan')
    Piece 1  – Feature mapping: describe the app to the LLM, get a prioritised bug-class hit list.
    Piece 2  – Request analysis: intercept in Burp/Caido, paste to LLM, get parameter tamper guidance.
    Piece 3  – JS / code review: feed client-side JS or open-source components, extract all API calls.
    AI finds the map; the hunter makes the calls.

Pillar 5 – Reporting & Growth  (action='report_assist' | 'feedback_loop')
    - Describe bug class → AI writes impact statement (no raw payload needed).
    - Paste sanitised draft → AI critiques clarity, severity framing, triage readiness.
    - After every bug (even N/A/dup): run the feedback loop to compound skill.
    Key insight: report quality is the difference between $500 and $3 000 on the same finding.

Full pipeline (action='full_pipeline'): Pillar 3 recon → Pillar 4 hunt → Pillar 5 report.
HITL gate   (action='plan'): produces an approved plan before any execution.
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

try:
    from skills.bug_hunting.platform_scanner import (  # noqa: E402
        PlatformScanner,
        run_platform_scan,
    )
    _PLATFORM_SCANNER_AVAILABLE = True
except ImportError:
    _PLATFORM_SCANNER_AVAILABLE = False
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
class HitList:
    """Prioritised attack surface produced by Pillar 3 recon."""

    auth_subdomains: List[str] = field(default_factory=list)
    admin_subdomains: List[str] = field(default_factory=list)
    api_subdomains: List[str] = field(default_factory=list)
    internal_subdomains: List[str] = field(default_factory=list)
    marketing_subdomains: List[str] = field(default_factory=list)
    other_subdomains: List[str] = field(default_factory=list)

    def prioritised(self) -> List[str]:
        """Return subdomains ordered from highest-value to lowest-value."""
        return (
            self.auth_subdomains
            + self.admin_subdomains
            + self.api_subdomains
            + self.internal_subdomains
            + self.marketing_subdomains
            + self.other_subdomains
        )


@dataclass
class HuntResult:
    """Aggregated result for a single hunt run."""

    target: str
    status: bool
    findings: List[Finding] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    alive_hosts: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    hit_list: Optional[HitList] = None
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
# Pillar 3 – AI-assisted subdomain categorisation (produces a HitList)
# ---------------------------------------------------------------------------


def step_categorise_subdomains(subdomains: List[str]) -> HitList:
    """Pillar 3 – Categorise subdomains by likely function to produce a HitList.

    This mirrors the video's workflow: paste subdomain list into AI and say
    'Categorize these by likely function: auth, admin, API, internal, marketing'.
    We do a keyword-heuristic version locally; the MCP tool can call an LLM on top.
    """
    hit = HitList()
    _AUTH = re.compile(r"(auth|login|sso|oauth|iam|identity|account|password)", re.I)
    _ADMIN = re.compile(r"(admin|manage|panel|backoffice|staff|cms|dashboard)", re.I)
    _API = re.compile(r"(api|gateway|graphql|rest|grpc|v\d+)", re.I)
    _INTERNAL = re.compile(r"(internal|dev|staging|qa|test|sandbox|corp|vpn)", re.I)
    _MARKETING = re.compile(r"(blog|news|marketing|landing|promo|cdn|assets|static|media)", re.I)

    for sd in subdomains:
        if _AUTH.search(sd):
            hit.auth_subdomains.append(sd)
        elif _ADMIN.search(sd):
            hit.admin_subdomains.append(sd)
        elif _API.search(sd):
            hit.api_subdomains.append(sd)
        elif _INTERNAL.search(sd):
            hit.internal_subdomains.append(sd)
        elif _MARKETING.search(sd):
            hit.marketing_subdomains.append(sd)
        else:
            hit.other_subdomains.append(sd)
    return hit


# ---------------------------------------------------------------------------
# Pillar 4 – The Hunt: three pieces
# ---------------------------------------------------------------------------


def step_feature_map(features: str) -> Dict[str, Any]:
    """Pillar 4, Piece 1 – Feature mapping.

    The hunter walks through the app and describes it to the LLM.
    Example: 'user dashboard, billing page, team management, admin panel I cannot access.'
    Returns a structured list of prioritised bug classes and where to look.

    Parameters
    ----------
    features:
        Free-text description of the application's visible features.
    """
    bug_class_hints: List[str] = []
    surfaces: List[str] = []

    _TEAM_MGMT = re.compile(r"team\s*(manage|member|role|permission)", re.I)
    _BILLING = re.compile(r"billing|payment|invoice|subscription", re.I)
    _ADMIN = re.compile(r"admin\s*(panel|page|section|area)", re.I)
    _UPLOAD = re.compile(r"(upload|file|attachment|import|export)", re.I)
    _API_KEY = re.compile(r"api\s*key|webhook|integration|token", re.I)

    if _TEAM_MGMT.search(features):
        bug_class_hints.append("Broken Access Control (team roles – privilege escalation)")
        surfaces.append("team management section")
    if _BILLING.search(features):
        bug_class_hints.append("IDOR (billing page – access other users' invoices)")
        surfaces.append("billing / payment page")
    if _ADMIN.search(features):
        bug_class_hints.append("Broken Access Control (admin panel – unauthenticated access)")
        surfaces.append("admin panel")
    if _UPLOAD.search(features):
        bug_class_hints.append("Unrestricted File Upload / Path Traversal")
        surfaces.append("file upload endpoint")
    if _API_KEY.search(features):
        bug_class_hints.append("API key leakage / insecure webhook validation")
        surfaces.append("API integrations page")

    # Always suggest foundational checks
    bug_class_hints += [
        "IDOR (swap user IDs / resource IDs across accounts)",
        "Blind XSS (inject into user-visible fields rendered by admin)",
        "Auth bypass (manipulate JWT / session tokens)",
    ]

    return {
        "pillar": 4,
        "piece": "feature_mapping",
        "description": features,
        "prioritised_bug_classes": bug_class_hints,
        "attack_surfaces": surfaces,
        "next_step": "Use Burp/Caido to intercept requests. Call action='request_analysis' with captured request.",
    }


def step_request_analysis(raw_request: str) -> Dict[str, Any]:
    """Pillar 4, Piece 2 – Request analysis.

    Intercept an interesting request in Burp/Caido, paste it here.
    Returns parameter analysis and tamper suggestions.

    Parameters
    ----------
    raw_request:
        Raw HTTP request text (method, headers, body).
    """
    tamper_targets: List[str] = []
    notes: List[str] = []

    # Detect JWT
    if re.search(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", raw_request):
        tamper_targets.append("JWT token – try alg:none, key confusion, or claim manipulation")
        notes.append("Decode JWT header/payload to inspect claims.")

    # Detect Base64 blobs
    if re.search(r"[A-Za-z0-9+/]{30,}={0,2}", raw_request):
        tamper_targets.append("Possible Base64 blob – decode and inspect for serialised objects or PII")

    # Detect numeric IDs (IDOR candidates)
    for m in re.finditer(r"[?&/](user_?id|uid|account_?id|id|resource_?id)=(\d+)", raw_request, re.I):
        tamper_targets.append(
            f"Numeric ID parameter '{m.group(1)}={m.group(2)}' – IDOR candidate: "
            "swap with another account's ID using a second test account."
        )

    # Detect redirect params
    if _REDIRECT_PARAMS.search(raw_request):
        tamper_targets.append("Redirect parameter – test open redirect / SSRF")

    # Detect file/path params
    if _LFI_PARAMS.search(raw_request):
        tamper_targets.append("File/path parameter – test LFI / path traversal (../../../etc/passwd)")

    if not tamper_targets:
        tamper_targets.append("No obvious high-signal parameters. Manually review each parameter for business-logic abuse.")

    return {
        "pillar": 4,
        "piece": "request_analysis",
        "tamper_targets": tamper_targets,
        "analysis_notes": notes,
        "next_step": "For each tamper target above, modify the request in Burp Repeater and observe the response. Call action='vuln_scan' to automate checks.",
    }


def step_js_review(js_content: str) -> Dict[str, Any]:
    """Pillar 4, Piece 3 – Client-side JS / code review.

    Feed client-side JavaScript or open-source component code.
    Extracts API endpoints, hardcoded secrets, and references to subdomains.

    Parameters
    ----------
    js_content:
        JavaScript source code text.
    """
    api_calls: List[str] = []
    hardcoded_secrets: List[str] = []
    subdomains_found: List[str] = []

    # Extract fetch / axios / XHR patterns
    for m in re.finditer(
        r"""(?:fetch|axios\.[a-z]+|XMLHttpRequest)\s*\(\s*[`'"]((?:https?://[^`'"]+|/[^`'"]+))[`'"]""",
        js_content,
    ):
        api_calls.append(m.group(1))

    # Extract relative API paths
    for m in re.finditer(r"""(?:url|endpoint|path)\s*[:=]\s*[`'"](/api/[^`'"]+)[`'"]""", js_content):
        api_calls.append(m.group(1))

    # Look for hardcoded keys/tokens
    for m in re.finditer(
        r"""(?:api_?key|secret|token|password|bearer)\s*[:=]\s*[`'"]([A-Za-z0-9_\-]{8,})[`'"]""",
        js_content,
        re.I,
    ):
        hardcoded_secrets.append(f"{m.group(0)[:80]} …")

    # Extract domain references
    for m in re.finditer(r"https?://([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})", js_content):
        host = m.group(1)
        if host not in subdomains_found:
            subdomains_found.append(host)

    return {
        "pillar": 4,
        "piece": "js_code_review",
        "api_endpoints_found": list(dict.fromkeys(api_calls)),
        "hardcoded_secrets": hardcoded_secrets,
        "subdomains_referenced": subdomains_found,
        "next_step": (
            "For each API endpoint found, generate curl commands or add to Burp/Caido scope. "
            "Test unauthenticated access (Broken Access Control). "
            "Add any new subdomains to your subdomain hit list."
        ),
    }


# ---------------------------------------------------------------------------
# Pillar 5 – Reporting & Growth
# ---------------------------------------------------------------------------

# Severity-to-bounty guidance based on video insights
_IMPACT_TEMPLATES: Dict[str, str] = {
    "broken_access_control": (
        "This vulnerability allows a low-privilege user to access resources belonging to "
        "other users, violating the principle of least privilege. Depending on the sensitivity "
        "of the exposed data (PII, financial records, session tokens), this constitutes a "
        "Critical or High severity finding under CVSS v3."
    ),
    "idor": (
        "An Insecure Direct Object Reference allows an authenticated attacker to read or "
        "modify resources owned by arbitrary users by manipulating predictable identifiers. "
        "Full account takeover or data exfiltration may be achievable at scale."
    ),
    "xss_blind": (
        "A Blind XSS payload executing in an admin or staff context grants the attacker the "
        "ability to steal privileged session cookies, exfiltrate CSRF tokens, or perform "
        "admin-level actions on behalf of the victim, constituting a High severity finding."
    ),
    "xss_reflected": (
        "Reflected XSS allows an attacker to craft a malicious URL that executes arbitrary "
        "JavaScript in a victim's browser, enabling session hijacking, credential theft, or "
        "phishing within the trusted origin."
    ),
    "open_redirect": (
        "An open redirect can be chained with phishing or OAuth token theft attacks, "
        "redirecting victims from a trusted domain to an attacker-controlled page."
    ),
}


def step_report_assist(bug_class: str, description: str) -> Dict[str, Any]:
    """Pillar 5 – Report writing assistance.

    Describe the bug class (not the raw payload/URL) and get:
      - A professional impact statement.
      - A severity framing.
      - Critique checklist to improve the report.

    Parameters
    ----------
    bug_class:
        One of: broken_access_control, idor, xss_blind, xss_reflected, open_redirect,
        or any free-text description.
    description:
        Sanitised description (no raw endpoints, no payloads, no target URLs).
    """
    # Normalise
    key = re.sub(r"[\s\-]", "_", bug_class.lower())
    impact = _IMPACT_TEMPLATES.get(key, (
        "Evaluate the blast radius: can this bug affect all users, only the attacker's account, "
        "or a subset? Quantify data sensitivity and regulatory exposure (GDPR, PCI-DSS). "
        "Frame the impact in terms of confidentiality, integrity, and availability (CIA triad)."
    ))

    critique = [
        "Is the reproduction path numbered and step-by-step?",
        "Does it include a proof-of-concept (screenshot / curl command) without exposing sensitive URLs?",
        "Is the impact statement written from a business risk perspective (not just technical)?",
        "Is the severity (CVSS) explicitly stated with justification?",
        "Are remediation recommendations concrete and actionable?",
        "Is the report free of jargon that a non-technical triage team member couldn't parse?",
        "Would a senior hunter reading this immediately understand what you found and why it matters?",
    ]

    return {
        "pillar": 5,
        "piece": "report_assist",
        "bug_class": bug_class,
        "your_description": description,
        "impact_statement": impact,
        "report_critique_checklist": critique,
        "pro_tip": (
            "You do NOT need to paste the raw payload or URL to get AI writing help. "
            "Describe the bug class + the access level achieved. "
            "The quality of your report is the difference between a $500 and a $3000 bounty."
        ),
    }


def step_feedback_loop(hunt_summary: str) -> Dict[str, Any]:
    """Pillar 5 – Post-hunt feedback loop (compounds skill on every finding).

    After every bug (even N/A or duplicates), describe what you did and get
    structured feedback. This is the habit that compounds fastest.

    Parameters
    ----------
    hunt_summary:
        A sanitised description of what you tested and what you found
        (e.g., 'Tested IDOR by swapping user_id param, confirmed access to another user's billing').
    """
    feedback_prompts = [
        "What did you do well in this hunt?",
        "What would a more experienced hunter have done differently?",
        "What related attack surfaces or chained bugs could be worth investigating next time?",
        "Which bug class would you prioritise testing first on a similar target in the future?",
        "How would you have structured the report differently to increase the bounty?",
    ]
    return {
        "pillar": 5,
        "piece": "feedback_loop",
        "your_summary": hunt_summary,
        "reflection_questions": feedback_prompts,
        "instruction": (
            "Run these reflection questions through your local LLM (Ollama) or paste your summary "
            "into Claude/ChatGPT (sanitised – no raw endpoints). "
            "Store the AI's answers in your wiki/ directory so they compound over time."
        ),
    }


def step_learning_loop(writeup_text: str) -> Dict[str, Any]:
    """Pillar 2 – Learning loop: Read-Ask-Quiz-Apply.

    Paste a bug bounty writeup. Returns structured prompts to run through your
    AI tutor (Claude/ChatGPT) to extract maximum learning.

    Parameters
    ----------
    writeup_text:
        The full text of a bug bounty writeup.
    """
    # Extract any vulnerability names mentioned
    vuln_names = re.findall(
        r"\b(IDOR|XSS|SQL[i\s]?injection|SSRF|RCE|LFI|SSTI|CSRF|XXE|"
        r"open redirect|broken access control|deserialization|path traversal)\b",
        writeup_text,
        re.I,
    )
    vuln_names = list(dict.fromkeys(v.upper() for v in vuln_names))

    prompts = [
        f"Explain this writeup to me like I'm a beginner who understands HTTP basics. Walk me through every step the attacker took and why it worked.",
        f"What vulnerability classes are involved? ({', '.join(vuln_names) if vuln_names else 'see writeup'})",
        "What would have prevented this bug? Give me the developer's perspective.",
        "Quiz me on the core concepts in this writeup with 5 questions.",
        "Give me 3 similar labs or challenges I can practice this on (HackTheBox / PortSwigger / TryHackMe).",
        "What should I look for on a real target that would indicate this same bug class exists?",
    ]

    return {
        "pillar": 2,
        "piece": "learning_loop",
        "loop": "Read → Ask → Quiz → Apply",
        "vuln_classes_detected": vuln_names,
        "ai_tutor_prompts": prompts,
        "reminder": (
            "Foundations first. If you don't understand HTTP, these prompts will generate "
            "confusion, not insight. Complete Pillar 1 before running the learning loop."
        ),
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
        Optional keys vary by action. Action-specific parameters:

        Pillar 2 – Learning Loop
          * ``action='learning_loop'`` – ``writeup`` (str): full text of a bug bounty writeup.

        Pillar 3 – Recon (target required)
          * ``action='plan'``           – HITL plan gate before execution.
          * ``action='subdomain_enum'`` – ``target`` (str), ``depth``.
          * ``action='port_scan'``      – ``target`` (str), ``depth``.
          * ``action='url_collect'``    – ``target`` (str), ``depth``.
          * ``action='recon'``          – Full Pillar 3: subdomain→categorise→port→URL.

        Pillar 4 – The Hunt
          * ``action='feature_map'``      – ``features`` (str): description of app features.
          * ``action='request_analysis'`` – ``raw_request`` (str): raw HTTP request.
          * ``action='js_review'``        – ``js_content`` (str): JavaScript source.
          * ``action='vuln_scan'``        – ``target`` (str).
          * ``action='full_pipeline'``    – Full Pillar 3+4 pipeline.

        Pillar 5 – Reporting & Growth
          * ``action='report_assist'``  – ``bug_class`` (str), ``description`` (str).
          * ``action='feedback_loop'``  – ``hunt_summary`` (str).
          * ``action='report'``         – ``raw_output`` (str): HTTP response to heuristically parse.

        Common:
          * ``depth`` – ``quick`` | ``medium`` | ``deep`` (default ``medium``).
    """
    target = params.get("target", "").strip()
    action = params.get("action", "full_pipeline")
    depth = params.get("depth", "medium")
    raw_output = params.get("raw_output", "")

    # Actions that don't require a target
    _NO_TARGET_ACTIONS = {"learning_loop", "feature_map", "request_analysis", "js_review", "report_assist", "feedback_loop"}
    if not target and action not in _NO_TARGET_ACTIONS:
        return {
            "status": False,
            "summary": f"Parameter 'target' is required for action='{action}'.",
            "result": {},
        }

    try:
        if action == "full_pipeline":
            return _SKILL.run(target, depth=depth)

        if action == "plan":
            analysis = step_analyze(target)
            domain = analysis["domain"]
            kb_snippets = step_search_kb(domain, _SKILL._kb)
            return {
                "status": True,
                "summary": f"Plan for {domain} (Requires human approval)",
                "result": {
                    "target": target,
                    "depth": depth,
                    "pipeline": ["subdomain_enum", "port_scan", "url_collect", "vuln_scan"],
                    "kb_context_found": len(kb_snippets) > 0,
                    "message": "Please review this plan. To execute, call this tool again with action='full_pipeline'."
                }
            }

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

        # ---- Pillar 2 ----
        if action == "learning_loop":
            writeup = params.get("writeup", "")
            if not writeup:
                return {"status": False, "summary": "Parameter 'writeup' is required.", "result": {}}
            return {"status": True, "summary": "Pillar 2: Learning loop prompts generated.", "result": step_learning_loop(writeup)}

        # ---- Pillar 3 (extended) ----
        if action == "recon":
            analysis = step_analyze(target)
            domain = analysis["domain"]
            subs = step_subdomain_enum(domain, depth)
            hit_list = step_categorise_subdomains(subs)
            resolved = step_resolve_hosts(subs)
            alive_hosts = step_port_scan(resolved, depth)
            urls = step_url_collect(alive_hosts, depth)
            return {
                "status": True,
                "summary": f"Pillar 3 recon complete for {domain}.",
                "result": {
                    "domain": domain,
                    "hit_list": {
                        "auth": hit_list.auth_subdomains,
                        "admin": hit_list.admin_subdomains,
                        "api": hit_list.api_subdomains,
                        "internal": hit_list.internal_subdomains,
                        "marketing": hit_list.marketing_subdomains,
                        "other": hit_list.other_subdomains,
                        "prioritised": hit_list.prioritised(),
                    },
                    "alive_hosts": alive_hosts,
                    "urls_collected": len(urls),
                    "next_step": "Human review: approve hit list, then call action='feature_map' or action='full_pipeline'.",
                },
            }

        # ---- Pillar 4 ----
        if action == "feature_map":
            features = params.get("features", "")
            if not features:
                return {"status": False, "summary": "Parameter 'features' is required.", "result": {}}
            return {"status": True, "summary": "Pillar 4 Piece 1: Feature map generated.", "result": step_feature_map(features)}

        if action == "request_analysis":
            raw_request = params.get("raw_request", "")
            if not raw_request:
                return {"status": False, "summary": "Parameter 'raw_request' is required.", "result": {}}
            return {"status": True, "summary": "Pillar 4 Piece 2: Request analysis complete.", "result": step_request_analysis(raw_request)}

        if action == "js_review":
            js_content = params.get("js_content", "")
            if not js_content:
                return {"status": False, "summary": "Parameter 'js_content' is required.", "result": {}}
            return {"status": True, "summary": "Pillar 4 Piece 3: JS review complete.", "result": step_js_review(js_content)}

        # ---- Pillar 5 ----
        if action == "report_assist":
            bug_class = params.get("bug_class", "")
            description = params.get("description", "")
            if not bug_class:
                return {"status": False, "summary": "Parameter 'bug_class' is required.", "result": {}}
            return {"status": True, "summary": "Pillar 5: Report assistance generated.", "result": step_report_assist(bug_class, description)}

        if action == "feedback_loop":
            hunt_summary = params.get("hunt_summary", "")
            if not hunt_summary:
                return {"status": False, "summary": "Parameter 'hunt_summary' is required.", "result": {}}
            return {"status": True, "summary": "Pillar 5: Feedback loop reflection generated.", "result": step_feedback_loop(hunt_summary)}

        if action == "platform_scan":
            if not _PLATFORM_SCANNER_AVAILABLE:
                return {
                    "status": False,
                    "summary": (
                        "Platform scanner unavailable: install DrissionPage, "
                        "playwright, and beautifulsoup4."
                    ),
                    "result": {},
                }
            return run_platform_scan(params)
        return {
            "status": False,
            "summary": f"Unknown action '{action}'.",
            "result": {
                "available_actions": [
                    # Pillar 2
                    "learning_loop",
                    # Pillar 3
                    "plan", "recon", "subdomain_enum", "port_scan", "url_collect",
                    # Pillar 4
                    "feature_map", "request_analysis", "js_review", "vuln_scan", "full_pipeline",
                    # Pillar 5
                    "report_assist", "feedback_loop", "report",
                    # Platform
                    "platform_scan",
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
            "platform_scan",
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

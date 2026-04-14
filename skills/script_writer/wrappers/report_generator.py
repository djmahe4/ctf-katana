"""ReportGenerator – synthesises findings into professional Purple Team reports.

Produces two artefacts per run:

* ``hunt_report_<YYYYMMDD>.md``   – Markdown (human-readable)
* ``hunt_report_<YYYYMMDD>.json`` – JSON (machine-readable / SIEM ingestible)

Both are written to *workspace* (defaults to ``outputs/reports/``).
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

# OWASP Top-10 (2021) keyword mapping for auto-classification
_OWASP_MAP: Dict[str, str] = {
    "sqli": "A03:2021 – Injection",
    "sql injection": "A03:2021 – Injection",
    "xss": "A03:2021 – Injection",
    "cross-site scripting": "A03:2021 – Injection",
    "lfi": "A01:2021 – Broken Access Control",
    "path traversal": "A01:2021 – Broken Access Control",
    "open redirect": "A01:2021 – Broken Access Control",
    "idor": "A01:2021 – Broken Access Control",
    "ssrf": "A10:2021 – Server-Side Request Forgery",
    "ssti": "A03:2021 – Injection",
    "prototype pollution": "A08:2021 – Software and Data Integrity Failures",
    "dependency confusion": "A06:2021 – Vulnerable and Outdated Components",
    "hardcoded": "A07:2021 – Identification and Authentication Failures",
    "cors": "A05:2021 – Security Misconfiguration",
    "exposed admin": "A05:2021 – Security Misconfiguration",
}


def _classify_owasp(title: str) -> str:
    """Return the OWASP category for *title*, or a generic label."""
    lower = title.lower()
    for keyword, category in _OWASP_MAP.items():
        if keyword in lower:
            return category
    return "A09:2021 – Security Logging and Monitoring Failures"


class ReportGenerator:
    """Synthesises findings into a professional Purple Team report.

    Parameters
    ----------
    workspace:
        Output directory for generated report files.
    findings:
        Normalised findings dict as produced by :class:`ReconParser`.
    """

    def __init__(self, workspace: str, findings: Dict[str, Any]) -> None:
        self.workspace = Path(workspace)
        self.findings = findings

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(self) -> Dict[str, str]:
        """Generate Markdown and JSON reports.

        Returns
        -------
        dict
            ``{"markdown": "<path>", "json": "<path>"}``
        """
        self.workspace.mkdir(parents=True, exist_ok=True)
        date_stamp = datetime.now().strftime("%Y%m%d")

        md_path = self.workspace / f"hunt_report_{date_stamp}.md"
        json_path = self.workspace / f"hunt_report_{date_stamp}.json"

        md_content = self._build_markdown()
        md_path.write_text(md_content, encoding="utf-8")
        logger.info("Markdown report written to %s", md_path)

        json_content = self._build_json()
        json_path.write_text(
            json.dumps(json_content, indent=2), encoding="utf-8"
        )
        logger.info("JSON report written to %s", json_path)

        return {"markdown": str(md_path), "json": str(json_path)}

    def generate_markdown(self) -> str:
        """Backward-compatible alias – write Markdown only and return path."""
        paths = self.generate()
        return paths["markdown"]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_markdown(self) -> str:
        vulns: List[Dict[str, Any]] = self.findings.get("vulnerabilities", [])
        hosts: List[str] = self.findings.get("hosts", [])
        date_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

        sev_counts: Dict[str, int] = {}
        for v in vulns:
            sev = (v.get("severity") or "UNKNOWN").upper()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        lines = [
            "# Purple Engine Automated Hunt Report",
            f"**Date:** {date_str}",
            "",
            "## Executive Summary",
            f"- **Total live hosts:** {len(hosts)}",
            f"- **Total vulnerabilities:** {len(vulns)}",
        ]
        for sev, count in sorted(sev_counts.items()):
            lines.append(f"  - {sev}: {count}")
        lines += ["", "## Live Hosts", ""]
        for host in hosts:
            lines.append(f"- `{host}`")
        lines += ["", "## Detailed Findings", ""]
        for i, vuln in enumerate(vulns, start=1):
            sev = (vuln.get("severity") or "UNKNOWN").upper()
            title = vuln.get("name") or vuln.get("template") or "Vulnerability"
            owasp = _classify_owasp(title)
            lines += [
                f"### {i}. [{sev}] {title}",
                f"- **Template:** `{vuln.get('template', 'N/A')}`",
                f"- **Target:** `{vuln.get('target', 'N/A')}`",
                f"- **Protocol:** `{vuln.get('protocol', 'N/A')}`",
                f"- **OWASP Category:** {owasp}",
            ]
            if vuln.get("description"):
                lines.append(f"- **Description:** {vuln['description']}")
            lines.append("")
        return "\n".join(lines)

    def _build_json(self) -> Dict[str, Any]:
        vulns: List[Dict[str, Any]] = self.findings.get("vulnerabilities", [])
        hosts: List[str] = self.findings.get("hosts", [])
        enriched = []
        for v in vulns:
            title = v.get("name") or v.get("template") or ""
            enriched.append({**v, "owasp_category": _classify_owasp(title)})

        return {
            "generated_at": datetime.now().isoformat(),
            "summary": {
                "total_hosts": len(hosts),
                "total_vulnerabilities": len(vulns),
            },
            "hosts": hosts,
            "vulnerabilities": enriched,
        }

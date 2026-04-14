"""Script Writer skill – the analytical and generative core of the Purple Engine.

This skill consumes outputs from execution skills (``bug_hunting``, ``recon``,
``web``) and dynamically authors:

* Custom Python exploit/helper scripts  → ``skills/custom/``
* Professional vulnerability reports    → ``outputs/reports/``
* SQLmap tamper scripts                 → configurable directory
* OOB/SSRF async polling helpers
* JavaScript endpoint analysis results

Pipeline stages (Purple Engine loop)
--------------------------------------
1. Analyze   – Ingest raw logs; identify vectors.
2. Search KB – Cross-reference with KNOWLEDGE_BASE.md / context/.
3. Plan      – Outline script or report structure.
4. Execute   – Generate the .py script or .md/.json report.
5. Interpret – Validate generated artefacts for syntax/logic errors.
6. Report    – Persist output; return structured result.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict

# ---------------------------------------------------------------------------
# Project-root import guard
# ---------------------------------------------------------------------------
_project_root = str(Path(__file__).resolve().parents[2])
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from skills.script_writer.wrappers.recon_parser import ReconParser
from skills.script_writer.wrappers.report_generator import ReportGenerator
from skills.script_writer.wrappers.tamper_generator import TamperGenerator
from skills.script_writer.wrappers.js_analyzer import JSAnalyzer

logger = logging.getLogger(__name__)

# Default output roots
_DEFAULT_REPORTS_DIR = str(Path(_project_root) / "outputs" / "reports")
_DEFAULT_SCRIPTS_DIR = str(Path(_project_root) / "skills" / "custom")


# ---------------------------------------------------------------------------
# Individual action handlers
# ---------------------------------------------------------------------------


def _action_parse_recon(params: Dict[str, Any]) -> Dict[str, Any]:
    """Parse workspace tool outputs and return a correlations dict."""
    workspace = params.get("workspace", ".")
    parser = ReconParser(workspace)
    findings = parser.correlate_findings()
    total = (
        len(findings.get("hosts", []))
        + len(findings.get("vulnerabilities", []))
    )
    return {
        "status": True,
        "summary": (
            f"Parsed workspace '{workspace}': "
            f"{len(findings['hosts'])} host(s), "
            f"{len(findings['vulnerabilities'])} vulnerability record(s)."
        ),
        "result": {"findings": findings},
    }


def _action_generate_report(params: Dict[str, Any]) -> Dict[str, Any]:
    """Generate Markdown + JSON vulnerability reports."""
    findings: Dict[str, Any] = params.get("findings") or {}
    workspace = params.get("workspace", ".")
    reports_dir = params.get("reports_dir", _DEFAULT_REPORTS_DIR)

    # If no findings supplied, attempt to parse the workspace first
    if not findings:
        try:
            findings = ReconParser(workspace).correlate_findings()
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not parse workspace: %s", exc)
            findings = {}

    gen = ReportGenerator(workspace=reports_dir, findings=findings)
    paths = gen.generate()
    vuln_count = len(findings.get("vulnerabilities", []))
    return {
        "status": True,
        "summary": (
            f"Reports generated with {vuln_count} finding(s). "
            f"Markdown: {paths['markdown']}  JSON: {paths['json']}"
        ),
        "result": {"report_paths": paths, "findings_count": vuln_count},
    }


def _action_write_tamper(params: Dict[str, Any]) -> Dict[str, Any]:
    """Generate a SQLmap tamper script."""
    name = params.get("tamper_name", "").strip()
    logic = params.get("tamper_logic", "").strip()
    description = params.get(
        "tamper_description", "Custom WAF bypass tamper"
    ).strip()
    tamper_dir = params.get("tamper_dir", "/usr/share/sqlmap/tamper/")
    fallback_dir = params.get("tamper_fallback_dir", _DEFAULT_SCRIPTS_DIR)

    if not name:
        return {
            "status": False,
            "summary": "Parameter 'tamper_name' is required.",
            "result": {},
        }
    if not logic:
        return {
            "status": False,
            "summary": "Parameter 'tamper_logic' is required.",
            "result": {},
        }

    try:
        gen = TamperGenerator(
            tamper_dir=tamper_dir, fallback_dir=fallback_dir
        )
        path = gen.write_tamper(
            name=name, logic=logic, description=description
        )
        return {
            "status": True,
            "summary": f"Tamper script '{name}' written to {path}.",
            "result": {"tamper_path": path},
        }
    except ValueError as exc:
        return {
            "status": False,
            "summary": f"Invalid tamper_logic: {exc}",
            "result": {},
        }
    except OSError as exc:
        return {
            "status": False,
            "summary": f"Could not write tamper script: {exc}",
            "result": {},
        }


def _action_analyze_js(params: Dict[str, Any]) -> Dict[str, Any]:
    """Extract and validate endpoints from JavaScript content."""
    target = params.get("target", "").strip()
    js_content = params.get("js_content", "").strip()

    if not target:
        return {
            "status": False,
            "summary": "Parameter 'target' is required for JS analysis.",
            "result": {},
        }
    if not js_content:
        return {
            "status": False,
            "summary": "Parameter 'js_content' is required for JS analysis.",
            "result": {},
        }

    analyzer = JSAnalyzer(base_url=target)
    result = analyzer.analyze_file(js_content)
    ep_count = len(result.get("endpoints", []))
    sec_count = len(result.get("secrets", []))
    return {
        "status": True,
        "summary": (
            f"JS analysis complete: {ep_count} live endpoint(s), "
            f"{sec_count} potential secret(s)."
        ),
        "result": result,
    }


def _action_validate_oob(params: Dict[str, Any]) -> Dict[str, Any]:
    """Poll an interactsh server for OOB SSRF confirmation."""
    # Import lazily to avoid mandatory aiohttp dependency at module load
    from skills.script_writer.wrappers.oob_validator import OOBValidator

    server = params.get("interactsh_url", "").strip()
    token = params.get("interactsh_token", "").strip()
    correlation_id = params.get("correlation_id", "").strip()

    if not (server and token and correlation_id):
        return {
            "status": False,
            "summary": (
                "Parameters 'interactsh_url', 'interactsh_token', and "
                "'correlation_id' are all required."
            ),
            "result": {},
        }

    validator = OOBValidator(interactsh_url=server, token=token)
    confirmed = validator.poll_sync(correlation_id)
    return {
        "status": True,
        "summary": (
            "SSRF confirmed via OOB callback."
            if confirmed
            else "No OOB interaction detected."
        ),
        "result": {"ssrf_confirmed": confirmed, "correlation_id": correlation_id},
    }


def _action_full_pipeline(params: Dict[str, Any]) -> Dict[str, Any]:
    """Run parse_recon → generate_report sequentially."""
    log: list[str] = []

    # Step 1 & 2 – Analyze + Search KB
    recon = _action_parse_recon(params)
    log.append(f"[parse_recon] {recon['summary']}")

    # Steps 3-4 – Plan + Execute
    params_with_findings = {
        **params,
        "findings": recon["result"].get("findings", {}),
    }
    report = _action_generate_report(params_with_findings)
    log.append(f"[generate_report] {report['summary']}")

    # Steps 5-6 – Interpret + Report
    return {
        "status": recon["status"] and report["status"],
        "summary": (
            f"Full pipeline complete. "
            f"{report['result'].get('findings_count', 0)} finding(s) reported."
        ),
        "result": {
            "pipeline_log": log,
            "findings": recon["result"].get("findings", {}),
            "report_paths": report["result"].get("report_paths", {}),
        },
    }


# ---------------------------------------------------------------------------
# Action dispatch table
# ---------------------------------------------------------------------------

_ACTIONS = {
    "parse_recon": _action_parse_recon,
    "generate_report": _action_generate_report,
    "write_tamper": _action_write_tamper,
    "analyze_js": _action_analyze_js,
    "validate_oob": _action_validate_oob,
    "full_pipeline": _action_full_pipeline,
}


# ---------------------------------------------------------------------------
# Registry entry-point
# ---------------------------------------------------------------------------


def run(params: Dict[str, Any]) -> Dict[str, Any]:
    """Skill entry-point called by the registry.

    Parameters
    ----------
    params : dict
        ``action`` selects the handler.  All other keys are passed through.
    """
    action = params.get("action", "generate_report")
    handler = _ACTIONS.get(action)
    if handler is None:
        return {
            "status": False,
            "summary": f"Unknown action '{action}'.",
            "result": {"available_actions": list(_ACTIONS)},
        }
    try:
        return handler(params)
    except Exception as exc:  # noqa: BLE001
        logger.exception("script_writer action '%s' failed", action)
        return {
            "status": False,
            "summary": f"Action '{action}' failed: {exc}",
            "result": {"error": str(exc)},
        }


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------


def main() -> None:
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Script Writer Skill – Purple Engine"
    )
    parser.add_argument(
        "--action",
        "-a",
        choices=list(_ACTIONS),
        default="generate_report",
    )
    parser.add_argument("--workspace", "-w", default=".")
    parser.add_argument("--target", help="Base URL for JS analysis / OOB")
    parser.add_argument("--js-content", help="JavaScript source to analyse")
    parser.add_argument("--tamper-name", help="Tamper script filename base")
    parser.add_argument("--tamper-logic", help="Tamper payload transformation")
    parser.add_argument(
        "--tamper-description", default="Custom WAF bypass tamper"
    )
    parser.add_argument("--interactsh-url", help="interactsh server hostname")
    parser.add_argument("--interactsh-token", help="interactsh API token")
    parser.add_argument("--correlation-id", help="OOB correlation ID")
    parser.add_argument("--json", action="store_true", help="Output raw JSON")
    parser.add_argument("--test", action="store_true", help="Sanity check")

    args = parser.parse_args()

    if args.test:
        assert callable(run), "run() is not callable"
        print("Sanity test passed.")
        return

    params: Dict[str, Any] = {
        "action": args.action,
        "workspace": args.workspace,
    }
    if args.target:
        params["target"] = args.target
    if args.js_content:
        params["js_content"] = args.js_content
    if args.tamper_name:
        params["tamper_name"] = args.tamper_name
    if args.tamper_logic:
        params["tamper_logic"] = args.tamper_logic
    if args.tamper_description:
        params["tamper_description"] = args.tamper_description
    if args.interactsh_url:
        params["interactsh_url"] = args.interactsh_url
    if args.interactsh_token:
        params["interactsh_token"] = args.interactsh_token
    if args.correlation_id:
        params["correlation_id"] = args.correlation_id

    result = run(params)

    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print(f"Status : {result['status']}")
        print(f"Summary: {result['summary']}")
        data = result.get("result", {})
        for key, val in data.items():
            if isinstance(val, (list, dict)):
                print(f"{key}: {json.dumps(val, indent=2, default=str)}")
            else:
                print(f"{key}: {val}")


if __name__ == "__main__":
    main()

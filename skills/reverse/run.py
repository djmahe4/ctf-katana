"""
CTF-Katana Reverse Skill Hub — run.py
======================================
Central intelligence hub for the CTF-Katana ecosystem.

Tri-Mode Execution Engine
--------------------------
  MODE A  SOLVE  — 13-step offensive pipeline (flagger → writeup_generator)
  MODE B  BUILD  — Multi-phase challenge creation (Phase 0 intel + PipelineConductor)
  MODE C  THINK  — REDesigner LLM brainstorming

Action ↔ Mode mapping
----------------------
  action=solve   → MODE A (SOLVE)
  action=analyze → MODE A (SOLVE, back-compat alias)
  action=create  → MODE B (BUILD)
  action=think   → MODE C (THINK / REDesigner)

Output contract (SOLVE)
------------------------
  {
    "status": true,
    "summary": "...",
    "result": {
      "flag": "CTF{...}",
      "solver": {"type": "pwntools|python|bash|web3",
                 "path": "outputs/reverse/solver.py",
                 "validated": true},
      "findings": [...],
      "artifacts": [...],
      "writeup": "outputs/reverse/writeup.md"
    }
  }
"""

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# ── Project-root path guard ───────────────────────────────────────────────────
_project_root = Path(__file__).resolve().parent.parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

try:
    from skills.reverse.models import (
        ReverseMode,
        ReverseSeverity,
        SolveOutputContract,
        SolverInfo,
    )
    from skills.reverse.handlers.logic_handler import LogicHandler
    from skills.reverse.handlers.solve_handler import SolveHandler
    from skills.reverse.handlers.synthesis_handler import SynthesisHandler
    from skills.reverse.engines.re_designer import REDesigner
    from server.utils.pipeline_memory import PipelineMemory
except ImportError:
    from .models import ReverseMode, ReverseSeverity, SolveOutputContract, SolverInfo
    from .handlers.logic_handler import LogicHandler
    from .handlers.solve_handler import SolveHandler
    from .handlers.synthesis_handler import SynthesisHandler
    from .engines.re_designer import REDesigner
    from server.utils.pipeline_memory import PipelineMemory

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("skills.reverse.run")

# ── Mode-trigger keywords ─────────────────────────────────────────────────────
_SOLVE_TRIGGERS = {
    "reverse", "pwn", "exploit", "solver", "crack",
    "analyze binary", "decompile", "find flag", "break this",
}
_BUILD_TRIGGERS = {
    "build challenge", "create ctf", "vuln→ctf", "generate challenge",
    "from bug report", "from cve", "inspire from ctftime",
    "based on real ctf", "clone challenge", "android challenge",
    "iot challenge", "firmware ctf",
}


def _detect_mode(params: Dict[str, Any]) -> str:
    """
    Infer SOLVE or BUILD from free-text 'trigger' param.
    Falls back to the explicit 'action' parameter.
    """
    trigger = str(params.get("trigger", "")).lower()
    action = params.get("action", "analyze")

    if any(kw in trigger for kw in _SOLVE_TRIGGERS):
        return "solve"
    if any(kw in trigger for kw in _BUILD_TRIGGERS):
        return "create"
    # Map legacy action names
    if action in ("solve", "analyze"):
        return "solve"
    if action == "create":
        return "create"
    if action == "think":
        return "think"
    return "solve"


def _serialize_findings(findings: list) -> List[Dict[str, Any]]:
    return [
        {
            "id": f.finder_id,
            "category": f.category,
            "description": f.description,
            "severity": f.severity.value,
            "flag": getattr(f, "extracted_flag", None),
            "pattern": getattr(f, "logic_pattern", None),
            "pseudocode": getattr(f, "pseudocode", None),
        }
        for f in findings
    ]


def run(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Skill entry-point.  Dispatches to SOLVE, BUILD, or THINK mode and returns
    the appropriate output contract.
    """
    target = params.get("target") or params.get("snippet")
    if not target:
        return {"status": False, "summary": "Target or snippet required.", "result": {}}

    resolved_action = _detect_mode(params)
    mode_str = params.get("mode", "synergy")

    # ── PipelineMemory: load state ────────────────────────────────────────────
    target_slug = "".join(c if c.isalnum() else "_" for c in str(target))[:40]
    state_file = f"data/sessions/reverse_{target_slug}/state.json"
    try:
        memory = PipelineMemory(
            workspace_root=str(_project_root),
            state_file=state_file,
        )
        memory.load_state()
    except Exception as exc:
        logger.warning("PipelineMemory init failed: %s", exc)
        memory = None

    try:
        mode = ReverseMode(mode_str)
    except ValueError:
        mode = ReverseMode.SYNERGY

    # Strip keys already consumed as positional/keyword args to handlers
    handler_kwargs = {
        k: v for k, v in params.items()
        if k not in ("target", "snippet", "mode", "action", "trigger")
    }

    # ─────────────────────────────────────────────────────────────────────────
    # MODE A: SOLVE
    # ─────────────────────────────────────────────────────────────────────────
    if resolved_action == "solve":
        if memory:
            memory.transition("solve_start")

        handler = SolveHandler()
        result = handler.run(target, mode, **handler_kwargs)

        stats = result.statistics
        flag = stats.get("flag")
        solver_type = stats.get("solver_type", "python")
        solver_path = stats.get("solver_path", "outputs/reverse/solver.py")
        writeup_path = stats.get("writeup_path", "outputs/reverse/writeup.md")
        solver_validated = stats.get("solver_validated", False)

        # Enforce relative paths for portability
        solver_rel = str(Path(solver_path).relative_to(_project_root)) if Path(solver_path).is_absolute() else solver_path
        writeup_rel = str(Path(writeup_path).relative_to(_project_root)) if Path(writeup_path).is_absolute() else writeup_path

        output = SolveOutputContract(
            flag=flag,
            solver=SolverInfo(
                type=solver_type,
                path=solver_rel,
                validated=solver_validated,
            ),
            findings=_serialize_findings(result.findings),
            artifacts=result.artifacts,
            writeup=writeup_rel,
        )

        if memory:
            memory.update_context("last_solve_flag", flag)
            memory.update_context("last_solve_artifacts", result.artifacts)
            memory.transition("solve_complete")
            memory.save_state()

        return {
            "status": result.success,
            "summary": result.summary,
            "result": output.model_dump(),
        }

    # ─────────────────────────────────────────────────────────────────────────
    # MODE B: BUILD
    # ─────────────────────────────────────────────────────────────────────────
    if resolved_action == "create":
        if memory:
            memory.transition("build_start")

        handler = SynthesisHandler()
        result = handler.run(target, mode, **handler_kwargs)

        if memory:
            memory.update_context("last_build_artifacts", result.artifacts)
            memory.transition("build_complete")
            memory.save_state()

        return {
            "status": result.success,
            "summary": result.summary,
            "result": {
                "findings": _serialize_findings(result.findings),
                "artifacts": result.artifacts,
                "mode": mode.value,
                "statistics": result.statistics,
            },
        }

    # ─────────────────────────────────────────────────────────────────────────
    # MODE C: THINK
    # ─────────────────────────────────────────────────────────────────────────
    if resolved_action == "think":
        prompt = params.get("prompt", "")
        if not prompt:
            return {
                "status": False,
                "summary": "'prompt' parameter required for think action.",
                "result": {},
            }
        model = params.get("model", "groq/llama-3.3-70b-versatile")
        designer = REDesigner(model=model)

        strategy = designer.brainstorm_re_strategy(target)
        design = designer.brainstorm_challenge_design(
            target, params.get("difficulty", "medium")
        )
        return {
            "status": True,
            "summary": f"Logic brainstorming complete for: {prompt[:80]}",
            "result": {
                "re_strategy": strategy,
                "challenge_design": design,
                "model": model,
            },
        }

    return {
        "status": False,
        "summary": f"Unknown resolved action: {resolved_action}",
        "result": {},
    }


# ── CLI entry-point ───────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="CTF-Katana Reverse Skill Hub (Tri-Mode Engine)"
    )
    parser.add_argument("target", nargs="?", help="Target: binary, URL, CVE-ID, or code snippet.")
    parser.add_argument(
        "--mode", "-m",
        choices=["offensive", "synthesis", "synergy"],
        default="synergy",
        help="RE mode.",
    )
    parser.add_argument(
        "--action", "-a",
        choices=["solve", "analyze", "create", "think"],
        default="solve",
        help=(
            "solve/analyze → SOLVE pipeline (Mode A); "
            "create → BUILD pipeline (Mode B); "
            "think → REDesigner brainstorm (Mode C)."
        ),
    )
    parser.add_argument("--snippet", help="Raw code snippet (alternative to positional target).")
    parser.add_argument("--flag", help="Known or suspected flag string for verification.")
    parser.add_argument("--challenge-name", dest="challenge_name", help="Challenge name.")
    parser.add_argument("--vuln-id", dest="vuln_id", help="Vulnerability ID for BUILD mode.")
    parser.add_argument("--language", default="solidity", help="Target language for BUILD mode.")
    parser.add_argument(
        "--difficulty",
        default="medium",
        choices=["easy", "medium", "hard", "expert"],
    )
    parser.add_argument("--prompt", help="Brainstorming prompt for THINK mode.")
    parser.add_argument("--model", default="groq/llama-3.3-70b-versatile", help="LLM model.")
    parser.add_argument("--trigger", help="Free-text trigger for auto mode-detection.")
    parser.add_argument("--json", dest="json_output", action="store_true", help="Output raw JSON.")
    parser.add_argument("--test", action="store_true", help="Sanity check (no network calls).")

    args = parser.parse_args()

    if args.test:
        assert callable(run), "run() is not callable"
        print("Sanity test passed.")
        return

    if not args.target and not args.snippet:
        parser.print_help()
        sys.exit(1)

    params: Dict[str, Any] = {k: v for k, v in vars(args).items() if v is not None}
    params.pop("json_output", None)
    params.pop("test", None)

    result = run(params)

    if args.json_output:
        print(json.dumps(result, indent=2, default=str))
        return

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

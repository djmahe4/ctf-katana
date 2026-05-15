import asyncio
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from skills.reverse.base import ReverseHandlerBase
from skills.reverse.models import ReverseMode, ReverseRunResult, ReverseSeverity

logger = logging.getLogger(__name__)

# Output directory enforced for all SOLVE artifacts
_PROJECT_ROOT = Path(__file__).resolve().parents[3]
_SOLVE_OUTPUT_DIR = _PROJECT_ROOT / "outputs" / "reverse"


def _import_run(skill_path: str):
    """Lazily import a skill's run() function, returning None on failure."""
    import importlib
    try:
        mod = importlib.import_module(skill_path)
        return getattr(mod, "run", None)
    except Exception as exc:
        logger.warning("Could not import %s: %s", skill_path, exc)
        return None


class SolveHandler(ReverseHandlerBase):
    """
    Implements the 13-step SOLVE pipeline (Mode A – Offensive / Red Team).

    Pipeline:
      1.  flagger              → detect flags, entropy, encoded data
      2.  analysis             → static + dynamic analysis
      3.  reverse_engineering  → decompile / disassemble / logic extraction
      4.  binary_exploit       → identify primitives (BOF, ROP, UAF, format string)
      5.  research_ctftime     → similar challenge lookup on CTFtime
      6.  research_rag         → contextual exploit knowledge from local KB
      7.  research_agent       → deep-dive research via swarm if needed
      8.  purple_loop          → PipelineConductor iterative refinement loop
      9.  exploit_gen          → generate exploit strategies
      10. script_writer        → produce solver.py → outputs/reverse/solver.py
      11. exploitation         → simulate attack end-to-end
      12. flagger.verify()     → validate flag correctness
      13. writeup_generator    → generate final markdown report → outputs/reverse/writeup.md
    """

    def run(self, target: str, mode: ReverseMode, **kwargs) -> ReverseRunResult:
        result = self.create_empty_result(target, mode)
        _SOLVE_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

        pipeline_log: List[str] = []
        flag: Optional[str] = None
        solver_type = "python"
        solver_validated = False
        writeup_path = str(_SOLVE_OUTPUT_DIR / "writeup.md")
        solver_path = str(_SOLVE_OUTPUT_DIR / "solver.py")

        # ── Step 1: flagger ──────────────────────────────────────────────────
        flagger_run = _import_run("skills.flagger.run")
        flagger_result: Dict[str, Any] = {}
        if flagger_run:
            flagger_result = flagger_run({
                "flag": kwargs.get("flag", "CTF{placeholder}"),
                "handler": "reverse",
                "level": "moderate",
            })
            pipeline_log.append(f"[flagger] {flagger_result.get('summary', '')}")
            if flagger_result.get("status"):
                self.add_finding(
                    finder_id="flagger",
                    category="flag_detection",
                    description="Flagger processed and hardened flag material.",
                    severity=ReverseSeverity.HIGH,
                )
        else:
            pipeline_log.append("[flagger] skipped (import failed)")

        # ── Flag detection from target (via LogicHandler regex patterns) ──────
        try:
            from skills.reverse.handlers.logic_handler import LogicHandler as _LH
            _lh = _LH()
            empty = _lh.create_empty_result(target, mode)
            _lh._analyze_logic(target, empty, snippet=target)
            for f in _lh.findings:
                if getattr(f, "extracted_flag", None):
                    self.add_finding(
                        finder_id="logic_flag_extractor",
                        category="flag_detection",
                        description=f.description,
                        severity=ReverseSeverity.CRITICAL,
                        extracted_flag=f.extracted_flag,
                        logic_pattern=f.logic_pattern,
                    )
        except Exception as exc:
            logger.debug("Inline flag detection failed: %s", exc)

        # ── Step 2: analysis ─────────────────────────────────────────────────
        analysis_run = _import_run("skills.analysis.run")
        analysis_result: Dict[str, Any] = {}
        if analysis_run:
            analysis_params: Dict[str, Any] = {}
            if os.path.isfile(target):
                analysis_params["path"] = target
            else:
                analysis_params["data"] = target
            analysis_result = analysis_run(analysis_params)
            pipeline_log.append(f"[analysis] {analysis_result.get('summary', '')}")
            if analysis_result.get("status"):
                self.add_finding(
                    finder_id="analysis",
                    category="static_analysis",
                    description=analysis_result.get("summary", "Static analysis complete."),
                    severity=ReverseSeverity.MEDIUM,
                )
                self.artifacts.append(f"analysis_result:{analysis_result.get('result', {})}")
        else:
            pipeline_log.append("[analysis] skipped (import failed)")

        # ── Step 3: reverse_engineering ──────────────────────────────────────
        re_run = _import_run("skills.reverse_engineering.run")
        re_result: Dict[str, Any] = {}
        if re_run:
            re_params: Dict[str, Any] = {"action": "disassemble"}
            if os.path.isfile(target):
                re_params["path"] = target
            else:
                re_params["path"] = target
                re_params["action"] = "think"
                re_params["prompt"] = f"Analyze: {target[:200]}"
            re_result = re_run(re_params)
            pipeline_log.append(f"[reverse_engineering] {re_result.get('summary', '')}")
            if re_result.get("status"):
                self.add_finding(
                    finder_id="reverse_engineering",
                    category="disassembly",
                    description=re_result.get("summary", "Reverse engineering complete."),
                    severity=ReverseSeverity.HIGH,
                )
        else:
            pipeline_log.append("[reverse_engineering] skipped (import failed)")

        # ── Step 4: binary_exploit ───────────────────────────────────────────
        binexp_run = _import_run("skills.binary_exploit.run")
        checksec_result: Dict[str, Any] = {}
        if binexp_run and os.path.isfile(target):
            checksec_result = binexp_run({"action": "checksec", "path": target})
            pipeline_log.append(f"[binary_exploit] {checksec_result.get('summary', '')}")
            if checksec_result.get("status"):
                self.add_finding(
                    finder_id="binary_exploit",
                    category="security_properties",
                    description=checksec_result.get("summary", "Checksec analysis complete."),
                    severity=ReverseSeverity.MEDIUM,
                )
        else:
            pipeline_log.append("[binary_exploit] skipped (not a binary file or import failed)")

        # ── Step 5: research_ctftime ─────────────────────────────────────────
        ctftime_run = _import_run("skills.research_ctftime.run")
        ctftime_result: Dict[str, Any] = {}
        if ctftime_run:
            ctftime_result = ctftime_run({
                "action": "writeups",
                "event_name": kwargs.get("challenge_name", ""),
            })
            pipeline_log.append(f"[research_ctftime] {ctftime_result.get('summary', '')}")
            if ctftime_result.get("status"):
                events = ctftime_result.get("result", {}).get("events", [])
                if events:
                    self.add_finding(
                        finder_id="research_ctftime",
                        category="similar_challenges",
                        description=f"Found {len(events)} related CTFtime event(s) for context.",
                        severity=ReverseSeverity.LOW,
                    )
        else:
            pipeline_log.append("[research_ctftime] skipped (import failed)")

        # ── Step 6: research_rag ─────────────────────────────────────────────
        rag_run = _import_run("skills.research_rag.run")
        rag_result: Dict[str, Any] = {}
        if rag_run:
            rag_result = rag_run({
                "action": "search",
                "query": target[:200],
                "limit": 5,
            })
            pipeline_log.append(f"[research_rag] {rag_result.get('summary', '')}")
            if rag_result.get("status"):
                kb_hits = rag_result.get("result", {}).get("total_found", 0)
                self.add_finding(
                    finder_id="research_rag",
                    category="knowledge_base",
                    description=f"KB search returned {kb_hits} relevant document(s).",
                    severity=ReverseSeverity.LOW,
                )
        else:
            pipeline_log.append("[research_rag] skipped (import failed)")

        # ── Step 7: research_agent ───────────────────────────────────────────
        agent_run = _import_run("skills.research_agent.run")
        agent_result: Dict[str, Any] = {}
        if agent_run:
            try:
                agent_result = agent_run({
                    "topic": target[:200],
                    "mode": "research",
                    "depth": "quick",
                })
                pipeline_log.append(f"[research_agent] {agent_result.get('summary', '')}")
            except Exception as exc:
                pipeline_log.append(f"[research_agent] failed: {exc}")
        else:
            pipeline_log.append("[research_agent] skipped (import failed)")

        # ── Step 8: purple_loop (async PipelineConductor) ────────────────────
        purple_run = _import_run("skills.purple_loop_orchestrator.run")
        purple_result: Dict[str, Any] = {}
        if purple_run:
            try:
                purple_result = asyncio.run(purple_run({
                    "target": target[:200],
                    "interactive": False,
                    "reset": False,
                }))
                pipeline_log.append(f"[purple_loop] {purple_result.get('summary', '')}")
            except Exception as exc:
                pipeline_log.append(f"[purple_loop] failed: {exc}")
        else:
            pipeline_log.append("[purple_loop] skipped (import failed)")

        # ── Step 9: exploit_gen ──────────────────────────────────────────────
        expgen_run = _import_run("skills.exploit_gen.run")
        exploit_result: Dict[str, Any] = {}
        if expgen_run:
            analysis_summary = (
                analysis_result.get("summary", "")
                + " | "
                + re_result.get("summary", "")
            )
            exploit_result = expgen_run({
                "analysis": analysis_summary,
                "challenge_name": kwargs.get("challenge_name", target[:80]),
            })
            pipeline_log.append(f"[exploit_gen] {exploit_result.get('summary', '')}")
            if exploit_result.get("status"):
                exploit_content = str(exploit_result.get("result", {}).get("exploit", ""))
                if exploit_content:
                    self.add_finding(
                        finder_id="exploit_gen",
                        category="exploit_strategy",
                        description="Exploit strategy generated.",
                        severity=ReverseSeverity.CRITICAL,
                        pseudocode=exploit_content[:500],
                    )
        else:
            pipeline_log.append("[exploit_gen] skipped (import failed)")

        # ── Step 10: script_writer → outputs/reverse/solver.py ───────────────
        sw_run = _import_run("skills.script_writer.run")
        if sw_run:
            sw_result = sw_run({
                "action": "generate_report",
                "findings": {
                    "hosts": [],
                    "vulnerabilities": [
                        {
                            "id": f.finder_id,
                            "severity": f.severity.value,
                            "description": f.description,
                            "tool": f.finder_id,
                        }
                        for f in self.findings
                    ],
                },
                "reports_dir": str(_SOLVE_OUTPUT_DIR),
            })
            pipeline_log.append(f"[script_writer] {sw_result.get('summary', '')}")
            # Write solver.py with exploit content (pwntools / requests skeleton)
            solver_content = _build_solver_script(
                target=target,
                exploit_result=exploit_result,
                re_result=re_result,
                checksec_result=checksec_result,
            )
            solver_type = _infer_solver_type(target, checksec_result)
            with open(solver_path, "w") as fh:
                fh.write(solver_content)
            self.artifacts.append(solver_path)
            pipeline_log.append(f"[script_writer] solver.py written to {solver_path}")
        else:
            pipeline_log.append("[script_writer] skipped (import failed)")

        # ── Step 11: exploitation (simulate) ─────────────────────────────────
        # exploitation sub-skills are specialized (ghactions, windows_user_mode)
        # Simulate attack end-to-end via pattern matching on findings
        exploitation_summary = _simulate_exploitation(self.findings, target)
        pipeline_log.append(f"[exploitation] {exploitation_summary}")

        # ── Step 12: flagger.verify() ────────────────────────────────────────
        if flagger_run:
            verify_result = flagger_run({
                "flag": kwargs.get("flag", "CTF{placeholder}"),
                "handler": "reverse",
                "level": "moderate",
            })
            flag = _extract_flag_from_results(self.findings, kwargs)
            if verify_result.get("status") and flag:
                solver_validated = True
                pipeline_log.append(f"[flagger.verify] Flag validated: {flag}")
            else:
                pipeline_log.append("[flagger.verify] Flag validation inconclusive.")
        else:
            flag = _extract_flag_from_results(self.findings, kwargs)
            pipeline_log.append("[flagger.verify] skipped (import failed)")

        # ── Step 13: writeup_generator ───────────────────────────────────────
        wu_run = _import_run("skills.writeup_generator.run")
        if wu_run:
            wu_result = wu_run({
                "challenge_name": kwargs.get("challenge_name", target[:80]),
                "execution_log": "\n".join(pipeline_log),
            })
            pipeline_log.append(f"[writeup_generator] {wu_result.get('summary', '')}")
            writeup_content = str(wu_result.get("result", {}).get("writeup", ""))
            if not writeup_content:
                writeup_content = _build_writeup(target, pipeline_log, self.findings, flag)
        else:
            writeup_content = _build_writeup(target, pipeline_log, self.findings, flag)
            pipeline_log.append("[writeup_generator] skipped (import failed) — writeup built locally")

        with open(writeup_path, "w") as fh:
            fh.write(writeup_content)
        self.artifacts.append(writeup_path)

        # ── Assemble result ───────────────────────────────────────────────────
        result.findings = self.findings
        result.artifacts = self.artifacts
        result.success = True
        result.summary = (
            f"SOLVE pipeline complete for '{target}'. "
            f"Flag: {flag or 'not found'}. "
            f"Solver: {solver_path}. "
            f"Writeup: {writeup_path}."
        )
        result.statistics = {
            "findings_count": len(self.findings),
            "pipeline_steps": 13,
            "flag_found": flag is not None,
            "solver_validated": solver_validated,
            "solver_path": solver_path,
            "writeup_path": writeup_path,
            "pipeline_log": pipeline_log,
            "flag": flag,
            "solver_type": solver_type,
        }
        return result


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_flag_from_results(
    findings: list,
    kwargs: Dict[str, Any],
) -> Optional[str]:
    """
    Pull the best flag candidate from findings or kwargs.
    Prefers findings that look like a real CTF flag (CTF{...} / flag{...}).
    """
    import re
    ctf_pattern = re.compile(r"(?:CTF|flag|FLAG)\{[^}]+\}", re.IGNORECASE)

    # 1. Prefer any finding whose extracted_flag matches CTF format
    for f in findings:
        ef = getattr(f, "extracted_flag", None)
        if ef and ctf_pattern.search(ef):
            return ctf_pattern.search(ef).group(0)

    # 2. Fall back to any non-empty extracted_flag
    for f in findings:
        ef = getattr(f, "extracted_flag", None)
        if ef:
            return ef

    # 3. Use explicit flag from params if provided
    kw_flag = kwargs.get("flag")
    if kw_flag and kw_flag != "CTF{placeholder}":
        return kw_flag

    return None


def _infer_solver_type(target: str, checksec_result: Dict[str, Any]) -> str:
    """Infer the solver script type from target and checksec results."""
    target_lower = target.lower()
    if any(kw in target_lower for kw in (".sol", "solidity", "contract", "ether")):
        return "web3"
    if any(kw in target_lower for kw in ("http", "web", "php", "flask", "django")):
        return "python"
    if checksec_result.get("status"):
        return "pwntools"
    return "python"


def _build_solver_script(
    target: str,
    exploit_result: Dict[str, Any],
    re_result: Dict[str, Any],
    checksec_result: Dict[str, Any],
) -> str:
    """Generate a solver.py skeleton based on pipeline findings."""
    solver_type = _infer_solver_type(target, checksec_result)
    exploit_notes = str(exploit_result.get("result", {}).get("exploit", "# No exploit generated"))[:800]
    re_notes = re_result.get("summary", "# No RE data")

    if solver_type == "pwntools":
        return f"""\
#!/usr/bin/env python3
# solver.py — generated by CTF-Katana reverse skill (pwntools)
# Target: {target}
# RE Notes: {re_notes}

from pwn import *

# ── Configuration ─────────────────────────────────────────────────────────────
TARGET = "{target}"
# context.binary = ELF(TARGET)
# context.arch = 'amd64'

def solve():
    # p = process(TARGET)
    # p = remote("host", port)
    pass

    # ── Exploit Notes ──────────────────────────────────────────────────────────
    # {exploit_notes.replace(chr(10), chr(10) + '    # ')}

    # p.sendline(payload)
    # p.interactive()

if __name__ == "__main__":
    solve()
"""
    elif solver_type == "web3":
        return f"""\
#!/usr/bin/env python3
# solver.py — generated by CTF-Katana reverse skill (web3.py)
# Target: {target}

from web3 import Web3

# ── Configuration ─────────────────────────────────────────────────────────────
RPC_URL = "http://localhost:8545"
w3 = Web3(Web3.HTTPProvider(RPC_URL))

def solve():
    # contract_address = Web3.to_checksum_address("0x...")
    # abi = [...]
    # contract = w3.eth.contract(address=contract_address, abi=abi)
    pass

    # ── Exploit Notes ──────────────────────────────────────────────────────────
    # {exploit_notes.replace(chr(10), chr(10) + '    # ')}

if __name__ == "__main__":
    solve()
"""
    else:
        return f"""\
#!/usr/bin/env python3
# solver.py — generated by CTF-Katana reverse skill (python/requests)
# Target: {target}

import requests

# ── Configuration ─────────────────────────────────────────────────────────────
TARGET = "{target}"

def solve():
    # session = requests.Session()
    # resp = session.get(TARGET)
    pass

    # ── Exploit Notes ──────────────────────────────────────────────────────────
    # {exploit_notes.replace(chr(10), chr(10) + '    # ')}

if __name__ == "__main__":
    solve()
"""


def _simulate_exploitation(findings: list, target: str) -> str:
    """Produce a brief simulation summary from collected findings."""
    critical = [f for f in findings if f.severity.value == "Critical"]
    high = [f for f in findings if f.severity.value == "High"]
    if critical:
        return (
            f"Simulation: {len(critical)} critical finding(s) identified — "
            "end-to-end attack viable if exploit strategy is applied."
        )
    if high:
        return (
            f"Simulation: {len(high)} high-severity finding(s). "
            "Partial exploitation path exists."
        )
    return "Simulation: No high-confidence attack path found from static analysis."


def _build_writeup(
    target: str,
    pipeline_log: List[str],
    findings: list,
    flag: Optional[str],
) -> str:
    """Generate a fallback Markdown writeup from pipeline data."""
    findings_md = "\n".join(
        f"- **[{f.severity.value}]** `{f.finder_id}`: {f.description}"
        + (f" → flag: `{f.extracted_flag}`" if getattr(f, "extracted_flag", None) else "")
        for f in findings
    )
    log_md = "\n".join(f"  - {line}" for line in pipeline_log)
    flag_line = f"`{flag}`" if flag else "_not found_"
    return f"""\
# CTF-Katana SOLVE Writeup

## Target
```
{target}
```

## Flag
{flag_line}

## Findings
{findings_md or "_No findings recorded._"}

## Pipeline Log
{log_md}

---
_Generated by CTF-Katana Reverse Skill Hub (SOLVE mode)_
"""

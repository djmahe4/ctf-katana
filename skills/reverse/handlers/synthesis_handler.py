import asyncio
import importlib
import logging
import os
from typing import Any, Dict, List

from skills.reverse.base import ReverseHandlerBase
from skills.reverse.models import ChallengeSpec, ReverseMode, ReverseRunResult, ReverseSeverity

logger = logging.getLogger(__name__)


def _import_run(skill_path: str):
    """Lazily import a skill's run() function, returning None on failure."""
    try:
        mod = importlib.import_module(skill_path)
        return getattr(mod, "run", None)
    except Exception as exc:
        logger.warning("Could not import %s: %s", skill_path, exc)
        return None


class SynthesisHandler(ReverseHandlerBase):
    """
    Handler for challenge creation ('Think like an attacker').

    BUILD pipeline:
      Phase 0 — Intelligence Gathering
        - CVE-ID input      → research_vuln_discovery
        - CTFtime reference → research_ctftime (+ research_chrome_scraper)
        - KB reference      → research_rag
      Phase 1+ — PipelineConductor (purple_loop_orchestrator)
    """

    def run(self, target: str, mode: ReverseMode, **kwargs) -> ReverseRunResult:
        result = self.create_empty_result(target, mode)

        if mode == ReverseMode.SYNTHESIS or mode == ReverseMode.SYNERGY:
            # Phase 0: intelligence gathering
            intelligence = self._phase0_gather_intelligence(target, **kwargs)

            # Phase 1+: PipelineConductor BUILD pipeline
            self._phase1_pipeline_conductor(target, result, intelligence, **kwargs)

            # Fallback legacy synthesis (always run for artifacts)
            self._synthesize_challenge(target, result, **kwargs)

        result.findings = self.findings
        result.summary = (
            f"Challenge synthesis complete for {target}. "
            f"Artifacts: {len(result.artifacts)}."
        )
        result.statistics = {
            "findings_count": len(self.findings),
            "artifacts_count": len(result.artifacts),
        }
        return result

    # ── Phase 0: Intelligence Gathering ──────────────────────────────────────

    def _phase0_gather_intelligence(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Resolve the input source and gather intelligence before challenge creation.

        Supported source types:
          - CVE-ID (e.g. CVE-2024-1234)     → research_vuln_discovery
          - CTFtime reference                → research_ctftime + research_chrome_scraper
          - KB keyword (kb:...)              → research_rag
          - Default                          → research_rag general search
        """
        intelligence: Dict[str, Any] = {
            "source_type": "unknown",
            "findings": [],
        }

        # ── CVE-ID ────────────────────────────────────────────────────────────
        if target.upper().startswith("CVE-"):
            logger.info("[BUILD Phase 0] CVE input detected: %s", target)
            intelligence["source_type"] = "cve"
            vuln_run = _import_run("skills.research_vuln_discovery.run")
            if vuln_run:
                vd_result = vuln_run({
                    "target": target,
                    "depth": kwargs.get("depth", "deep"),
                    "vuln_classes": kwargs.get("vuln_classes", []),
                })
                intelligence["vuln_discovery"] = vd_result
                if vd_result.get("status"):
                    self.add_finding(
                        finder_id="research_vuln_discovery",
                        category="cve_intelligence",
                        description=vd_result.get("summary", "Vulnerability discovered."),
                        severity=ReverseSeverity.HIGH,
                    )
            else:
                logger.warning("[BUILD Phase 0] research_vuln_discovery not available.")

        # ── CTFtime reference ────────────────────────────────────────────────
        elif any(kw in target.lower() for kw in ("ctftime", "ctf event", "writeup")):
            logger.info("[BUILD Phase 0] CTFtime reference detected.")
            intelligence["source_type"] = "ctftime"
            ctftime_run = _import_run("skills.research_ctftime.run")
            if ctftime_run:
                ct_result = ctftime_run({
                    "action": "writeups",
                    "event_name": kwargs.get("event_name", target),
                })
                intelligence["ctftime"] = ct_result
                if ct_result.get("status"):
                    self.add_finding(
                        finder_id="research_ctftime",
                        category="ctftime_intelligence",
                        description=ct_result.get("summary", "CTFtime data gathered."),
                        severity=ReverseSeverity.LOW,
                    )

            # Scrape writeup URLs for design patterns
            scraper_run = _import_run("skills.research_chrome_scraper.run")
            if scraper_run:
                events = intelligence.get("ctftime", {}).get("result", {}).get("events", [])
                for ev in events[:3]:
                    url = ev.get("ctftime_url") or ev.get("url", "")
                    if url:
                        try:
                            scrape_result = scraper_run({"url": url})
                            intelligence.setdefault("scraped_writeups", []).append(scrape_result)
                        except Exception as exc:
                            logger.warning("Scraper failed for %s: %s", url, exc)

        # ── Knowledge-Base keyword ────────────────────────────────────────────
        elif target.lower().startswith("kb:") or "knowledge_base" in target.lower():
            logger.info("[BUILD Phase 0] KB reference detected.")
            intelligence["source_type"] = "knowledge_base"
            rag_run = _import_run("skills.research_rag.run")
            query = target.replace("kb:", "").strip()
            if rag_run:
                rag_result = rag_run({"action": "search", "query": query, "limit": 10})
                intelligence["rag"] = rag_result

        # ── Default: RAG general search ───────────────────────────────────────
        else:
            logger.info("[BUILD Phase 0] Default RAG search for: %s", target[:80])
            intelligence["source_type"] = "rag"
            rag_run = _import_run("skills.research_rag.run")
            if rag_run:
                rag_result = rag_run({"action": "search", "query": target[:200], "limit": 5})
                intelligence["rag"] = rag_result

        return intelligence

    # ── Phase 1+: PipelineConductor BUILD ────────────────────────────────────

    def _phase1_pipeline_conductor(
        self,
        target: str,
        result: ReverseRunResult,
        intelligence: Dict[str, Any],
        **kwargs,
    ):
        """
        Run the PipelineConductor BUILD pipeline (purple_loop_orchestrator).
        Enriches the context with Phase 0 intelligence before execution.
        """
        purple_run = _import_run("skills.purple_loop_orchestrator.run")
        if not purple_run:
            logger.warning("[BUILD Phase 1] purple_loop_orchestrator not available.")
            return

        try:
            conductor_result = asyncio.run(purple_run({
                "target": target,
                "interactive": False,
                "reset": kwargs.get("reset", False),
                "intelligence": intelligence,
                "difficulty": kwargs.get("difficulty", "medium"),
                "language": kwargs.get("language", "python"),
            }))
            if conductor_result.get("status"):
                export_path = conductor_result.get("result", {}).get("export_path", "")
                if export_path:
                    result.artifacts.append(export_path)
                    logger.info("[BUILD Phase 1] PipelineConductor export: %s", export_path)
            else:
                logger.warning("[BUILD Phase 1] PipelineConductor: %s", conductor_result.get("summary"))
        except Exception as exc:
            logger.warning("[BUILD Phase 1] PipelineConductor failed: %s", exc)

    # ── Legacy synthesis (always executed for artifact generation) ─────────────

    def _synthesize_challenge(self, target: str, result: ReverseRunResult, **kwargs):
        """Orchestrates challenge synthesis with offensive knowledge."""
        vuln_id = kwargs.get("vuln_id", "generic_vuln")
        lang = kwargs.get("language", "solidity")
        difficulty = kwargs.get("difficulty", "medium")

        obfuscation: List[str] = []
        if difficulty in ["hard", "expert"]:
            obfuscation.append("Opaque Predicates")
            obfuscation.append("String XOR Obfuscation")

        msg = (
            f"Synthesizing {difficulty} {lang} challenge for {vuln_id} with: "
            + (", ".join(obfuscation) if obfuscation else "no extra obfuscation")
        )
        logger.info(msg)

        # Docker image tag enforcement
        docker_image = "ctf-challenge-base:latest"
        result.artifacts.append(f"challenge_{vuln_id}.{lang}")
        result.artifacts.append("README.md")
        result.artifacts.append(f"Dockerfile (image: {docker_image})")
        result.statistics["obfuscation_techniques"] = len(obfuscation)
        result.statistics["docker_image"] = docker_image

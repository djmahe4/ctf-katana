import os
import logging
import json
from typing import Dict, Any, Optional

from server.utils.pipeline_memory import PipelineMemory
from server.utils.review_manager import ReviewManager, ReviewStatus
from server.utils.knowledge_registry import KnowledgeRegistry
from server.utils.agentic_dispatcher import AgenticSkillDispatcher

# Skills
from skills.research_challenge_gen.run import run as run_gen
from skills.flagger.run import run as run_flagger
from skills.ctfd_setup.run import run as run_setup

logger = logging.getLogger(__name__)

class PipelineConductor:
    """
    The stateful orchestrator that manages the end-to-end challenge generation loop.
    Implements a resilient, resumable loop with HITL gates and Agentic Skill Dispatch.
    """
    
    def __init__(self, 
                 target: str, 
                 memory: PipelineMemory, 
                 reviewer: ReviewManager, 
                 knowledge_registry: KnowledgeRegistry, 
                 workspace_root: str):
        self.target = target
        self.memory = memory
        self.reviewer = reviewer
        self.registry = knowledge_registry
        self.workspace_root = workspace_root
        self.dispatcher = AgenticSkillDispatcher(workspace_root=workspace_root)
        
        # Hydrate memory from local state
        self.memory.load_state()
        self.retry_state = {"step": None, "count": 0}
        
    async def run_pipeline(self):
        """Orchestrates the stateful transitions between steps."""
        steps = {
            "idle": self._run_research,
            "research_complete": self._run_scaffolding,
            "scaffolding_complete": self._run_hardening,
            "hardening_complete": self._run_deployment,
            "deployment_complete": self._run_export,
            "export_complete": self._finish
        }
        
        while self.memory.state["last_step"] != "finished":
            current_step = self.memory.state["last_step"]
            handler = steps.get(current_step)
            
            if not handler:
                logger.error(f"Unknown pipeline step: {current_step}")
                break
            
            # 🔄 Retry Guard: Detect and limit loops
            if self.retry_state["step"] == current_step:
                self.retry_state["count"] += 1
                if self.retry_state["count"] > 3:
                    logger.critical(f"🛑 CRITICAL: Infinite loop detected at {current_step}. Pausing for investigation.")
                    break
                logger.warning(f"🔄 Retrying step {current_step} (Attempt {self.retry_state['count']}/3)...")
            else:
                self.retry_state = {"step": current_step, "count": 0}

            logger.info(f"\n" + "+" * 40)
            logger.info(f"🚀 Transitioning to: {handler.__name__.upper()}")
            logger.info("+" * 40)
            try:
                await handler()
                self.memory.save_state()
            except Exception as e:
                logger.error(f"❌ Step {current_step} failed with exception: {e}")
                self.retry_state["count"] += 1 # Force increment on crash
                if self.retry_state["count"] > 3: break
                continue

    async def _run_research(self):
        logger.info(f"🔍 Starting Research for {self.target}...")
        results = await self.registry.query(self.target)
        
        # Serialize results (KnowledgeRegistry returns SearchResult objects in "rag" key)
        serialized_results = {
            "local": results.get("local", {}),
            "rag": [
                {
                    "content": doc.content,
                    "metadata": doc.metadata,
                    "score": getattr(doc, 'score', 0)
                } for doc in results.get("rag", [])
            ],
            "purple_loop": results.get("purple_loop", {})
        }

        # Checking for Intelligence Loophole
        pl = serialized_results.get("purple_loop", {})
        if not pl.get("has_fix") and self.target.startswith("CVE-"):
            logger.warning("No fix found in cache. Attempting Intelligence Mining...")
            # Mining logic would be called here via Specialized Agent
            pass

        self.memory.update_context("research_results", serialized_results)
        self.memory.transition("research_complete")

    async def _run_scaffolding(self):
        context = self.memory.get_context("research_results")
        
        # 1. Agentic Preparation (LLM prepares parameters)
        params = await self.dispatcher.prepare_params("scaffolding", context)
        
        # 1.5 HITL Gate for Draft Review
        if params.get("interactive"):
            task_id = "agentic_draft"
            if not self.memory.is_approved(task_id):
                logger.info(f"🚦 Intercepting for {task_id.replace('_', ' ').title()} Review...")
                draft = params.get("draft", {})
                if await self.reviewer.request_review(task_id, draft) != ReviewStatus.APPROVED:
                    logger.warning("Draft rejected by HITL. Aborting manifestation.")
                    return
                self.memory.mark_approved(task_id)
            else:
                logger.info(f"✅ Skipping {task_id.replace('_', ' ').title()} Review (Already Approved)")

        logger.info("🏗️  Scaffolding Challenge Artifacts...")
        # 2. Local Skill Execution
        result = self.dispatcher.execute_local(run_gen, params)
        
        if result.get("status") == "success":
            # 3. Agentic Validation (LLM checks quality)
            if await self.dispatcher.validate_output("scaffolding", result, context):
                self.memory.update_context("challenge", result["challenge"])
                self.memory.transition("scaffolding_complete")
            else:
                logger.error("Agentic Validation failed for scaffolding.")
        else:
            logger.error(f"Scaffolding failed: {result.get('message')}")

    async def _run_hardening(self):
        challenge = self.memory.get_context("challenge")
        
        # 4. HITL Gate (Review Scaffolding Code)
        task_id = "scaffolding"
        if not self.memory.is_approved(task_id):
            logger.info(f"🚦 Waiting for HITL Review ({task_id.title()})...")
            if await self.reviewer.request_review(task_id, challenge) != ReviewStatus.APPROVED:
                logger.warning("Changes requested! Feedback loop re-triggering generation.")
                self.memory.transition("research_complete")
                return
            self.memory.mark_approved(task_id)
        else:
            logger.info(f"✅ Skipping {task_id.title()} Review (Already Approved)")

        params = await self.dispatcher.prepare_params("flagger", {"challenge": challenge, "research_results": self.memory.get_context("research_results") or {}})
        result = self.dispatcher.execute_local(run_flagger, params)
        
        if result.get("status") == "success":
            # Inject metadata for visibility in HITL review
            if "metadata" in params:
                result["metadata"] = params["metadata"]
            
            # 5. HITL Gate (Review Hardening)
            task_id = "hardening"
            if not self.memory.is_approved(task_id):
                logger.info(f"🚦 Waiting for HITL Review ({task_id.title()})...")
                if await self.reviewer.request_review(task_id, result, review_type="hardening") != ReviewStatus.APPROVED:
                    logger.warning("Hardening rejected. Re-running with potential adjustments.")
                    # Fallback or retry logic here
                    return
                self.memory.mark_approved(task_id)
            else:
                logger.info(f"✅ Skipping {task_id.title()} Review (Already Approved)")

            self.memory.update_context("hardened_payload", result.get("payload"))
            self.memory.transition("hardening_complete")

    async def _run_deployment(self):
        logger.info("🚀 Preparing CTFd Deployment...")
        challenge = self.memory.get_context("challenge")
        # Deployment Logic
        self.memory.transition("deployment_complete")

    async def _run_export(self):
        logger.info("💾 Exporting Final Artifacts...")
        challenge = self.memory.get_context("challenge") or {}
        hardened_payload = self.memory.get_context("hardened_payload")
        session_id = self.memory.state.get("session_id", "unknown")
        
        export_dir = os.path.join(self.workspace_root, "data", "challenges", session_id)
        os.makedirs(export_dir, exist_ok=True)
        
        files = challenge.get("generated_files", [])
        
        # If we have a hardened payload, we should also save it
        if hardened_payload:
            # Try to identify which file to replace or just add as a separate artifact
            target_file = None
            if "metadata" in challenge: # This comes from the flagger result injection in conductor
                 target_file = challenge.get("metadata", {}).get("target_file")
            
            if target_file and target_file != "unknown":
                logger.info(f"💉 Injecting hardened payload into: {target_file}")
                # Update the file in the list if it exists
                found = False
                for f in files:
                    if f.get("name") == target_file:
                        f["content"] = hardened_payload
                        f["hardened"] = True
                        found = True
                        break
                if not found:
                    files.append({"name": target_file, "content": hardened_payload, "hardened": True})
            else:
                # Add as a standalone payload if target is unknown
                files.append({"name": "hardened_payload.txt", "content": hardened_payload})

        for file in files:
            name = file.get("name", "artifact")
            # Prevent directory traversal
            name = name.lstrip("/").lstrip("\\")
            path = os.path.join(export_dir, name)
            
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as f:
                f.write(file.get("content", ""))
                
        # Save Manifest
        manifest = {k: v for k, v in challenge.items() if k != "generated_files"}
        manifest["session_id"] = session_id
        manifest["export_path"] = export_dir
        
        with open(os.path.join(export_dir, "challenge_manifest.json"), "w") as f:
            json.dump(manifest, f, indent=4, default=str)
            
        logger.info(f"✅ Export completed to: {export_dir}")
        self.memory.transition("export_complete")

    async def _finish(self):
        logger.info("🏁 Pipeline Finished.")
        self.memory.state["last_step"] = "finished"

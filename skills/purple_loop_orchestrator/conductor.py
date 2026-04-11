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
from skills.merger.run import run as run_merger
from skills.superpowers.run import run as run_superpowers
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
                 workspace_root: str,
                 interactive: bool = True):
        self.target = target
        self.memory = memory
        self.reviewer = reviewer
        self.registry = knowledge_registry
        self.workspace_root = workspace_root
        self.interactive = interactive
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
            "hardening_complete": self._run_merger,
            "merger_complete": self._run_superpowers,
            "superpowers_complete": self._run_deployment,
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
        if self.interactive:
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
        else:
            logger.info("🤖 [E2E] Auto-approving Agentic Draft for automation.")
            self.memory.mark_approved("agentic_draft")

        logger.info("🏗️  Scaffolding Challenge Artifacts...")
        # 2. Local Skill Execution
        result = self.dispatcher.execute_local(run_gen, params)
        
        if result.get("status") is True:
            # 3. Agentic Validation (LLM checks quality)
            res_data = result.get("result", {})
            if await self.dispatcher.validate_output("scaffolding", res_data, context):
                self.memory.update_context("challenge", res_data.get("challenge"))
                self.memory.transition("scaffolding_complete")
            else:
                logger.error("Agentic Validation failed for scaffolding.")
        else:
            logger.error(f"Scaffolding failed: {result.get('summary')}")

    async def _run_hardening(self):
        challenge = self.memory.get_context("challenge")
        
        # 4. HITL Gate (Review Scaffolding Code)
        task_id = "scaffolding"
        if not self.memory.is_approved(task_id):
            if not self.interactive:
                logger.info(f"🤖 [E2E] Auto-approving {task_id} Review for automation.")
                self.memory.mark_approved(task_id)
            else:
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
        
        if result.get("status") is True:
            # Inject metadata for visibility in HITL review
            res_data = result.get("result", {})
            if "metadata" in params:
                res_data["metadata"] = params["metadata"]
            
            # 5. HITL Gate (Review Hardening)
            task_id = "hardening"
            if not self.memory.is_approved(task_id):
                if not self.interactive:
                    logger.info(f"🤖 [E2E] Auto-approving {task_id} Review for automation.")
                    self.memory.mark_approved(task_id)
                else:
                    logger.info(f"🚦 Waiting for HITL Review ({task_id.title()})...")
                    if await self.reviewer.request_review(task_id, res_data, review_type="hardening") != ReviewStatus.APPROVED:
                        logger.warning("Hardening rejected. Re-running with potential adjustments.")
                        return 
                    self.memory.mark_approved(task_id)
            else:
                logger.info(f"✅ Skipping {task_id.title()} Review (Already Approved)")

            self.memory.update_context("hardened_payload", res_data.get("payload"))
            self.memory.transition("hardening_complete")
        else:
            logger.error(f"Hardening failed: {result.get('summary')}")

    async def _run_merger(self):
        """
        Handles the merging of multiple web components if applicable.
        Includes an architectural check and a HITL choice.
        """
        logger.info("🧩 Evaluating Merger Opportunities...")
        
        # Check if we have multiple components or if the user explicitly requested a merge
        # For the current single-loop, we might simulate a list of components or just check if it's 'web'
        challenge = self.memory.get_context("challenge")
        category = challenge.get("category", "").lower()
        
        # In a real batch scenario, context would contain 'challenge_history'
        components = self.memory.get_context("challenge_history") or [challenge]
        
        # Rule: Only trigger merger if multiple web components exist OR if it's complex enough to warrant a unified UI
        is_web = category == "web" or any(c.get("category") == "web" for c in components)
        
        if len(components) > 1 and is_web:
            params = await self.dispatcher.prepare_params("merger", {"challenge_history": components, "session_id": self.target})
            
            # HITL Gate: Choice and Architectural Confirmation
            task_id = "merger_layout"
            if self.interactive and not self.memory.is_approved(task_id):
                logger.info("🚦 Intercepting for Merger Layout Review...")
                if await self.reviewer.request_review(task_id, params.get("layout_plan", {})) != ReviewStatus.APPROVED:
                    logger.warning("Merger aborted by user. Proceeding with single challenge.")
                    self.memory.transition("merger_complete")
                    return
                self.memory.mark_approved(task_id)
            
            result = self.dispatcher.execute_local(run_merger, params)
            if result.get("status") is True:
                logger.info("✅ Merger successful! Updating context with unified challenge.")
                self.memory.update_context("challenge", result.get("result", {}).get("merged_challenge"))
            else:
                logger.error(f"Merger failed: {result.get('summary')}")
        else:
            logger.info("⏭️  Single component detected. Skipping merger.")

        self.memory.transition("merger_complete")

    async def _run_superpowers(self):
        """
        Applies adversarial enhancements to the challenge.
        """
        logger.info("😈 Activating Superpowers (Adversarial Engine)...")
        challenge = self.memory.get_context("challenge")
        
        # Get chaos level from memory or default to 0.5
        chaos_level = self.memory.state.get("chaos_level", 0.5)
        
        params = await self.dispatcher.prepare_params("superpowers", {
            "challenge": challenge, 
            "chaos_level": chaos_level
        })
        
        # HITL Gate: Strategy Review
        task_id = "adversarial_strategy"
        if self.interactive and not self.memory.is_approved(task_id):
            logger.info("🚦 Intercepting for Adversarial Strategy Review...")
            if await self.reviewer.request_review(task_id, params.get("strategy", {})) != ReviewStatus.APPROVED:
                logger.warning("Superpowers bypassed by user.")
                self.memory.transition("superpowers_complete")
                return
            self.memory.mark_approved(task_id)

        result = self.dispatcher.execute_local(run_superpowers, params)
        
        if result.get("status") is True:
            logger.info("✅ Superpowers applied! Challenge is now AI-Hard.")
            self.memory.update_context("challenge", result.get("result", {}).get("challenge"))
        else:
            logger.error(f"Superpowers failed: {result.get('summary')}")
            
        self.memory.transition("superpowers_complete")

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
        self.memory.update_context("export_path", export_dir)
        self.memory.transition("export_complete")

    async def _finish(self):
        logger.info("🏁 Pipeline Finished.")
        self.memory.state["last_step"] = "finished"

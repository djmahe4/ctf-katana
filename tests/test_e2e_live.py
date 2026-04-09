import pytest
import asyncio
import httpx
import os
import shutil
from unittest.mock import MagicMock, AsyncMock, patch
from skills.purple_loop_orchestrator.conductor import PipelineConductor
from server.utils.pipeline_memory import PipelineMemory
from server.utils.review_manager import ReviewManager, ReviewStatus

@pytest.mark.asyncio
async def test_e2e_adversarial_pipeline():
    """
    E2E Test: Simulates a full run from research to export.
    Uses mocks to ensure the pipeline logic is correct and fast.
    """
    workspace = "."
    target = "CVE-2024-ADVERSARIAL-TEST"
    state_file = "data/test_pipeline_state.json"
    
    # 1. Setup Environment
    memory = PipelineMemory(workspace_root=workspace, state_file=state_file)
    memory.state["context"] = {} 
    memory.state["last_step"] = "idle"
    memory.save_local()
    
    reviewer = ReviewManager(workspace_root=workspace)
    reviewer.request_review = AsyncMock(return_value=ReviewStatus.APPROVED)
    
    # Mock KnowledgeRegistry to avoid ChromaDB dependency issues in E2E
    registry = MagicMock()
    registry.query = AsyncMock(return_value={
        "local": {"category": "web", "vuln_id": target},
        "rag": [],
        "purple_loop": {"finding": {"id": target}, "snippets": []}
    })

    conductor = PipelineConductor(
        target=target,
        memory=memory,
        reviewer=reviewer,
        knowledge_registry=registry,
        workspace_root=workspace,
        interactive=False
    )

    # 2. Patch Dispatcher and Skill Execution for deterministic/fast run
    # (Even if Ollama is running, we prefer mocks for E2E logic verification)
    with patch.object(conductor.dispatcher, 'prepare_params', new_callable=AsyncMock) as mock_prep:
        with patch.object(conductor.dispatcher, 'validate_output', new_callable=AsyncMock) as mock_val:
            mock_val.return_value = True
            
            async def mock_prepare(skill, context):
                if skill == "scaffolding":
                    return {"draft": {"files": [{"name": "app.py", "content": "print('hello')"}]}, "status": "success"}
                if skill == "flagger":
                    return {"flag": "katana{test}", "handler": "reverse", "target_file": "app.py", "metadata": {"target_file": "app.py"}}
                if skill == "merger":
                    # Simulate multiple components for merger test if needed, but here we just pass
                    return {"selected_components": [], "layout_plan": {"services": []}}
                if skill == "superpowers":
                    return {"challenge": context.get("challenge"), "strategy": {"injections": []}}
                return {}
            
            mock_prep.side_effect = mock_prepare
            
            # 3. Run the full pipeline
            try:
                await conductor.run_pipeline()
                
                # 4. Verification
                assert memory.state["last_step"] == "finished"
                
                export_path = memory.get_context("export_path")
                assert export_path is not None
                assert os.path.exists(export_path)
                assert os.path.exists(os.path.join(export_path, "challenge_manifest.json"))
                
                print(f"\n[E2E] Success! Artifacts exported to {export_path}")
                
            finally:
                # Cleanup test data
                if os.path.exists(os.path.join(workspace, state_file)):
                    os.remove(os.path.join(workspace, state_file))

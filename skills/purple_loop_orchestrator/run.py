import os
import sys
import logging
import asyncio
import argparse
from pathlib import Path
from typing import Dict, Any

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from server.utils.knowledge_registry import KnowledgeRegistry
from server.utils.pipeline_memory import PipelineMemory
from server.utils.review_manager import ReviewManager
from skills.purple_loop_orchestrator.conductor import PipelineConductor

logger = logging.getLogger(__name__)

async def run(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Stateful execution of the Purple Loop.
    """
    target = params.get('target')
    reset = params.get('reset', False)
    interactive = params.get('interactive', True)
    
    # 1. Initialize Memory & State
    # We use a subfolder for each target to avoid state collisions
    target_slug = "".join(c if c.isalnum() else "_" for c in target)
    state_file = f"data/sessions/{target_slug}/state.json"
    
    if reset and os.path.exists(os.path.join(PROJECT_ROOT, state_file)):
        logger.info(f"♻️ Resetting session for {target}...")
        os.remove(os.path.join(PROJECT_ROOT, state_file))
        
    memory = PipelineMemory(workspace_root=str(PROJECT_ROOT), state_file=state_file)
    reviewer = ReviewManager(workspace_root=str(PROJECT_ROOT))
    registry = KnowledgeRegistry(workspace_root=PROJECT_ROOT)
    
    # 2. Instantiate and Run Conductor
    conductor = PipelineConductor(
        target=target,
        memory=memory,
        reviewer=reviewer,
        knowledge_registry=registry,
        workspace_root=str(PROJECT_ROOT),
        interactive=interactive
    )
    
    try:
        await conductor.run_pipeline()
        return {
            "status": "success",
            "session_id": memory.state["session_id"],
            "last_step": memory.state["last_step"],
            "export_path": memory.get_context("export_path")
        }
    except Exception as e:
        logger.error(f"Execution failed: {e}")
        return {"status": "error", "message": str(e)}

async def main():
    parser = argparse.ArgumentParser(description="Purple Engine - Stateful Orchestrator")
    parser.add_argument("--target", required=True, help="Target CVE-ID or URL")
    parser.add_argument("--reset", action="store_true", help="Start a fresh session for this target")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    
    params = {
        'target': args.target,
        'reset': args.reset
    }
    
    result = await run(params)
    print("\n" + "="*50)
    print("PURPLE LOOP RESULT:")
    print(import_json_dumps(result))
    print("="*50)

def import_json_dumps(data):
    import json
    return json.dumps(data, indent=2)

if __name__ == "__main__":
    asyncio.run(main())

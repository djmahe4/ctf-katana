import time
import os
import json
import asyncio
from typing import Any, Dict, Optional, Callable
from enum import Enum

class ReviewStatus(Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    CHANGES_REQUESTED = "changes_requested"

class ReviewManager:
    """
    Handles Human-In-The-Loop (HITL) gates.
    Supports filesystem-based signals for headless/wrapped execution.
    """
    
    def __init__(self, workspace_root: str):
        self.workspace_root = workspace_root
        self.review_dir = os.path.join(workspace_root, "data", "reviews")
        self._ensure_dirs()

    def _ensure_dirs(self):
        os.makedirs(self.review_dir, exist_ok=True)

    async def request_review(self, 
                       task_id: str, 
                       content: Any, 
                       review_type: str = "general",
                       blocking: bool = True,
                       timeout: int = 3600) -> ReviewStatus:
        """
        Creates a review request on the filesystem.
        """
        review_path = os.path.join(self.review_dir, f"{task_id}.json")
        signal_path = os.path.join(self.review_dir, f"{task_id}.signal")
        
        # Write task content for review (JSON)
        with open(review_path, "w") as f:
            json.dump({
                "task_id": task_id,
                "type": review_type,
                "content": content,
                "timestamp": time.time(),
                "status": "pending"
            }, f, indent=4)
        
        # Create initial signal file
        with open(signal_path, "w") as f:
            f.write("PENDING")
            
        print(f"\n" + "="*60)
        print(f"🚦 [REVIEW REQUIRED] Task: {task_id} ({review_type})")
        print(f"📄 Signal file: {signal_path}")
        
        # Enhanced Terminal Visibility for Drafts and Scaffolding
        if isinstance(content, dict):
            # Case 1: Agentic Draft (Thinking phase)
            if review_type == "agentic_draft":
                explanation = content.get("explanation", "No explanation provided.")
                files = content.get("files", [])
                print(f"\n🧠 AGENTIC SUMMARY:\n{explanation}")
                if files:
                    print(f"\n📁 DRAFTED FILES ({len(files)}):")
                    for file in files:
                        name = file.get("name", "unknown")
                        code = file.get("content", "")
                        self._print_file_snippet(name, code)
            
            # Case 2: Scaffolding (Manifestation phase)
            elif review_type == "scaffolding" or "challenge" in content:
                challenge = content.get("challenge", content)
                desc = challenge.get("description", "No description.")
                files = challenge.get("generated_files", [])
                print(f"\n🏛️  SCAFFOLDING RESULT:\n{desc}")
                if files:
                    print(f"\n📁 GENERATED FILES ({len(files)}):")
                    for file in files:
                        path = file.get("path") or file.get("name", "unknown")
                        code = file.get("content", "")
                        self._print_file_snippet(path, code)
        
        print("="*60 + "\n")
        
        if blocking:
            return await self._wait_for_signal(task_id, signal_path, timeout)
        
        return ReviewStatus.PENDING

    def _print_file_snippet(self, name: str, code: str):
        """Helper to print a pretty snippet of code."""
        lines = code.split("\n")
        snippet = "\n".join(lines[:10])
        print(f"\n--- [ {name} ] ---")
        print(snippet)
        if len(lines) > 10:
            print(f"... ({len(lines)-10} more lines)")

    async def _wait_for_signal(self, task_id: str, signal_path: str, timeout: int) -> ReviewStatus:
        """Polls the signal file for user/agent intervention."""
        start_time = time.time()
        print("Waiting for signal file update (APPROVED/REJECTED/instruction)...")
        
        while time.time() - start_time < timeout:
            if os.path.exists(signal_path):
                with open(signal_path, "r") as f:
                    signal = f.read().strip().upper()
                    
                if signal == "APPROVED" or signal == "A":
                    return ReviewStatus.APPROVED
                elif signal == "REJECTED" or signal == "R":
                    return ReviewStatus.REJECTED
                elif signal.startswith("CHANGES:") or signal.startswith("C:"):
                    # Extract feedback after colon
                    return ReviewStatus.CHANGES_REQUESTED
            
            await asyncio.sleep(2) # Poll interval
            
        print(f"Review timeout for {task_id}")
        return ReviewStatus.PENDING

    def get_feedback_from_signal(self, task_id: str) -> Optional[str]:
        signal_path = os.path.join(self.review_dir, f"{task_id}.signal")
        if os.path.exists(signal_path):
            with open(signal_path, "r") as f:
                content = f.read().strip()
                if ":" in content:
                    return content.split(":", 1)[1].strip()
        return None

    def poll_status(self, task_id: str) -> ReviewStatus:
        """Used by async conductors or TUIs to check for approval."""
        return self.reviews.get(task_id, {}).get("status", ReviewStatus.PENDING)

    def get_feedback(self, task_id: str) -> Optional[str]:
        return self.reviews.get(task_id, {}).get("feedback")

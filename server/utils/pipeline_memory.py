import json
import os
import hashlib
from typing import Any, Dict, Optional
from datetime import datetime

class PipelineMemory:
    """
    Manages hybrid state for the CTF-Katana pipeline.
    Syncs between local JSON storage and @free-llms persistent memory.
    """
    
    def __init__(self, workspace_root: str, state_file: str = "data/pipeline_state.json"):
        self.workspace_root = workspace_root
        self.state_file = os.path.join(workspace_root, state_file)
        # Default state - logic_analysis and artifacts are critical context
        self.state: Dict[str, Any] = {
            "session_id": None, 
            "created_at": datetime.now().isoformat(),
            "last_step": "idle",
            "tasks": {},
            "reviews_approved": [],
            "context": {
                "snippets": [],
                "logic_analysis": {},
                "artifacts": []
            }
        }
        self._ensure_data_dir()
        self.load_local()
        
        # Stabilize session_id: Create only if missing to support resume
        if not self.state.get("session_id"):
            self.state["session_id"] = hashlib.sha256(str(datetime.now()).encode()).hexdigest()[:12]
            self.save_local()

    def _ensure_data_dir(self):
        os.makedirs(os.path.dirname(self.state_file), exist_ok=True)

    def load_local(self):
        """Loads state with basic error recovery."""
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, "r") as f:
                    data = json.load(f)
                    # Merge logic: preserve critical keys
                    self.state.update(data)
            except (json.JSONDecodeError, IOError) as e:
                print(f"Warning: Could not load state file {self.state_file}: {e}")
                # Optional: Handle backup recovery here if needed

    def save_local(self):
        """Atomic write to prevent corruption during crashes or multi-agent access."""
        temp_file = self.state_file + ".tmp"
        try:
            with open(temp_file, "w") as f:
                json.dump(self.state, f, indent=4)
            # Atomic rename (posix-compliant, Windows handles replace)
            if os.path.exists(self.state_file):
                os.remove(self.state_file)
            os.rename(temp_file, self.state_file)
        except Exception as e:
            print(f"Error saving state: {e}")
            if os.path.exists(temp_file):
                os.remove(temp_file)

    def update_context(self, key: str, value: Any):
        """Update a specific context piece and mark for sync."""
        if key not in self.state["context"]:
            print(f"Adding new context key: {key}")
        
        self.state["context"][key] = value
        self.state["updated_at"] = datetime.now().isoformat()
        self.save_local()

    def load_state(self):
        """Alias for load_local to match Conductor expectations."""
        self.load_local()

    def save_state(self):
        """Alias for save_local to match Conductor expectations."""
        self.save_local()

    def transition(self, step_name: str):
        """Updates the current step and persists immediately."""
        old_step = self.state["last_step"]
        self.state["last_step"] = step_name
        self.save_local()
        print(f"State Transition: {old_step} -> {step_name}")

    def get_context(self, key: str) -> Optional[Any]:
        return self.state["context"].get(key)

    def is_approved(self, task_id: str) -> bool:
        """Check if a specific task/review has already been approved in this session."""
        return task_id in self.state.get("reviews_approved", [])

    def mark_approved(self, task_id: str):
        """Record an approval in the persistent state."""
        if "reviews_approved" not in self.state:
            self.state["reviews_approved"] = []
        if task_id not in self.state["reviews_approved"]:
            self.state["reviews_approved"].append(task_id)
            self.save_local()
            print(f"Approval Recorded: {task_id}")

    def export_for_memory_service(self) -> str:
        """Serializes the critical 'brain' state for @free-llms storage."""
        return json.dumps({
            "session_id": self.state["session_id"],
            "last_step": self.state["last_step"],
            "logic_analysis": self.state["context"].get("logic_analysis", {}),
            "artifact_count": len(self.state["context"].get("artifacts", []))
        })

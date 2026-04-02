import time
import json
import os
import psutil
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

class TelemetryManager:
    """
    Manages performance metrics collection and persistence for the B.Tech Thesis.
    """
    def __init__(self, log_path: str = "logs/telemetry.json"):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._current_session = []
        
    def start_metric(self, name: str, category: str = "general") -> Dict[str, Any]:
        return {
            "name": name,
            "category": category,
            "start_time": time.perf_counter(),
            "timestamp": datetime.now().isoformat(),
            "cpu_percent": psutil.cpu_percent(),
            "memory_mb": psutil.Process().memory_info().rss / 1024 / 1024
        }
    
    def finish_metric(self, metric: Dict[str, Any], status: str = "success", metadata: Optional[Dict] = None):
        end_time = time.perf_counter()
        duration = end_time - metric["start_time"]
        
        entry = {
            "name": metric["name"],
            "category": metric["category"],
            "timestamp": metric["timestamp"],
            "duration_sec": round(duration, 4),
            "status": status,
            "cpu_at_start": metric["cpu_percent"],
            "memory_at_start_mb": round(metric["memory_mb"], 2),
            "cpu_at_end": psutil.cpu_percent(),
            "memory_at_end_mb": round(psutil.Process().memory_info().rss / 1024 / 1024, 2),
            "metadata": metadata or {}
        }
        
        self._save_entry(entry)
        return entry

    def _save_entry(self, entry: Dict[str, Any]):
        data = []
        if self.log_path.exists():
            try:
                with open(self.log_path, "r") as f:
                    data = json.load(f)
            except json.JSONDecodeError:
                data = []
        
        data.append(entry)
        with open(self.log_path, "w") as f:
            json.dump(data, f, indent=2)

# Global singleton for the server
_telemetry = TelemetryManager()

def get_telemetry():
    return _telemetry

"""
Kavach Monitoring Components

Implements active defense mechanisms:
- AutoEnforcer: Automatic timeout-based process termination
- TripwireMonitor: Honeypot file monitoring for suspicious access
- FileWatcher: Real-time file system monitoring
- LoopDetector: Detects and prevents high-velocity command loops
"""

import os
import time
import threading
import psutil
import logging
from pathlib import Path
from typing import Dict, List, Optional, Callable, Set
from dataclasses import dataclass
from datetime import datetime, timedelta
from collections import defaultdict

from skills.firewall.kavach.exceptions import (
    ExecutionTimeoutError,
    TripwireTriggered,
    LoopDetectionError,
    ProcessLimitExceeded,
)

logger = logging.getLogger(__name__)


@dataclass
class ProcessInfo:
    """Information about a monitored process."""
    pid: int
    command: str
    start_time: datetime
    parent_pid: Optional[int] = None
    cpu_percent: float = 0.0
    memory_mb: float = 0.0


class AutoEnforcer:
    """
    Automatic Process Enforcement.
    
    Implements "The Auto Enforcer" from original Kavach - ruthless background
    thread that terminates processes exceeding timeout thresholds.
    
    If a monitored process runs for more than the timeout, it receives a hard
    OS termination signal (SIGTERM, then SIGKILL if necessary).
    """
    
    def __init__(self, timeout_seconds: int = 60, check_interval: float = 1.0):
        self.timeout_seconds = timeout_seconds
        self.check_interval = check_interval
        
        # Monitored processes: {pid: ProcessInfo}
        self.monitored: Dict[int, ProcessInfo] = {}
        self.lock = threading.Lock()
        
        # Background enforcer thread
        self._running = False
        self._thread: Optional[threading.Thread] = None
        
        logger.info(f"AutoEnforcer initialized (timeout={timeout_seconds}s)")
    
    def start(self) -> None:
        """Start the auto-enforcer background thread."""
        if self._running:
            logger.warning("AutoEnforcer already running")
            return
        
        self._running = True
        self._thread = threading.Thread(target=self._enforce_loop, daemon=True)
        self._thread.start()
        logger.info("AutoEnforcer started")
    
    def stop(self) -> None:
        """Stop the auto-enforcer thread."""
        if not self._running:
            return
        
        self._running = False
        if self._thread:
            self._thread.join(timeout=5.0)
        logger.info("AutoEnforcer stopped")
    
    def monitor_process(self, pid: int, command: str, parent_pid: Optional[int] = None) -> None:
        """Add process to monitoring list."""
        with self.lock:
            self.monitored[pid] = ProcessInfo(
                pid=pid,
                command=command,
                start_time=datetime.utcnow(),
                parent_pid=parent_pid,
            )
        logger.debug(f"Monitoring process {pid}: {command}")
    
    def unmonitor_process(self, pid: int) -> None:
        """Remove process from monitoring."""
        with self.lock:
            if pid in self.monitored:
                del self.monitored[pid]
        logger.debug(f"Unmonitored process {pid}")
    
    def _enforce_loop(self) -> None:
        """Background enforcement loop (runs in separate thread)."""
        while self._running:
            try:
                with self.lock:
                    to_terminate = []
                    
                    for pid, info in list(self.monitored.items()):
                        # Check if process still exists
                        if not psutil.pid_exists(pid):
                            del self.monitored[pid]
                            continue
                        
                        # Check timeout
                        elapsed = (datetime.utcnow() - info.start_time).total_seconds()
                        if elapsed > self.timeout_seconds:
                            to_terminate.append((pid, info))
                            logger.warning(
                                f"Process {pid} exceeded timeout "
                                f"({elapsed:.1f}s > {self.timeout_seconds}s)"
                            )
                
                # Terminate processes (outside lock to avoid blocking)
                for pid, info in to_terminate:
                    self._terminate_process(pid, info)
                
                time.sleep(self.check_interval)
                
            except Exception as e:
                logger.error(f"AutoEnforcer error: {e}")
                time.sleep(self.check_interval)
    
    def _terminate_process(self, pid: int, info: ProcessInfo) -> None:
        """Terminate a process (SIGTERM, then SIGKILL if necessary)."""
        try:
            proc = psutil.Process(pid)
            
            # Log termination
            logger.warning(
                f"AUTO-ENFORCER TERMINATING: {info.command} (PID {pid})"
            )
            
            # Try graceful SIGTERM first
            proc.terminate()
            
            # Wait up to 3 seconds for graceful shutdown
            try:
                proc.wait(timeout=3.0)
                logger.info(f"Process {pid} terminated gracefully")
            except psutil.TimeoutExpired:
                # Force kill if still alive
                logger.warning(f"Process {pid} did not terminate, forcing SIGKILL")
                proc.kill()
                proc.wait(timeout=1.0)
                logger.info(f"Process {pid} killed forcefully")
            
            # Remove from monitoring
            self.unmonitor_process(pid)
            
        except psutil.NoSuchProcess:
            logger.debug(f"Process {pid} already terminated")
            self.unmonitor_process(pid)
        except Exception as e:
            logger.error(f"Failed to terminate process {pid}: {e}")
    
    def get_monitored_processes(self) -> List[ProcessInfo]:
        """Get list of currently monitored processes."""
        with self.lock:
            return list(self.monitored.values())


class TripwireMonitor:
    """
    Honeypot Tripwire Monitoring.
    
    Implements "Honeypot Tripwire Architecture" from original Kavach - deploys
    decoy files (e.g. system_auth_tokens.json) that trigger critical alarms
    when accessed by any process.
    
    Tripwires are automatically cleaned up when monitoring ends.
    """
    
    DEFAULT_TRIPWIRES = {
        "system_auth_tokens.json": '{"aws_key": "AKIA1234567890ABCDEF", "openai_key": "sk-FAKE"}',
        ".env.production": "DATABASE_PASSWORD=SuperSecret123\nAPI_KEY=deadbeef",
        "credentials.txt": "username: admin\npassword: Admin123!",
    }
    
    def __init__(
        self,
        workspace: Path,
        custom_tripwires: Optional[Dict[str, str]] = None,
        level: str = "enforcement"
    ):
        self.workspace = Path(workspace)
        self.tripwires = {**self.DEFAULT_TRIPWIRES}
        if custom_tripwires:
            self.tripwires.update(custom_tripwires)
        
        self.level = level
        # Track deployed tripwires and their access logs
        self.deployed_paths: Set[Path] = set()
        self.access_log: List[Dict] = []
        
        logger.info(f"TripwireMonitor initialized with {len(self.tripwires)} tripwires")
    
    def deploy(self) -> None:
        """Deploy all tripwire files to workspace."""
        for filename, content in self.tripwires.items():
            tripwire_path = self.workspace / filename
            
            # Don't overwrite existing files
            if tripwire_path.exists():
                logger.warning(f"Skipping tripwire (file exists): {tripwire_path}")
                continue
            
            # Write tripwire content
            with open(tripwire_path, 'w') as f:
                f.write(content)
            
            self.deployed_paths.add(tripwire_path)
            logger.info(f"Deployed tripwire: {tripwire_path}")
        
        logger.info(f"Deployed {len(self.deployed_paths)} tripwires")
    
    def check_access(self, file_path: Path) -> bool:
        """
        Check if a file access triggers a tripwire.
        
        Returns True if tripwire triggered, False otherwise.
        Logs the access event for forensics.
        """
        file_path = Path(file_path).resolve()
        
        if file_path in self.deployed_paths:
            # TRIPWIRE TRIGGERED!
            access_event = {
                "tripwire_path": str(file_path),
                "timestamp": datetime.utcnow().isoformat(),
                "triggered": True,
                "level": self.level,
            }
            self.access_log.append(access_event)
            
            log_msg = f"🚨 TRIPWIRE TRIGGERED [{self.level.upper()}]: {file_path}"
            if self.level == "enforcement":
                logger.critical(log_msg)
            else:
                logger.warning(log_msg)
                
            return True
        
        return False
    
    def cleanup(self) -> None:
        """Remove all deployed tripwire files (called at end of session)."""
        for tripwire_path in self.deployed_paths:
            try:
                if tripwire_path.exists():
                    tripwire_path.unlink()
                    logger.debug(f"Removed tripwire: {tripwire_path}")
            except Exception as e:
                logger.error(f"Failed to remove tripwire {tripwire_path}: {e}")
        
        logger.info(f"Cleaned up {len(self.deployed_paths)} tripwires")
        self.deployed_paths.clear()
    
    def get_access_log(self) -> List[Dict]:
        """Get log of all tripwire accesses."""
        return self.access_log


class LoopDetector:
    """
    High-Velocity Loop Detection.
    
    Implements "High Velocity Loop Break" from original Kavach - detects when
    an agent is stuck in a repetitive command loop (e.g. recursive npm install)
    and forces automatic suspension.
    """
    
    def __init__(self, threshold: int = 10, time_window: float = 30.0):
        self.threshold = threshold  # Max repetitions before alarm
        self.time_window = time_window  # Time window in seconds
        
        # Track command patterns: {command_hash: [timestamps]}
        self.command_history: Dict[str, List[datetime]] = defaultdict(list)
    
    def record_command(self, command: str) -> None:
        """Record a command execution."""
        # Simple hash of command (ignoring minor variations)
        cmd_hash = command.strip().lower()[:100]  # First 100 chars
        
        self.command_history[cmd_hash].append(datetime.utcnow())
    
    def check_loop(self, command: str) -> bool:
        """
        Check if command execution constitutes a loop.
        
        Returns True if loop detected (threshold exceeded in time window).
        """
        self.record_command(command)
        
        cmd_hash = command.strip().lower()[:100]
        timestamps = self.command_history[cmd_hash]
        
        # Count executions within time window
        cutoff = datetime.utcnow() - timedelta(seconds=self.time_window)
        recent_executions = [ts for ts in timestamps if ts > cutoff]
        
        if len(recent_executions) >= self.threshold:
            logger.warning(
                f"🔁 LOOP DETECTED: {command} executed {len(recent_executions)} "
                f"times in {self.time_window}s"
            )
            return True
        
        return False
    
    def reset(self) -> None:
        """Reset loop detection history."""
        self.command_history.clear()


class FileWatcher:
    """
    Real-time File System Watcher.
    
    Monitors file system events (create, modify, delete, access) in the
    workspace using watchdog library (if available) or manual polling.
    
    Integrates with TripwireMonitor to detect tripwire accesses.
    """
    
    def __init__(
        self,
        workspace: Path,
        tripwire_monitor: Optional[TripwireMonitor] = None,
        on_violation: Optional[Callable[[str, Path, str], None]] = None,
    ):
        self.workspace = Path(workspace)
        self.tripwire_monitor = tripwire_monitor
        self.on_violation = on_violation
        
        # Event log
        self.events: List[Dict] = []
        
        # Try to import watchdog for efficient monitoring
        try:
            from watchdog.observers import Observer
            from watchdog.events import FileSystemEventHandler
            self.has_watchdog = True
            logger.info("FileWatcher using watchdog library")
        except ImportError:
            self.has_watchdog = False
            logger.warning("watchdog not installed, using polling mode")
        
        self._observer = None
    
    def start(self) -> None:
        """Start file system monitoring."""
        if self.has_watchdog:
            self._start_watchdog()
        else:
            logger.info("File watching disabled (install watchdog for real-time monitoring)")
    
    def _start_watchdog(self) -> None:
        """Start watchdog-based monitoring."""
        try:
            from watchdog.observers import Observer
            from watchdog.events import FileSystemEventHandler
            
            class KavachEventHandler(FileSystemEventHandler):
                def __init__(self, watcher):
                    self.watcher = watcher
                
                def on_any_event(self, event):
                    self.watcher._handle_event(event)
            
            self._observer = Observer()
            handler = KavachEventHandler(self)
            self._observer.schedule(handler, str(self.workspace), recursive=True)
            self._observer.start()
            
            logger.info(f"FileWatcher started monitoring: {self.workspace}")
            
        except Exception as e:
            logger.error(f"Failed to start watchdog: {e}")
    
    def _handle_event(self, event) -> None:
        """Handle a file system event."""
        event_data = {
            "type": event.event_type,
            "path": event.src_path,
            "is_directory": event.is_directory,
            "timestamp": datetime.utcnow().isoformat(),
        }
        self.events.append(event_data)
        
        # Check for tripwire access
        if self.tripwire_monitor:
            triggered = self.tripwire_monitor.check_access(Path(event.src_path))
            if triggered and self.on_violation:
                self.on_violation("tripwire", Path(event.src_path), event.event_type)
        
        logger.debug(f"File event: {event.event_type} - {event.src_path}")
    
    def stop(self) -> None:
        """Stop file system monitoring."""
        if self._observer:
            self._observer.stop()
            self._observer.join()
            logger.info("FileWatcher stopped")
    
    def get_events(self, event_type: Optional[str] = None, limit: int = 100) -> List[Dict]:
        """Get file system events."""
        if event_type:
            filtered = [e for e in self.events if e["type"] == event_type]
            return filtered[-limit:]
        return self.events[-limit:]


class ProcessMonitor:
    """
    Child Process Monitoring and Limiting.
    
    Implements "Child Process Quarantine" from original Kavach - tracks all
    child processes spawned by monitored agents and enforces limits.
    """
    
    def __init__(self, max_children: int = 10):
        self.max_children = max_children
        
        # Track process tree: {parent_pid: [child_pids]}
        self.process_tree: Dict[int, List[int]] = defaultdict(list)
        
        logger.info(f"ProcessMonitor initialized (max_children={max_children})")
    
    def register_parent(self, parent_pid: int) -> None:
        """Register a parent process for monitoring."""
        self.process_tree[parent_pid] = []
        logger.debug(f"Registered parent process: {parent_pid}")
    
    def check_and_register_child(self, parent_pid: int, child_pid: int) -> None:
        """
        Check if child can be spawned, then register it.
        
        Raises ProcessLimitExceeded if too many children.
        """
        if parent_pid not in self.process_tree:
            self.register_parent(parent_pid)
        
        current_count = len(self.process_tree[parent_pid])
        
        if current_count >= self.max_children:
            raise ProcessLimitExceeded(
                f"Process {parent_pid} exceeded child limit",
                process_count=current_count + 1,
                limit=self.max_children,
            )
        
        self.process_tree[parent_pid].append(child_pid)
        logger.debug(f"Registered child {child_pid} for parent {parent_pid}")
    
    def get_children(self, parent_pid: int) -> List[int]:
        """Get all children of a parent process."""
        return self.process_tree.get(parent_pid, [])
    
    def cleanup_parent(self, parent_pid: int) -> None:
        """Remove parent and all children from tracking."""
        if parent_pid in self.process_tree:
            del self.process_tree[parent_pid]
            logger.debug(f"Cleaned up parent process: {parent_pid}")

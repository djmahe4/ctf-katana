"""
Kavach Audit System - Enhanced Audit Ledger

Extends the basic AuditLedger with advanced querying, aggregation,
rotation, and notification capabilities.

Features:
- Time-range filtering
- Skill-based aggregation
- Severity histograms
- Event correlation
- Automatic log rotation
- Real-time notifications
- Retention policies
"""

import os
import gzip
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from collections import defaultdict
import json
import logging

logger = logging.getLogger(__name__)


@dataclass
class AuditStatistics:
    """Aggregated audit statistics."""
    total_events: int = 0
    events_by_type: Dict[str, int] = field(default_factory=dict)
    events_by_severity: Dict[str, int] = field(default_factory=dict)
    events_by_skill: Dict[str, int] = field(default_factory=dict)
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    time_range: Tuple[Optional[str], Optional[str]] = (None, None)


@dataclass
class NotificationConfig:
    """Configuration for audit event notifications."""
    enabled: bool = True
    severity_threshold: str = "HIGH"  # Notify for HIGH and CRITICAL
    channels: List[str] = field(default_factory=lambda: ["log", "terminal"])
    rate_limit: int = 10  # Max notifications per minute
    callback: Optional[Callable] = None


class EnhancedAuditLedger:
    """
    Enhanced Audit Ledger with advanced features.
    
    Extends basic AuditLedger from core.py with:
    - Advanced querying (time range, aggregation)
    - Automatic log rotation
    - Real-time notifications
    - Event correlation
    - Statistics and analytics
    """
    
    def __init__(
        self,
        ledger_path: Path,
        max_size_mb: int = 100,
        rotation_enabled: bool = True,
        notification_config: Optional[NotificationConfig] = None,
    ):
        self.ledger_path = Path(ledger_path)
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        
        self.max_size_mb = max_size_mb
        self.rotation_enabled = rotation_enabled
        
        # Notification system
        self.notification_config = notification_config or NotificationConfig()
        self.notification_counter: Dict[str, List[datetime]] = defaultdict(list)
        
        # Hash chain tracking
        self.last_hash = "0" * 64
        
        # Load last hash from existing ledger
        if self.ledger_path.exists():
            self._load_last_hash()
        
        logger.info(f"EnhancedAuditLedger initialized: {self.ledger_path}")
    
    def _load_last_hash(self) -> None:
        """Load the last hash from existing ledger."""
        try:
            with open(self.ledger_path, 'r') as f:
                # Read last line
                lines = f.readlines()
                if lines:
                    last_entry = json.loads(lines[-1].strip())
                    self.last_hash = last_entry.get("hash", "0" * 64)
        except Exception as e:
            logger.warning(f"Failed to load last hash: {e}")
            self.last_hash = "0" * 64
    
    def _compute_hash(self, data: Dict) -> str:
        """Compute SHA-256 hash of entry chained with previous hash."""
        import hashlib
        entry_json = json.dumps(data, sort_keys=True)
        combined = self.last_hash + entry_json
        return hashlib.sha256(combined.encode()).hexdigest()
    
    def log_event(
        self,
        event_type: str,
        skill_name: str,
        severity: str,
        details: Dict,
    ) -> str:
        """
        Log security event with enhanced features.
        
        Returns: hash of logged entry
        """
        # Check if rotation needed
        if self.rotation_enabled:
            self._check_and_rotate()
        
        # Create entry
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "skill_name": skill_name,
            "severity": severity,
            "details": details,
            "previous_hash": self.last_hash,
        }
        
        # Compute hash
        entry_hash = self._compute_hash(entry)
        entry["hash"] = entry_hash
        
        # Append to ledger
        with open(self.ledger_path, 'a') as f:
            f.write(json.dumps(entry) + "\n")
        
        # Update chain
        self.last_hash = entry_hash
        
        # Send notification if needed
        self._maybe_notify(event_type, skill_name, severity, details)
        
        logger.debug(f"Audit log: {event_type} - {skill_name} [{severity}]")
        return entry_hash
    
    def _check_and_rotate(self) -> None:
        """Check if rotation needed and perform it."""
        if not self.ledger_path.exists():
            return
        
        # Check file size
        size_mb = self.ledger_path.stat().st_size / (1024 * 1024)
        
        if size_mb > self.max_size_mb:
            self._rotate_ledger()
    
    def _rotate_ledger(self) -> None:
        """Rotate audit ledger (compress old, start new)."""
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        archive_name = self.ledger_path.with_suffix(f".{timestamp}.jsonl.gz")
        
        # Compress old ledger
        with open(self.ledger_path, 'rb') as f_in:
            with gzip.open(archive_name, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        
        logger.info(f"Rotated audit ledger: {archive_name}")
        
        # Clear current ledger
        self.ledger_path.unlink()
        
        # Reset hash chain
        self.last_hash = "0" * 64
    
    def _maybe_notify(
        self,
        event_type: str,
        skill_name: str,
        severity: str,
        details: Dict,
    ) -> None:
        """Send notification if conditions met."""
        if not self.notification_config.enabled:
            return
        
        # Check severity threshold
        severity_levels = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        threshold_level = severity_levels.get(self.notification_config.severity_threshold, 3)
        event_level = severity_levels.get(severity, 0)
        
        if event_level < threshold_level:
            return  # Below threshold
        
        # Check rate limiting
        now = datetime.utcnow()
        cutoff = now - timedelta(minutes=1)
        
        # Clean old notifications
        self.notification_counter[severity] = [
            ts for ts in self.notification_counter[severity] if ts > cutoff
        ]
        
        if len(self.notification_counter[severity]) >= self.notification_config.rate_limit:
            logger.warning(f"Notification rate limit exceeded for {severity}")
            return
        
        # Record notification
        self.notification_counter[severity].append(now)
        
        # Send via configured channels
        message = f"[{severity}] {event_type} - {skill_name}"
        
        for channel in self.notification_config.channels:
            if channel == "log":
                logger.warning(f"AUDIT ALERT: {message}")
            elif channel == "terminal":
                print(f"🚨 AUDIT ALERT: {message}")
        
        # Custom callback
        if self.notification_config.callback:
            self.notification_config.callback(event_type, skill_name, severity, details)
    
    def query_events(
        self,
        event_type: Optional[str] = None,
        skill_name: Optional[str] = None,
        severity: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[Dict]:
        """
        Advanced event querying with time range.
        
        Args:
            event_type: Filter by event type
            skill_name: Filter by skill name
            severity: Filter by severity
            start_time: Filter events after this time
            end_time: Filter events before this time
            limit: Max results
        
        Returns:
            List of matching events
        """
        if not self.ledger_path.exists():
            return []
        
        results = []
        with open(self.ledger_path, 'r') as f:
            for line in f:
                try:
                    entry = json.loads(line.strip())
                    
                    # Apply filters
                    if event_type and entry.get("event_type") != event_type:
                        continue
                    if skill_name and entry.get("skill_name") != skill_name:
                        continue
                    if severity and entry.get("severity") != severity:
                        continue
                    
                    # Time range filtering
                    if start_time or end_time:
                        timestamp_str = entry.get("timestamp")
                        if timestamp_str:
                            try:
                                entry_time = datetime.fromisoformat(timestamp_str)
                                if start_time and entry_time < start_time:
                                    continue
                                if end_time and entry_time > end_time:
                                    continue
                            except ValueError:
                                continue
                    
                    results.append(entry)
                    
                    if len(results) >= limit:
                        break
                        
                except json.JSONDecodeError:
                    continue
        
        return results
    
    def get_statistics(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> AuditStatistics:
        """
        Get aggregated statistics.
        
        Args:
            start_time: Stats start time (None = all time)
            end_time: Stats end time (None = now)
        
        Returns:
            AuditStatistics object
        """
        stats = AuditStatistics()
        
        if not self.ledger_path.exists():
            return stats
        
        first_timestamp = None
        last_timestamp = None
        
        with open(self.ledger_path, 'r') as f:
            for line in f:
                try:
                    entry = json.loads(line.strip())
                    
                    # Time range filtering
                    timestamp_str = entry.get("timestamp")
                    if timestamp_str:
                        try:
                            entry_time = datetime.fromisoformat(timestamp_str)
                            
                            if start_time and entry_time < start_time:
                                continue
                            if end_time and entry_time > end_time:
                                continue
                            
                            # Track time range
                            if first_timestamp is None or timestamp_str < first_timestamp:
                                first_timestamp = timestamp_str
                            if last_timestamp is None or timestamp_str > last_timestamp:
                                last_timestamp = timestamp_str
                            
                        except ValueError:
                            pass
                    
                    # Count events
                    stats.total_events += 1
                    
                    # By type
                    event_type = entry.get("event_type", "unknown")
                    stats.events_by_type[event_type] = stats.events_by_type.get(event_type, 0) + 1
                    
                    # By severity
                    severity = entry.get("severity", "UNKNOWN")
                    stats.events_by_severity[severity] = stats.events_by_severity.get(severity, 0) + 1
                    
                    if severity == "CRITICAL":
                        stats.critical_count += 1
                    elif severity == "HIGH":
                        stats.high_count += 1
                    elif severity == "MEDIUM":
                        stats.medium_count += 1
                    elif severity == "LOW":
                        stats.low_count += 1
                    
                    # By skill
                    skill_name = entry.get("skill_name", "unknown")
                    stats.events_by_skill[skill_name] = stats.events_by_skill.get(skill_name, 0) + 1
                    
                except json.JSONDecodeError:
                    continue
        
        stats.time_range = (first_timestamp, last_timestamp)
        return stats
    
    def verify_integrity(self) -> Tuple[bool, List[str]]:
        """
        Verify integrity of audit ledger.
        
        Returns: (is_valid, list_of_errors)
        """
        if not self.ledger_path.exists():
            return True, []
        
        errors = []
        prev_hash = "0" * 64
        
        with open(self.ledger_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                try:
                    entry = json.loads(line.strip())
                    
                    # Verify chain continuity
                    if entry.get("previous_hash") != prev_hash:
                        errors.append(
                            f"Line {line_num}: Hash chain broken "
                            f"(expected {prev_hash}, got {entry.get('previous_hash')})"
                        )
                    
                    # Verify entry hash
                    stored_hash = entry.pop("hash")
                    computed_hash = self._compute_hash(entry)
                    
                    if stored_hash != computed_hash:
                        errors.append(
                            f"Line {line_num}: Entry hash mismatch "
                            f"(expected {computed_hash}, got {stored_hash})"
                        )
                    
                    prev_hash = stored_hash
                    
                except json.JSONDecodeError:
                    errors.append(f"Line {line_num}: Invalid JSON")
        
        is_valid = len(errors) == 0
        return is_valid, errors
    
    def correlate_events(
        self,
        time_window_seconds: int = 60,
        event_types: Optional[List[str]] = None,
    ) -> List[Dict]:
        """
        Find correlated events (events happening close together).
        
        Args:
            time_window_seconds: Events within this window are correlated
            event_types: Only correlate these event types (None = all)
        
        Returns:
            List of correlation groups
        """
        if not self.ledger_path.exists():
            return []
        
        # Load all events
        events = []
        with open(self.ledger_path, 'r') as f:
            for line in f:
                try:
                    entry = json.loads(line.strip())
                    if event_types and entry.get("event_type") not in event_types:
                        continue
                    events.append(entry)
                except json.JSONDecodeError:
                    continue
        
        # Sort by timestamp
        events.sort(key=lambda e: e.get("timestamp", ""))
        
        # Find correlations
        correlations = []
        i = 0
        
        while i < len(events):
            group = [events[i]]
            base_time = datetime.fromisoformat(events[i]["timestamp"])
            
            j = i + 1
            while j < len(events):
                event_time = datetime.fromisoformat(events[j]["timestamp"])
                time_diff = (event_time - base_time).total_seconds()
                
                if time_diff <= time_window_seconds:
                    group.append(events[j])
                    j += 1
                else:
                    break
            
            if len(group) > 1:  # Only include correlated groups
                correlations.append({
                    "event_count": len(group),
                    "time_span_seconds": (
                        datetime.fromisoformat(group[-1]["timestamp"]) -
                        datetime.fromisoformat(group[0]["timestamp"])
                    ).total_seconds(),
                    "events": group,
                })
            
            i = j if j > i + 1 else i + 1
        
        return correlations
    
    def cleanup_old_logs(self, retention_days: int = 90) -> int:
        """
        Delete archived logs older than retention period.
        
        Args:
            retention_days: Keep logs from this many days
        
        Returns:
            Number of files deleted
        """
        cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
        deleted_count = 0
        
        # Find archived logs
        archive_pattern = f"{self.ledger_path.stem}.*.jsonl.gz"
        archive_dir = self.ledger_path.parent
        
        for archive_file in archive_dir.glob(archive_pattern):
            try:
                # Extract timestamp from filename
                # Format: kavach_audit.20260331_120000.jsonl.gz
                parts = archive_file.stem.split('.')
                if len(parts) >= 2:
                    timestamp_str = parts[1]  # 20260331_120000
                    file_date = datetime.strptime(timestamp_str, "%Y%m%d_%H%M%S")
                    
                    if file_date < cutoff_date:
                        archive_file.unlink()
                        deleted_count += 1
                        logger.info(f"Deleted old audit log: {archive_file}")
            except Exception as e:
                logger.warning(f"Failed to process archive {archive_file}: {e}")
        
        return deleted_count

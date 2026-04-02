"""
Kavach Core Components

Implements the main security primitives adapted from the original Kavach EDR:
- PhantomWorkspace: Isolated workspace with copy-on-write semantics
- SecurityPolicy: Rule engine for file/network/process restrictions
- PIISanitizer: Real-time PII detection and redaction
- AuditLedger: Cryptographic immutable audit log
- KavachWrapper: Main decorator for wrapping skill executions
"""

import os
import re
import json
import shutil
import hashlib
import tempfile
from pathlib import Path
from enum import Enum
from typing import Dict, List, Optional, Any, Callable, Set, Union
from dataclasses import dataclass, field, fields
from datetime import datetime
from contextlib import contextmanager
import logging

from .exceptions import (
    PhantomWorkspaceError,
    PIIDetectionError,
    FileAccessViolation,
)
from .monitor import TripwireMonitor, AutoEnforcer

logger = logging.getLogger(__name__)


class TripwireLevel(Enum):
    """
    Tripwire enforcement levels.
    
    ENFORCEMENT: Process is killed/interrupted upon tripwire trigger.
    AUDIT: Event is logged to AuditLedger, but process continues.
    """
    ENFORCEMENT = "enforcement"
    AUDIT = "audit"


@dataclass
class SecurityPolicy:
    """
    Security policy configuration for Kavach.
    
    Defines what operations are allowed/blocked for wrapped skill executions.
    """
    # File access control
    allowed_read_paths: List[str] = field(default_factory=lambda: ["*"])
    allowed_write_paths: List[str] = field(default_factory=lambda: ["*"])
    blocked_paths: List[str] = field(default_factory=list)
    
    # Network control
    allow_network: bool = True
    allowed_domains: List[str] = field(default_factory=lambda: ["*"])
    blocked_domains: List[str] = field(default_factory=list)
    
    # Process control
    max_child_processes: int = 10
    execution_timeout: int = 300  # seconds (auto-enforcer timeout)
    
    # PII protection
    sanitize_pii: bool = True
    pii_patterns: Dict[str, str] = field(default_factory=dict)
    
    # Tripwire Monitoring
    enable_tripwires: bool = True
    tripwire_level: TripwireLevel = TripwireLevel.ENFORCEMENT
    custom_tripwires: Optional[Dict[str, str]] = None
    tripwire_files: Any = field(default_factory=lambda: ["system_auth_tokens.json"])
    
    # Phantom workspace
    enable_phantom_workspace: bool = True
    phantom_dir_name: str = ".kavach_phantom"
    
    # Circuit breaker
    max_errors_before_shutdown: int = 5
    loop_detection_threshold: int = 10  # Same command repeated N times
    
    # Optional monitoring flags
    enable_file_watching: bool = False
    enable_process_monitoring: bool = True
    enable_audit_logging: bool = True
    
    @classmethod
    def from_yaml(cls, yaml_path: Path, profile: str = None) -> "SecurityPolicy":
        """Load security policy from YAML file."""
        import yaml
        with open(yaml_path, 'r') as f:
            data = yaml.safe_load(f)
        
        # Handle structured YAML with profiles
        if 'profiles' in data:
            # Get the profile to use
            if profile is None:
                profile = data.get('default_profile', 'standard')
            
            # Get the profile data
            profiles = data.get('profiles', {})
            if profile in profiles:
                profile_data = profiles[profile]
                # Filter to only valid fields
                valid_fields = {f.name for f in fields(cls)}
                filtered_data = {k: v for k, v in profile_data.items() if k in valid_fields}
                return cls(**filtered_data)
            else:
                logger.warning(f"Profile '{profile}' not found, using default standard")
                return cls.default_standard()
        else:
            # Direct policy data (legacy format) - filter unknown fields
            valid_fields = {f.name for f in fields(cls)}
            filtered_data = {k: v for k, v in data.items() if k in valid_fields}
            return cls(**filtered_data)
    
    @classmethod
    def default_strict(cls) -> "SecurityPolicy":
        """Create strict security policy (maximum protection)."""
        return cls(
            allowed_read_paths=["context/*", "skills/*", "configs/*"],
            allowed_write_paths=["context/outputs/*", "/tmp/*"],
            blocked_paths=[
                "~/.ssh/*",
                "~/.aws/*",
                "*.key",
                "*.pem",
                "*.env",
                ".git/config"
            ],
            allow_network=False,
            max_child_processes=3,
            execution_timeout=60,
            sanitize_pii=True,
            enable_tripwires=True,
            enable_phantom_workspace=True,
            max_errors_before_shutdown=3,
        )
    
    @classmethod
    def default_permissive(cls) -> "SecurityPolicy":
        """Create permissive policy (minimal restrictions)."""
        return cls(
            allowed_read_paths=["*"],
            allowed_write_paths=["*"],
            blocked_paths=[],
            allow_network=True,
            max_child_processes=10,
            execution_timeout=300,
            sanitize_pii=False,
            enable_tripwires=False,
            enable_phantom_workspace=False,
            max_errors_before_shutdown=10,
        )
    
    @classmethod
    def default_standard(cls) -> "SecurityPolicy":
        """Create standard security policy (balanced)."""
        return cls(
            allowed_read_paths=["*"],
            allowed_write_paths=["context/*", "skills/*/outputs/*", "/tmp/*", "~/.cache/purple-engine/*"],
            blocked_paths=["~/.ssh/*", "~/.aws/*", "*.key", "*.pem", ".env", ".git/config"],
            allow_network=True,
            allowed_domains=["*"],
            blocked_domains=["*.onion", "*.i2p"],
            max_child_processes=10,
            execution_timeout=300,
            sanitize_pii=True,
            enable_tripwires=True,
            enable_phantom_workspace=True,
            max_errors_before_shutdown=5,
        )


class PIISanitizer:
    """
    PII Detection and Sanitization Engine.
    
    Implements "Gag Order" from original Kavach - scans outputs for sensitive
    data (API keys, credit cards, emails, SSH keys) and redacts them.
    
    Uses entropy analysis + regex patterns for detection.
    """
    
    # Default PII patterns (can be extended via SecurityPolicy)
    # NOTE: Order matters - more specific patterns should come first
    DEFAULT_PATTERNS = {
        "openai_key": r"sk-[A-Za-z0-9]{20,}",  # OpenAI keys: sk- prefix + 20+ chars
        "aws_key": r"AKIA[0-9A-Z]{16}",
        "github_token": r"ghp_[A-Za-z0-9]{36}",
        "private_key": r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----",
        "jwt_token": r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
        "credit_card": r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",
        "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "api_key_generic": r"\b[A-Za-z0-9]{32,64}\b",  # Must be last - most generic
    }
    
    def __init__(self, custom_patterns: Optional[Dict[str, str]] = None):
        self.patterns = {**self.DEFAULT_PATTERNS}
        if custom_patterns:
            self.patterns.update(custom_patterns)
        
        # Compile regex patterns for performance
        self.compiled_patterns = {
            name: re.compile(pattern)
            for name, pattern in self.patterns.items()
        }
        
        # Dynamic environment-based secrets
        self.env_secrets: Dict[str, str] = self._load_env_secrets()
        
        self.detections: List[Dict[str, Any]] = []

    def _load_env_secrets(self) -> Dict[str, str]:
        """Automatically identify and load secrets from common environment variables."""
        secrets = {}
        target_keys = ["API_KEY", "TOKEN", "PASSWORD", "SECRET", "CREDENTIAL"]
        for key, value in os.environ.items():
            if any(target in key.upper() for target in target_keys):
                if len(value) > 8: # Only track substantial secrets
                    secrets[key] = value
        return secrets
    
    def calculate_entropy(self, string: str) -> float:
        """Calculate Shannon entropy of string (for detecting high-entropy secrets)."""
        import math
        
        if not string:
            return 0.0
        
        probabilities = [float(string.count(c)) / len(string) for c in set(string)]
        entropy = -sum(p * math.log2(p) if p > 0 else 0 for p in probabilities)
        return entropy
    
    def scan_text(self, text: str) -> List[Dict[str, Any]]:
        """
        Scan text for PII patterns.
        
        Returns list of detections with: type, value, position, entropy
        Prioritizes specific patterns over generic ones.
        """
        detections = []
        matched_ranges = []  # Track what's already matched
        
        # Process patterns in order (specific first, generic last)
        for pii_type, pattern in self.compiled_patterns.items():
            for match in pattern.finditer(text):
                start, end = match.start(), match.end()
                
                # Skip if this range overlaps with an already matched range
                is_overlapping = any(
                    not (end <= existing_start or start >= existing_end)
                    for existing_start, existing_end in matched_ranges
                )
                if is_overlapping:
                    continue
                
                value = match.group()
                detection = {
                    "type": pii_type,
                    "value": value,
                    "position": (start, end),
                    "entropy": self.calculate_entropy(value),
                    "timestamp": datetime.utcnow().isoformat(),
                }
                detections.append(detection)
                matched_ranges.append((start, end))
        
        self.detections.extend(detections)
        return detections
    
    def sanitize(self, text: str, redaction_char: str = "*") -> tuple[str, List[Dict[str, Any]]]:
        """
        Sanitize text by redacting PII.
        
        Returns: (sanitized_text, list_of_detections)
        """
        detections = self.scan_text(text)
        
        # Also redact environment secrets
        for env_key, secret_val in self.env_secrets.items():
            if secret_val in text:
                # Find all occurrences manually if not already caught by regex
                start = 0
                while True:
                    start = text.find(secret_val, start)
                    if start == -1: break
                    end = start + len(secret_val)
                    
                    # check for overlaps with existing detections
                    is_overlapping = any(
                        not (end <= d["position"][0] or start >= d["position"][1])
                        for d in detections
                    )
                    
                    if not is_overlapping:
                        detections.append({
                            "type": f"env_{env_key.lower()}",
                            "value": secret_val,
                            "position": (start, end),
                            "entropy": self.calculate_entropy(secret_val),
                            "timestamp": datetime.utcnow().isoformat(),
                        })
                    start = end

        if not detections:
            return text, []
        
        # Sort detections by position (descending) to avoid index shifts
        sorted_detections = sorted(detections, key=lambda d: d["position"][0], reverse=True)
        
        sanitized = text
        for detection in sorted_detections:
            start, end = detection["position"]
            pii_value = detection["value"]
            
            # Redact with pattern based on type
            if detection["type"] in ["openai_key", "aws_key", "github_token"]:
                # Show first 8 chars, redact rest
                redacted = pii_value[:8] + redaction_char * (len(pii_value) - 8)
            elif detection["type"] == "credit_card":
                # Show last 4 digits
                redacted = redaction_char * (len(pii_value) - 4) + pii_value[-4:]
            elif detection["type"] == "email":
                # Show domain, redact username
                parts = pii_value.split("@")
                redacted = redaction_char * len(parts[0]) + "@" + parts[1]
            else:
                # Full redaction
                redacted = redaction_char * len(pii_value)
            
            sanitized = sanitized[:start] + redacted + sanitized[end:]
        
        return sanitized, detections
    
    def get_detection_summary(self) -> Dict[str, int]:
        """Get summary of all detections by type."""
        summary = {}
        for detection in self.detections:
            pii_type = detection["type"]
            summary[pii_type] = summary.get(pii_type, 0) + 1
        return summary


class PhantomWorkspace:
    """
    Phantom Workspace Implementation.
    
    Creates an isolated copy-on-write workspace where destructive operations
    (modify, delete, create) are redirected to a hidden .kavach_phantom directory.
    
    This allows agents to "think" they're modifying the real filesystem while
    actually operating in a sandbox. Provides 1-click restore and inspection.
    """
    
    def __init__(self, real_workspace: Path, phantom_dir_name: str = ".kavach_phantom"):
        self.real_workspace = Path(real_workspace).resolve()
        self.phantom_root = self.real_workspace / phantom_dir_name
        self.phantom_root.mkdir(exist_ok=True, parents=True)
        
        # Track all phantom operations for rollback
        self.operations: List[Dict[str, Any]] = []
        self.file_snapshots: Dict[Path, bytes] = {}  # Original file contents
        
        logger.info(f"PhantomWorkspace initialized: {self.phantom_root}")
    
    def _get_phantom_path(self, real_path: Path) -> Path:
        """Convert real path to phantom path."""
        try:
            relative = real_path.relative_to(self.real_workspace)
            return self.phantom_root / relative
        except ValueError:
            # Path is outside workspace
            raise PhantomWorkspaceError(
                f"Path {real_path} is outside workspace {self.real_workspace}"
            )
    
    def snapshot_file(self, file_path: Path) -> None:
        """Create snapshot of file before modification (for rollback)."""
        if file_path.exists() and file_path.is_file():
            # Only snapshot files under 50MB (as per original Kavach)
            size_mb = file_path.stat().st_size / (1024 * 1024)
            if size_mb < 50:
                with open(file_path, 'rb') as f:
                    self.file_snapshots[file_path] = f.read()
                logger.debug(f"Snapshotted file: {file_path} ({size_mb:.2f}MB)")
            else:
                logger.warning(f"File too large for snapshot: {file_path} ({size_mb:.2f}MB)")
    
    def intercept_write(self, target_path: Path, content: bytes) -> Path:
        """
        Intercept write operation and redirect to phantom workspace.
        
        Returns phantom path where content was written.
        """
        target_path = Path(target_path).resolve()
        phantom_path = self._get_phantom_path(target_path)
        
        # Snapshot original if exists
        if target_path.exists():
            self.snapshot_file(target_path)
        
        # Write to phantom location
        phantom_path.parent.mkdir(parents=True, exist_ok=True)
        with open(phantom_path, 'wb') as f:
            f.write(content)
        
        self.operations.append({
            "type": "write",
            "real_path": str(target_path),
            "phantom_path": str(phantom_path),
            "timestamp": datetime.utcnow().isoformat(),
            "size": len(content),
        })
        
        logger.info(f"Intercepted write: {target_path} -> {phantom_path}")
        return phantom_path
    
    def intercept_delete(self, target_path: Path) -> None:
        """
        Intercept delete operation - move to phantom instead of actual delete.
        """
        target_path = Path(target_path).resolve()
        
        if not target_path.exists():
            logger.warning(f"Cannot intercept delete of non-existent file: {target_path}")
            return
        
        # Snapshot before "deleting"
        self.snapshot_file(target_path)
        
        phantom_path = self._get_phantom_path(target_path)
        phantom_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Move to phantom (simulate delete)
        shutil.move(str(target_path), str(phantom_path))
        
        self.operations.append({
            "type": "delete",
            "real_path": str(target_path),
            "phantom_path": str(phantom_path),
            "timestamp": datetime.utcnow().isoformat(),
        })
        
        logger.info(f"Intercepted delete: {target_path} -> {phantom_path}")
    
    def intercept_create(self, target_path: Path, content: bytes) -> Path:
        """Intercept file creation - create in phantom workspace."""
        return self.intercept_write(target_path, content)
    
    def rollback_file(self, file_path: Path) -> bool:
        """
        Rollback file to snapshot (1-click restore).
        
        Returns True if rollback successful, False if no snapshot available.
        """
        file_path = Path(file_path).resolve()
        
        if file_path not in self.file_snapshots:
            logger.warning(f"No snapshot available for: {file_path}")
            return False
        
        # Restore from snapshot
        with open(file_path, 'wb') as f:
            f.write(self.file_snapshots[file_path])
        
        logger.info(f"Rolled back file: {file_path}")
        return True
    
    def commit_changes(self) -> None:
        """Commit phantom changes to real workspace (make them permanent)."""
        for operation in self.operations:
            if operation["type"] in ["write", "create"]:
                phantom_path = Path(operation["phantom_path"])
                real_path = Path(operation["real_path"])
                
                if phantom_path.exists():
                    shutil.copy2(str(phantom_path), str(real_path))
                    logger.info(f"Committed: {phantom_path} -> {real_path}")
        
        logger.info(f"Committed {len(self.operations)} phantom operations")
    
    def discard_changes(self) -> None:
        """Discard all phantom changes (cleanup sandbox)."""
        logger.info(f"Discarding {len(self.operations)} phantom operations")
        self.operations.clear()
        self.file_snapshots.clear()
        # Optionally: shutil.rmtree(self.phantom_root)
    
    def get_operation_summary(self) -> Dict[str, int]:
        """Get summary of phantom operations."""
        summary = {}
        for op in self.operations:
            op_type = op["type"]
            summary[op_type] = summary.get(op_type, 0) + 1
        return summary


class AuditLedger:
    """
    Cryptographic Audit Ledger.
    
    Implements "Black Box" from original Kavach - immutable FNV hash chain
    that ensures audit logs cannot be tampered with.
    """
    
    def __init__(self, ledger_path: Optional[Path] = None):
        if ledger_path is None:
            ledger_path = Path(tempfile.gettempdir()) / "kavach_audit.jsonl"
        
        self.ledger_path = Path(ledger_path)
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        
        # FNV-1a hash chain (last entry hash seeds next entry)
        self.last_hash = "0" * 64  # Genesis hash
        
        logger.info(f"AuditLedger initialized: {self.ledger_path}")
    
    def _compute_hash(self, data: Dict[str, Any], prev_hash: str = None) -> str:
        """Compute SHA256 hash of entry data chained with previous hash."""
        if prev_hash is None:
            prev_hash = self.last_hash
        entry_json = json.dumps(data, sort_keys=True)
        combined = prev_hash + entry_json
        return hashlib.sha256(combined.encode()).hexdigest()
    
    def log_event(
        self,
        event_type: str,
        skill_name: str,
        severity: str,
        details: Dict[str, Any],
    ) -> str:
        """
        Log security event to immutable audit ledger.
        
        Returns: hash of logged entry
        """
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "skill_name": skill_name,
            "severity": severity,
            "details": details,
            "previous_hash": self.last_hash,
        }
        
        # Compute hash for this entry
        entry_hash = self._compute_hash(entry)
        entry["hash"] = entry_hash
        
        # Append to ledger (immutable append-only)
        with open(self.ledger_path, 'a') as f:
            f.write(json.dumps(entry) + "\n")
        
        # Update chain
        self.last_hash = entry_hash
        
        logger.debug(f"Audit log: {event_type} - {skill_name} [{severity}]")
        return entry_hash
    
    def verify_integrity(self) -> tuple[bool, List[str]]:
        """
        Verify integrity of audit ledger.
        
        Returns: (is_valid, list_of_errors)
        """
        if not self.ledger_path.exists():
            return True, []  # Empty ledger is valid
        
        errors = []
        prev_hash = "0" * 64  # Genesis
        
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
                    stored_hash = entry.get("hash")
                    entry_copy = entry.copy()
                    entry_copy.pop("hash", None)  # Remove hash before computing
                    computed_hash = self._compute_hash(entry_copy, prev_hash)
                    
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
    
    def query_events(
        self,
        event_type: Optional[str] = None,
        skill_name: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Query audit log with filters."""
        if not self.ledger_path.exists():
            return []
        
        results = []
        with open(self.ledger_path, 'r') as f:
            for line in f:
                try:
                    entry = json.loads(line.strip())
                    
                    # Apply filters
                    if event_type and entry["event_type"] != event_type:
                        continue
                    if skill_name and entry["skill_name"] != skill_name:
                        continue
                    if severity and entry["severity"] != severity:
                        continue
                    
                    results.append(entry)
                    
                    if len(results) >= limit:
                        break
                        
                except json.JSONDecodeError:
                    continue
        
        return results


class KavachWrapper:
    """
    Main Kavach Security Wrapper.
    
    Decorator/context manager that wraps skill executions with full Kavach
    security layer: phantom workspace, PII sanitization, timeout enforcement,
    tripwire monitoring, and audit logging.
    
    Usage:
        wrapper = KavachWrapper(policy=SecurityPolicy.default_strict())
        result = wrapper.execute(skill_func, *args, **kwargs)
    """
    
    def __init__(
        self,
        policy: Optional[SecurityPolicy] = None,
        workspace: Optional[Path] = None,
        audit_ledger: Optional[AuditLedger] = None,
    ):
        self.policy = policy or SecurityPolicy.default_permissive()
        self.workspace = Path(workspace) if workspace else Path.cwd()
        self.audit_ledger = audit_ledger or AuditLedger()
        
        # Initialize components
        self.pii_sanitizer = PIISanitizer(custom_patterns=self.policy.pii_patterns)
        
        if self.policy.enable_phantom_workspace:
            self.phantom_workspace = PhantomWorkspace(
                self.workspace,
                phantom_dir_name=self.policy.phantom_dir_name
            )
        else:
            self.phantom_workspace = None

        if self.policy.enable_tripwires:
            self.tripwire = TripwireMonitor(
                workspace=self.workspace,
                level=self.policy.tripwire_level.value
            )
            self.tripwire.deploy()
        else:
            self.tripwire = None

        if self.policy.enable_process_monitoring:
            self.auto_enforcer = AutoEnforcer(timeout_seconds=self.policy.execution_timeout)
            self.auto_enforcer.start()
        else:
            self.auto_enforcer = None

        self.error_count = 0
        self.skill_name = "unknown"

    def __enter__(self):
        """Allows use of KavachWrapper as a context manager."""
        self.audit_ledger.log_event(
            event_type="shield_activated",
            skill_name=self.skill_name,
            severity="INFO",
            details={"mode": "context_manager"}
        )
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Cleanup on context exit."""
        if exc_type:
            self.audit_ledger.log_event(
                event_type="shield_exception",
                skill_name=self.skill_name,
                severity="HIGH",
                details={"error": str(exc_val)}
            )
        self.cleanup()
    
    def execute(
        self,
        skill_func: Callable,
        skill_name: str,
        *args,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Execute skill function with full Kavach protection.
        
        Returns: {
            'status': 'success' | 'error',
            'result': skill_result,
            'audit': {security_metrics},
        }
        """
        self.skill_name = skill_name
        start_time = datetime.utcnow()
        
        # Log execution start
        self.audit_ledger.log_event(
            event_type="execution_start",
            skill_name=skill_name,
            severity="INFO",
            details={"workspace": str(self.workspace)},
        )
        
        try:
            # Execute with timeout (auto-enforcer handled by monitor.py)
            result = skill_func(*args, **kwargs)
            
            # Sanitize output if enabled
            if self.policy.sanitize_pii and isinstance(result, str):
                sanitized, detections = self.pii_sanitizer.sanitize(result)
                if detections:
                    self.audit_ledger.log_event(
                        event_type="pii_detected",
                        skill_name=skill_name,
                        severity="CRITICAL",
                        details={
                            "count": len(detections),
                            "types": [d["type"] for d in detections],
                        },
                    )
                    result = sanitized
            
            # Log successful execution
            duration = (datetime.utcnow() - start_time).total_seconds()
            self.audit_ledger.log_event(
                event_type="execution_success",
                skill_name=skill_name,
                severity="INFO",
                details={"duration_seconds": duration},
            )
            
            return {
                'status': 'success',
                'result': result,
                'audit': {
                    'duration': duration,
                    'pii_detections': len(self.pii_sanitizer.detections),
                    'phantom_operations': (
                        self.phantom_workspace.get_operation_summary()
                        if self.phantom_workspace else {}
                    ),
                },
            }
            
        except Exception as e:
            self.error_count += 1
            
            # Log error
            self.audit_ledger.log_event(
                event_type="execution_error",
                skill_name=skill_name,
                severity="HIGH",
                details={
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "error_count": self.error_count,
                },
            )
            
            # Check circuit breaker
            if self.error_count >= self.policy.max_errors_before_shutdown:
                self.audit_ledger.log_event(
                    event_type="circuit_breaker",
                    skill_name=skill_name,
                    severity="CRITICAL",
                    details={"reason": "max_errors_exceeded"},
                )
                raise
            
            return {
                'status': 'error',
                'error': str(e),
                'error_type': type(e).__name__,
                'audit': {
                    'error_count': self.error_count,
                },
            }
    
    def cleanup(self) -> None:
        """Cleanup phantom workspace and resources."""
        if self.phantom_workspace:
            self.phantom_workspace.discard_changes()
        
        if self.tripwire:
            self.tripwire.cleanup()

        if self.auto_enforcer:
            self.auto_enforcer.stop()
            
        logger.info("Kavach wrapper cleanup complete")

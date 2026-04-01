"""
Kavach AI Firewall - Python Integration Layer

Adapts the Kavach EDR concepts (phantom workspace, auto-enforcer, tripwires, 
PII sanitizer) from the original Rust/Tauri application into a Python library
for wrapping Purple Engine MCP skill executions.

Original Kavach: github.com/LucidAkshay/kavach (Tauri EDR desktop app)
This Integration: Python security wrapper for autonomous AI agent containment

Architecture:
- PhantomWorkspace: Isolated workspace with redirect-on-write for destructive ops
- AutoEnforcer: Timeout-based automatic termination of stuck/suspicious processes
- TripwireMonitor: Honeypot files that trigger alarms when accessed
- PIISanitizer: Real-time PII detection and sanitization in outputs
- AuditLedger: Cryptographic immutable log of all security events
"""

from .core import (
    KavachWrapper,
    PhantomWorkspace,
    SecurityPolicy,
    AuditLedger,
    PIISanitizer,
)
from .monitor import (
    AutoEnforcer,
    TripwireMonitor,
    FileWatcher,
)
from .exceptions import (
    KavachSecurityViolation,
    PhantomWorkspaceError,
    PIIDetectionError,
    TripwireTriggered,
)

__version__ = "1.0.0-alpha"
__all__ = [
    "KavachWrapper",
    "PhantomWorkspace",
    "SecurityPolicy",
    "AuditLedger",
    "PIISanitizer",
    "AutoEnforcer",
    "TripwireMonitor",
    "FileWatcher",
    "KavachSecurityViolation",
    "PhantomWorkspaceError",
    "PIIDetectionError",
    "TripwireTriggered",
]

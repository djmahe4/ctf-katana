"""
Kavach Security Exceptions

Custom exceptions for different security violation types.
"""


class KavachSecurityViolation(Exception):
    """Base exception for all Kavach security violations."""
    
    def __init__(self, message: str, severity: str = "HIGH", **context):
        super().__init__(message)
        self.severity = severity
        self.context = context


class PhantomWorkspaceError(KavachSecurityViolation):
    """Raised when phantom workspace isolation fails."""
    pass


class PIIDetectionError(KavachSecurityViolation):
    """Raised when PII is detected in output and sanitization fails."""
    
    def __init__(self, message: str, pii_type: str, detected_count: int, **context):
        super().__init__(message, severity="CRITICAL", **context)
        self.pii_type = pii_type
        self.detected_count = detected_count


class TripwireTriggered(KavachSecurityViolation):
    """Raised when a honeypot tripwire file is accessed."""
    
    def __init__(self, message: str, tripwire_path: str, access_type: str, **context):
        super().__init__(message, severity="CRITICAL", **context)
        self.tripwire_path = tripwire_path
        self.access_type = access_type


class ExecutionTimeoutError(KavachSecurityViolation):
    """Raised when skill execution exceeds timeout (auto-enforcer)."""
    
    def __init__(self, message: str, timeout_seconds: int, **context):
        super().__init__(message, severity="HIGH", **context)
        self.timeout_seconds = timeout_seconds


class FileAccessViolation(KavachSecurityViolation):
    """Raised when skill attempts unauthorized file access."""
    
    def __init__(self, message: str, file_path: str, operation: str, **context):
        super().__init__(message, severity="HIGH", **context)
        self.file_path = file_path
        self.operation = operation


class NetworkAccessViolation(KavachSecurityViolation):
    """Raised when skill attempts unauthorized network access."""
    
    def __init__(self, message: str, destination: str, **context):
        super().__init__(message, severity="MEDIUM", **context)
        self.destination = destination


class ProcessLimitExceeded(KavachSecurityViolation):
    """Raised when skill spawns too many child processes."""
    
    def __init__(self, message: str, process_count: int, limit: int, **context):
        super().__init__(message, severity="HIGH", **context)
        self.process_count = process_count
        self.limit = limit


class LoopDetectionError(KavachSecurityViolation):
    """Raised when high-velocity command loop is detected."""
    
    def __init__(self, message: str, command_pattern: str, repetitions: int, **context):
        super().__init__(message, severity="MEDIUM", **context)
        self.command_pattern = command_pattern
        self.repetitions = repetitions

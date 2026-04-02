from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Any, Optional

class AnalysisMode(Enum):
    FIRMWARE = "firmware"
    BINARY = "binary"
    PROTOCOL = "protocol"
    HARDWARE = "hardware"
    FULL = "full"

class Architecture(Enum):
    AUTO = "auto"
    ARM = "arm"
    MIPS = "mips"
    PPC = "ppc"
    X86 = "x86"
    X86_64 = "x86_64"
    RISCV = "riscv"

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class VulnType(Enum):
    # Firmware Vulns
    HARDCODED_SECRETS = "hardcoded_secrets"
    INSECURE_SERVICES = "insecure_services"
    SENSITIVE_FILES = "sensitive_files"
    WEAK_PERMISSIONS = "weak_permissions"
    COMMAND_INJECTION = "command_injection"
    DEBUG_ACCOUNTS = "debug_accounts"
    
    # Binary Vulns
    DANGEROUS_FUNCTIONS = "dangerous_functions"
    FORMAT_STRING = "format_string"
    WEAK_CRYPTO = "weak_crypto"
    HARDCODED_ADDRESSES = "hardcoded_addresses"
    STACK_CANARY_MISSING = "stack_canary_missing"
    
    # Generic
    OTHER = "other"

@dataclass
class IoTFinding:
    """Represents a security finding in an IoT/Embedded device."""
    id: str
    finding_type: VulnType
    severity: Severity
    file: str
    line: int = 0
    details: str = ""
    evidence: str = ""
    remediation: str = ""
    confidence: float = 0.0

@dataclass
class ExtractedFile:
    """Represents a file extracted from a firmware image."""
    path: str
    file_type: str
    size: int
    permissions: str = ""
    interesting: bool = False

@dataclass
class IoTAnalysisResult:
    """Result of an IoT/Embedded security analysis."""
    status: str
    target: str
    arch: str = "auto"
    os_info: str = "unknown"
    findings: List[IoTFinding] = field(default_factory=list)
    extracted_files: List[ExtractedFile] = field(default_factory=list)
    strings_of_interest: List[str] = field(default_factory=list)
    report: str = ""
    duration: float = 0.0

SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 100,
    Severity.HIGH: 70,
    Severity.MEDIUM: 40,
    Severity.LOW: 10,
    Severity.INFO: 0
}

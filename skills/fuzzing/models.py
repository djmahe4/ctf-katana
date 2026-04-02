from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from enum import Enum
from datetime import datetime

class FuzzCategory(Enum):
    WEB = "web"
    BINARY = "binary"
    PROTOCOL = "protocol"
    CLOUD = "cloud"
    CUSTOM = "custom"

class FuzzerSeverity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

@dataclass
class FuzzFinding:
    """Represents a single interesting finding from a fuzzer (e.g., a crash or a unique response)."""
    vulnerability_id: str
    description: str
    severity: FuzzerSeverity
    payload: str
    evidence: str  # e.g., response snippet, stack trace, status code
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class FuzzRunResult:
    """Represents the complete result of a fuzzing run."""
    category: FuzzCategory
    target: str
    summary: str
    findings: List[FuzzFinding] = field(default_factory=list)
    statistics: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    artifacts: List[str] = field(default_factory=list) # paths to generated harnesses or crashes 

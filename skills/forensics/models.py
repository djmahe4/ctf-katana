from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Any, Optional

class ForensicsCategory(Enum):
    FILE = "file"
    PCAP = "pcap"
    MEMORY = "memory"
    DISK = "disk"
    NETWORK = "network"

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

@dataclass
class ForensicsFinding:
    category: ForensicsCategory
    vulnerability_id: str
    severity: Severity
    description: str
    file_path: str
    evidence: str
    remediation: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ForensicsResult:
    target: str
    category: ForensicsCategory
    findings: List[ForensicsFinding] = field(default_factory=list)
    summary: str = ""
    extracted_files: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self):
        return {
            "target": self.target,
            "category": self.category.value,
            "findings": [
                {
                    "id": f.vulnerability_id,
                    "severity": f.severity.value,
                    "description": f.description,
                    "file": f.file_path,
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                    "metadata": f.metadata
                } for f in self.findings
            ],
            "summary": self.summary,
            "extracted_files": self.extracted_files,
            "metadata": self.metadata
        }

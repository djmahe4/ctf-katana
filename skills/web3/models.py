import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

class VulnType(str, Enum):
    """Web3 vulnerability types."""
    REENTRANCY = "REENTRANCY"
    FLASH_LOAN = "FLASH_LOAN"
    INTEGER_OVERFLOW = "INTEGER_OVERFLOW"
    INTEGER_UNDERFLOW = "INTEGER_UNDERFLOW"
    ACCESS_CONTROL = "ACCESS_CONTROL"
    ACCOUNTING = "ACCOUNTING"
    ORACLE_MANIPULATION = "ORACLE_MANIPULATION"
    FRONT_RUNNING = "FRONT_RUNNING"
    DENIAL_OF_SERVICE = "DENIAL_OF_SERVICE"
    LOGIC_ERROR = "LOGIC_ERROR"
    UNCHECKED_RETURN = "UNCHECKED_RETURN"
    PRIVATE_DATA_EXPOSURE = "PRIVATE_DATA_EXPOSURE"
    DELEGATE_CALL = "DELEGATE_CALL"
    SELF_DESTRUCT = "SELF_DESTRUCT"
    TX_ORIGIN_USAGE = "TX_ORIGIN_USAGE"
    GAS_LIMITATION = "GAS_LIMITATION"
    OTHER = "OTHER"

class Severity(str, Enum):
    """Vulnerability severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

VULN_SEVERITY = {
    VulnType.REENTRANCY: Severity.CRITICAL,
    VulnType.FLASH_LOAN: Severity.HIGH,
    VulnType.ACCESS_CONTROL: Severity.CRITICAL,
    VulnType.ORACLE_MANIPULATION: Severity.HIGH,
    VulnType.LOGIC_ERROR: Severity.HIGH,
    VulnType.INTEGER_OVERFLOW: Severity.MEDIUM,
    VulnType.INTEGER_UNDERFLOW: Severity.MEDIUM,
    VulnType.DENIAL_OF_SERVICE: Severity.MEDIUM,
    VulnType.ACCOUNTING: Severity.MEDIUM,
    VulnType.UNCHECKED_RETURN: Severity.MEDIUM,
    VulnType.DELEGATE_CALL: Severity.HIGH,
    VulnType.SELF_DESTRUCT: Severity.HIGH,
    VulnType.FRONT_RUNNING: Severity.LOW,
    VulnType.PRIVATE_DATA_EXPOSURE: Severity.LOW,
    VulnType.TX_ORIGIN_USAGE: Severity.MEDIUM,
    VulnType.GAS_LIMITATION: Severity.LOW,
}

SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 8,
    Severity.MEDIUM: 5,
    Severity.LOW: 2,
    Severity.INFO: 1,
}

@dataclass
class Web3Vulnerability:
    """Web3 vulnerability data structure."""
    id: str
    vuln_type: VulnType
    severity: Severity
    function: str
    line: int
    description: str
    pattern_matched: str
    remediation: str
    confidence: float = 1.0
    evidence: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "vuln_type": self.vuln_type.value,
            "severity": self.severity.value,
            "function": self.function,
            "line": self.line,
            "description": self.description,
            "pattern_matched": self.pattern_matched,
            "remediation": self.remediation,
            "confidence": self.confidence,
            "evidence": self.evidence
        }

@dataclass
class Web3AnalysisResult:
    """Web3 analysis result data structure."""
    status: str
    target: str
    chain: str
    network: str = "mainnet"
    contract_name: Optional[str] = None
    vulnerabilities: List[Web3Vulnerability] = field(default_factory=list)
    security_features: Dict[str, bool] = field(default_factory=dict)
    risk_score: float = 0.0
    report: str = ""
    duration: float = 0.0

    def calculate_risk_score(self) -> float:
        """Calculate the risk score based on the vulnerabilities."""
        score = sum(SEVERITY_WEIGHTS.get(v.severity, 0) for v in self.vulnerabilities)
        self.risk_score = min(score, 100.0) # Cap at 100
        return self.risk_score

    def to_dict(self) -> Dict[str, Any]:
        """Convert Web3AnalysisResult to a dictionary for easy JSON serialization."""
        return {
            "status": self.status,
            "target": self.target,
            "chain": self.chain,
            "network": self.network,
            "contract_name": self.contract_name,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "security_features": self.security_features,
            "risk_score": self.risk_score,
            "report": self.report,
            "duration": self.duration,
        }

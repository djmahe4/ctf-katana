"""
Web3 Smart Contract Vulnerability Analyzer

Analyzes Solidity smart contracts for:
- Reentrancy vulnerabilities
- Flash loan attack vectors
- Integer overflow/underflow
- Access control issues
- Logic and accounting bugs
"""

import os
import sys
import re
import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

logger = logging.getLogger(__name__)


class VulnType(Enum):
    REENTRANCY = "reentrancy"
    FLASH_LOAN = "flash_loan"
    INTEGER_OVERFLOW = "integer_overflow"
    INTEGER_UNDERFLOW = "integer_underflow"
    ACCESS_CONTROL = "access_control"
    ACCOUNTING = "accounting"
    ORACLE_MANIPULATION = "oracle_manipulation"
    FRONT_RUNNING = "front_running"
    DENIAL_OF_SERVICE = "denial_of_service"
    LOGIC_ERROR = "logic_error"


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# Solidity vulnerability patterns
VULN_PATTERNS = {
    VulnType.REENTRANCY: [
        # External call patterns
        (r'\.call\{.*value.*\}\s*\(', "External call with value transfer"),
        (r'\.transfer\s*\(', "Transfer that could trigger fallback"),
        (r'\.send\s*\(', "Send that could trigger fallback"),
        # State after call
        (r'(\.call|\.transfer|\.send)[^;]*;[^}]*\w+\s*=', "State update after external call"),
    ],
    VulnType.FLASH_LOAN: [
        # Price calculation from pool
        (r'reserve[01]\s*/\s*reserve[10]', "Direct reserve ratio price calculation"),
        (r'getReserves\(\)', "Using pool reserves for price"),
        # Single-block price
        (r'block\.timestamp', "Timestamp dependency for price"),
    ],
    VulnType.INTEGER_OVERFLOW: [
        # Pre-0.8.0 unchecked math
        (r'pragma solidity\s*[<^]?\s*0\.[0-7]', "Solidity version < 0.8.0 (no automatic overflow checks)"),
        # Unchecked blocks in 0.8+
        (r'unchecked\s*\{', "Unchecked arithmetic block"),
    ],
    VulnType.ACCESS_CONTROL: [
        # tx.origin check
        (r'tx\.origin', "tx.origin used for authentication"),
        # Missing access control
        (r'function\s+\w+\s*\([^)]*\)\s+(external|public)[^{]*{[^}]*selfdestruct', "Unprotected selfdestruct"),
        # Default visibility
        (r'function\s+\w+\s*\([^)]*\)\s*{', "Function without visibility specifier"),
    ],
    VulnType.ACCOUNTING: [
        # Division before multiplication
        (r'\w+\s*/\s*\w+\s*\*\s*\w+', "Division before multiplication (precision loss)"),
        # Rounding
        (r'(\w+\s*-\s*1)\s*/', "Potential rounding manipulation"),
    ],
    VulnType.DENIAL_OF_SERVICE: [
        # Unbounded loops
        (r'for\s*\([^)]*;\s*\w+\s*<\s*\w+\.length', "Unbounded loop over array"),
        # External call in loop
        (r'for\s*\([^)]*\{[^}]*(\.call|\.transfer|\.send)', "External call in loop"),
    ],
}

# Security patterns to check for (good practices)
SECURITY_PATTERNS = {
    "ReentrancyGuard": r'ReentrancyGuard|nonReentrant',
    "SafeMath": r'SafeMath|using SafeMath',
    "Ownable": r'Ownable|onlyOwner',
    "Pausable": r'Pausable|whenNotPaused',
    "AccessControl": r'AccessControl|hasRole',
}


@dataclass
class Web3Vulnerability:
    """Represents a smart contract vulnerability."""
    id: str
    vuln_type: str
    severity: str
    function: str
    line: int
    description: str
    pattern_matched: str
    exploitation: str = ""
    remediation: str = ""
    poc: str = ""
    confidence: float = 0.0


@dataclass
class Web3AnalysisResult:
    """Result of smart contract analysis."""
    status: str
    target: str
    contract_name: str = ""
    solidity_version: str = ""
    vulnerabilities: List[Web3Vulnerability] = field(default_factory=list)
    security_features: Dict[str, bool] = field(default_factory=dict)
    risk_score: float = 0.0
    report: str = ""
    duration: float = 0.0


class Web3Analyzer:
    """
    Web3 Smart Contract Vulnerability Analyzer.
    """
    
    # Severity weights for risk score
    SEVERITY_WEIGHTS = {
        Severity.CRITICAL: 10.0,
        Severity.HIGH: 7.5,
        Severity.MEDIUM: 5.0,
        Severity.LOW: 2.5,
        Severity.INFO: 0.5,
    }
    
    # Vuln type to severity mapping
    VULN_SEVERITY = {
        VulnType.REENTRANCY: Severity.CRITICAL,
        VulnType.FLASH_LOAN: Severity.CRITICAL,
        VulnType.INTEGER_OVERFLOW: Severity.HIGH,
        VulnType.INTEGER_UNDERFLOW: Severity.HIGH,
        VulnType.ACCESS_CONTROL: Severity.HIGH,
        VulnType.ACCOUNTING: Severity.MEDIUM,
        VulnType.ORACLE_MANIPULATION: Severity.HIGH,
        VulnType.FRONT_RUNNING: Severity.MEDIUM,
        VulnType.DENIAL_OF_SERVICE: Severity.MEDIUM,
        VulnType.LOGIC_ERROR: Severity.MEDIUM,
    }
    
    # Remediation suggestions
    REMEDIATIONS = {
        VulnType.REENTRANCY: "Use checks-effects-interactions pattern and/or ReentrancyGuard modifier",
        VulnType.FLASH_LOAN: "Use time-weighted average price (TWAP) oracles and multi-block price checks",
        VulnType.INTEGER_OVERFLOW: "Use Solidity 0.8+ or SafeMath library for arithmetic operations",
        VulnType.INTEGER_UNDERFLOW: "Use Solidity 0.8+ or SafeMath library for arithmetic operations",
        VulnType.ACCESS_CONTROL: "Implement proper access control using OpenZeppelin's AccessControl or Ownable",
        VulnType.ACCOUNTING: "Use multiplication before division, implement proper rounding guards",
        VulnType.ORACLE_MANIPULATION: "Use decentralized oracles (Chainlink) with manipulation resistance",
        VulnType.FRONT_RUNNING: "Implement commit-reveal schemes or use Flashbots",
        VulnType.DENIAL_OF_SERVICE: "Implement pagination for loops, avoid unbounded iterations",
        VulnType.LOGIC_ERROR: "Comprehensive unit and integration testing, formal verification if possible",
    }
    
    def __init__(
        self,
        ollama_model: str = None,
        ollama_host: str = None,
    ):
        self.ollama_model = ollama_model or os.environ.get("KATANA_OLLAMA_MODEL", "mistral-nemo")
        self.ollama_host = ollama_host or os.environ.get("KATANA_OLLAMA_HOST", "http://localhost:11434")
        self.vuln_counter = 0
    
    def _generate_vuln_id(self) -> str:
        """Generate unique vulnerability ID."""
        self.vuln_counter += 1
        return f"WEB3-{datetime.utcnow().strftime('%Y%m%d')}-{self.vuln_counter:04d}"
    
    def _extract_solidity_version(self, content: str) -> str:
        """Extract Solidity version from pragma."""
        match = re.search(r'pragma solidity\s*([^;]+);', content)
        return match.group(1).strip() if match else "unknown"
    
    def _extract_contract_name(self, content: str) -> str:
        """Extract contract name."""
        match = re.search(r'contract\s+(\w+)', content)
        return match.group(1) if match else "Unknown"
    
    def _extract_function_at_line(self, content: str, line_num: int) -> str:
        """Extract function name containing the given line."""
        lines = content.split('\n')
        for i in range(line_num - 1, -1, -1):
            match = re.search(r'function\s+(\w+)', lines[i])
            if match:
                return match.group(1)
        return "unknown"
    
    def _check_security_features(self, content: str) -> Dict[str, bool]:
        """Check for security patterns in contract."""
        features = {}
        for name, pattern in SECURITY_PATTERNS.items():
            features[name] = bool(re.search(pattern, content))
        return features
    
    def _calculate_risk_score(
        self,
        vulnerabilities: List[Web3Vulnerability],
        security_features: Dict[str, bool],
    ) -> float:
        """Calculate overall risk score (0-10)."""
        if not vulnerabilities:
            return 0.0
        
        # Sum weighted vulnerabilities
        vuln_score = sum(
            self.SEVERITY_WEIGHTS.get(Severity(v.severity), 0)
            for v in vulnerabilities
        )
        
        # Cap at 10
        base_score = min(10.0, vuln_score)
        
        # Reduce score for security features
        feature_count = sum(1 for v in security_features.values() if v)
        reduction = feature_count * 0.5
        
        final_score = max(0.0, base_score - reduction)
        return round(final_score, 1)
    
    def analyze_content(
        self,
        content: str,
        vuln_types: List[VulnType] = None,
    ) -> List[Web3Vulnerability]:
        """Analyze Solidity source code for vulnerabilities."""
        vulnerabilities = []
        lines = content.split('\n')
        
        # Filter vuln types if specified
        patterns_to_check = VULN_PATTERNS
        if vuln_types:
            patterns_to_check = {k: v for k, v in VULN_PATTERNS.items() if k in vuln_types}
        
        for vuln_type, patterns in patterns_to_check.items():
            severity = self.VULN_SEVERITY.get(vuln_type, Severity.MEDIUM)
            
            for pattern, description in patterns:
                for line_num, line in enumerate(lines, 1):
                    if re.search(pattern, line, re.IGNORECASE):
                        function_name = self._extract_function_at_line(content, line_num)
                        
                        vuln = Web3Vulnerability(
                            id=self._generate_vuln_id(),
                            vuln_type=vuln_type.value,
                            severity=severity.value,
                            function=function_name,
                            line=line_num,
                            description=description,
                            pattern_matched=line.strip()[:100],
                            remediation=self.REMEDIATIONS.get(vuln_type, ""),
                            confidence=0.7,
                        )
                        vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def analyze(
        self,
        target: str,
        mode: str = "full",
    ) -> Web3AnalysisResult:
        """
        Analyze a smart contract for vulnerabilities.
        
        Args:
            target: Contract source file, address, or repo URL
            mode: Analysis mode (reentrancy, flash_loan, accounting, access_control, full)
        """
        start = datetime.utcnow()
        
        # Determine vuln types based on mode
        vuln_types = None
        if mode != "full":
            mode_mapping = {
                "reentrancy": [VulnType.REENTRANCY],
                "flash_loan": [VulnType.FLASH_LOAN, VulnType.ORACLE_MANIPULATION],
                "accounting": [VulnType.ACCOUNTING, VulnType.INTEGER_OVERFLOW],
                "access_control": [VulnType.ACCESS_CONTROL],
            }
            vuln_types = mode_mapping.get(mode)
        
        # Load contract source
        target_path = Path(target)
        if target_path.is_file() and target_path.suffix == '.sol':
            content = target_path.read_text(encoding='utf-8', errors='ignore')
            contract_name = self._extract_contract_name(content)
        else:
            # For addresses/repos, we'd need etherscan API or git clone
            # For now, create placeholder
            content = ""
            contract_name = target
        
        if not content:
            return Web3AnalysisResult(
                status="error",
                target=target,
                report="Could not load contract source. Provide a .sol file path.",
            )
        
        # Extract metadata
        solidity_version = self._extract_solidity_version(content)
        contract_name = self._extract_contract_name(content)
        
        # Check security features
        security_features = self._check_security_features(content)
        
        # Analyze for vulnerabilities
        vulnerabilities = self.analyze_content(content, vuln_types)
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(vulnerabilities, security_features)
        
        # Generate report
        report = self._generate_report(
            contract_name, solidity_version, vulnerabilities, security_features, risk_score
        )
        
        duration = (datetime.utcnow() - start).total_seconds()
        
        return Web3AnalysisResult(
            status="success",
            target=target,
            contract_name=contract_name,
            solidity_version=solidity_version,
            vulnerabilities=vulnerabilities,
            security_features=security_features,
            risk_score=risk_score,
            report=report,
            duration=duration,
        )
    
    def _generate_report(
        self,
        contract_name: str,
        solidity_version: str,
        vulnerabilities: List[Web3Vulnerability],
        security_features: Dict[str, bool],
        risk_score: float,
    ) -> str:
        """Generate analysis report."""
        report = f"""# Smart Contract Security Analysis

## Contract: {contract_name}
- Solidity Version: {solidity_version}
- Risk Score: {risk_score}/10

## Security Features
"""
        for feature, present in security_features.items():
            status = "✅" if present else "❌"
            report += f"- {feature}: {status}\n"
        
        report += f"\n## Vulnerabilities Found: {len(vulnerabilities)}\n"
        
        # Group by severity
        by_severity = {}
        for v in vulnerabilities:
            by_severity.setdefault(v.severity, []).append(v)
        
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if severity in by_severity:
                report += f"\n### {severity} ({len(by_severity[severity])})\n"
                for v in by_severity[severity]:
                    report += f"""
#### {v.id}: {v.description}
- **Type**: {v.vuln_type}
- **Function**: {v.function}
- **Line**: {v.line}
- **Pattern**: `{v.pattern_matched[:50]}...`
- **Remediation**: {v.remediation}
"""
        
        return report


def run(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main entry point for Web3 Analyzer skill.
    """
    target = params.get('target', '')
    mode = params.get('mode', 'full')
    
    if not target:
        return {
            'status': 'error',
            'message': 'target parameter required (contract file, address, or repo URL)',
        }
    
    try:
        analyzer = Web3Analyzer()
        result = analyzer.analyze(target, mode)
        
        return {
            'status': result.status,
            'target': result.target,
            'contract_name': result.contract_name,
            'solidity_version': result.solidity_version,
            'vulnerabilities': [asdict(v) for v in result.vulnerabilities],
            'security_features': result.security_features,
            'risk_score': result.risk_score,
            'vulnerability_count': len(result.vulnerabilities),
            'report': result.report,
            'duration': result.duration,
        }
        
    except Exception as e:
        logger.error(f"Web3 analysis error: {e}")
        return {
            'status': 'error',
            'message': str(e),
        }


def main():
    """CLI entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Web3 Smart Contract Analyzer')
    parser.add_argument('target', help='Contract file, address, or repo')
    parser.add_argument('--mode', '-m', 
                        choices=['reentrancy', 'flash_loan', 'accounting', 'access_control', 'full'],
                        default='full')
    
    args = parser.parse_args()
    
    result = run({
        'target': args.target,
        'mode': args.mode,
    })
    
    print(json.dumps(result, indent=2, default=str))


if __name__ == '__main__':
    main()

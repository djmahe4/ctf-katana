import re
import os
import logging
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from .models import VulnType, Severity, Web3Vulnerability, Web3AnalysisResult, SEVERITY_WEIGHTS

logger = logging.getLogger(__name__)

class Web3HandlerBase(ABC):
    """Abstract base class for Web3 security handlers."""

    def __init__(self, chain: str, network: str = "mainnet"):
        self.chain = chain
        self.network = network

    @abstractmethod
    def get_patterns(self) -> Dict[VulnType, List[Any]]:
        """Return a mapping of vulnerability types to pattern definitions (str, tuple, or dict)."""
        pass

    def scan_file(self, content: str, file_path: str) -> List[Web3Vulnerability]:
        """Scan a file content for vulnerabilities using regex patterns."""
        vulnerabilities = []
        patterns_map = self.get_patterns()
        
        # Clean content (remove comments for more accurate regex matching)
        clean_content = self._remove_comments(content)
        lines = content.splitlines()

        for vuln_type, patterns in patterns_map.items():
            for pattern_item in patterns:
                # Handle different pattern formats (string vs dict)
                pattern_str = ""
                custom_desc = None
                custom_severity = None
                custom_confidence = 0.8

                if isinstance(pattern_item, dict):
                    pattern_str = pattern_item.get('pattern', '')
                    custom_desc = pattern_item.get('description')
                    custom_severity = pattern_item.get('severity')
                    if custom_severity:
                        try:
                            custom_severity = Severity(custom_severity.upper())
                        except (ValueError, AttributeError):
                            custom_severity = None
                    custom_confidence = pattern_item.get('confidence', 0.8)
                elif isinstance(pattern_item, tuple):
                    pattern_str = pattern_item[0]
                    if len(pattern_item) > 1:
                        custom_desc = pattern_item[1]
                else:
                    pattern_str = str(pattern_item)

                if not pattern_str:
                    continue

                try:
                    for match in re.finditer(pattern_str, clean_content, re.MULTILINE | re.IGNORECASE):
                        start_pos = match.start()
                        line_no = content.count('\n', 0, start_pos) + 1
                        
                        # Extract function name if possible
                        function_name = self._extract_function_name(content, line_no)
                        
                        # Use custom metadata if available, otherwise fall back to defaults
                        severity = custom_severity or self._get_default_severity(vuln_type)
                        description = custom_desc or f"Potential {vuln_type.value.replace('_', ' ').lower()} detected."
                        
                        vulnerability = Web3Vulnerability(
                            id=f"{self.chain.upper()}-{vuln_type.name}-{line_no}",
                            vuln_type=vuln_type,
                            severity=severity,
                            function=function_name or "unknown",
                            line=line_no,
                            description=description,
                            pattern_matched=pattern_str,
                            remediation=self._get_remediation(vuln_type),
                            confidence=custom_confidence,
                            evidence=match.group(0).strip()
                        )
                        vulnerabilities.append(vulnerability)
                except Exception as e:
                    logger.error(f"Error scanning pattern '{pattern_str}': {e}")
        
        return vulnerabilities

    def _remove_comments(self, content: str) -> str:
        """Remove comments based on common web3 language syntax (Solidity, Rust, etc.)."""
        # Remove single line comments
        content = re.sub(r'//.*', '', content)
        # Remove multi-line comments
        content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
        # Remove hash comments (for Python/Vyper)
        content = re.sub(r'#.*', '', content)
        return content

    def _extract_function_name(self, content: str, line_no: int) -> Optional[str]:
        """Attempt to extract the function name containing the vulnerability."""
        lines = content.splitlines()
        # Search backwards from the line_no for function definitions
        for i in range(line_no - 1, max(-1, line_no - 50), -1):
            line = lines[i]
            # Match Solidity: function name(...)
            sol_match = re.search(r'function\s+([a-zA-Z0-9_]+)', line)
            if sol_match:
                return sol_match.group(1)
            # Match Rust/Move: pub? fn name(...)
            rust_match = re.search(r'fn\s+([a-zA-Z0-9_]+)', line)
            if rust_match:
                return rust_match.group(1)
        return None

    def _get_default_severity(self, vuln_type: VulnType) -> Severity:
        from .models import VULN_SEVERITY
        return VULN_SEVERITY.get(vuln_type, Severity.MEDIUM)

    def _get_remediation(self, vuln_type: VulnType) -> str:
        remediations = {
            VulnType.REENTRANCY: "Use the Checks-Effects-Interactions pattern or a ReentrancyGuard.",
            VulnType.ACCESS_CONTROL: "Ensure all sensitive functions have proper access modifiers (e.g., onlyOwner).",
            VulnType.INTEGER_OVERFLOW: "Use SafeMath library or Solidity 0.8+ built-in overflow checks.",
            VulnType.FRONT_RUNNING: "Use commit-reveal schemes or minimize dependency on block timestamp/order.",
            # Add more as needed
        }
        return remediations.get(vuln_type, "Review logic and ensure security best practices are followed.")

    def risk_level(self, score: float) -> str:
        if score >= 80: return "CRITICAL"
        if score >= 50: return "HIGH"
        if score >= 20: return "MEDIUM"
        return "LOW"

    def generate_markdown_report(self, result: Web3AnalysisResult) -> str:
        """Generate a beautiful Markdown report."""
        risk = self.risk_level(result.risk_score)
        
        report = f"# Web3 Security Audit Report: {result.contract_name or result.target}\n\n"
        report += f"**Chain**: {result.chain.capitalize()} | **Network**: {result.network}\n"
        report += f"**Risk Score**: {result.risk_score}/100 (**{risk}**)\n"
        report += f"**Duration**: {result.duration:.2f}s\n\n"

        if not result.vulnerabilities:
            report += "## ✅ No major vulnerabilities found.\n\n"
            report += "The contract appears to follow standard security patterns for the identified areas.\n"
        else:
            report += f"## ⚠️ {len(result.vulnerabilities)} Vulnerabilities Detected\n\n"
            
            # Sort vulnerabilities by severity
            sorted_vulns = sorted(
                result.vulnerabilities, 
                key=lambda v: SEVERITY_WEIGHTS.get(v.severity, 0), 
                reverse=True
            )

            for v in sorted_vulns:
                report += f"### [{v.severity.value}] {v.vuln_type.value.replace('_', ' ')}\n"
                report += f"- **Location**: `{v.function}` (Line {v.line})\n"
                report += f"- **Description**: {v.description}\n"
                report += f"- **Evidence**: `{v.evidence}`\n"
                report += f"- **Remediation**: {v.remediation}\n\n"

        if result.security_features:
            report += "## 🛡️ Security Features Detected\n"
            for feature, detected in result.security_features.items():
                status = "✅ Detected" if detected else "❌ Not Detected"
                report += f"- **{feature.replace('_', ' ').capitalize()}**: {status}\n"

        return report

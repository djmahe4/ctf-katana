import re
import os
import logging
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from pathlib import Path
from .models import VulnType, Severity, IoTFinding, IoTAnalysisResult, SEVERITY_WEIGHTS

logger = logging.getLogger(__name__)

class IoTHandlerBase(ABC):
    """Abstract base class for IoT/Embedded security handlers."""

    def __init__(self, target_path: str, arch: str = "auto"):
        self.target_path = Path(target_path)
        self.arch = arch
        self.finding_counter = 0

    @abstractmethod
    def get_patterns(self) -> Dict[VulnType, List[Any]]:
        """Return a mapping of vulnerability types to pattern definitions."""
        pass
    
    def _generate_finding_id(self, vuln_type: VulnType) -> str:
        """Generate a unique finding ID."""
        self.finding_counter += 1
        return f"IOT-{vuln_type.name}-{self.finding_counter:04d}"

    def scan_file(self, content: str, file_path: str) -> List[IoTFinding]:
        """Scan a file content for vulnerabilities using regex patterns."""
        findings = []
        patterns_map = self.get_patterns()
        
        # IoT files can be binary or text; we handle both as strings for regex
        lines = content.splitlines()

        for vuln_type, patterns in patterns_map.items():
            for pattern_item in patterns:
                pattern_str = ""
                custom_desc = None
                custom_severity = None
                custom_confidence = 0.8
                custom_remediation = None

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
                    custom_remediation = pattern_item.get('remediation')
                elif isinstance(pattern_item, tuple):
                    pattern_str = pattern_item[0]
                    if len(pattern_item) > 1:
                        custom_desc = pattern_item[1]
                else:
                    pattern_str = str(pattern_item)

                if not pattern_str:
                    continue

                try:
                    for match in re.finditer(pattern_str, content, re.MULTILINE | re.IGNORECASE):
                        start_pos = match.start()
                        line_no = content.count('\n', 0, start_pos) + 1
                        
                        severity = custom_severity or self._get_default_severity(vuln_type)
                        description = custom_desc or f"Potential {vuln_type.value.replace('_', ' ').lower()} detected."
                        remediation = custom_remediation or self._get_default_remediation(vuln_type)
                        
                        finding = IoTFinding(
                            id=self._generate_finding_id(vuln_type),
                            finding_type=vuln_type,
                            severity=severity,
                            file=file_path,
                            line=line_no,
                            details=description,
                            evidence=match.group(0).strip()[:200],
                            remediation=remediation,
                            confidence=custom_confidence
                        )
                        findings.append(finding)
                except Exception as e:
                    logger.error(f"Error scanning pattern '{pattern_str}' in {file_path}: {e}")
        
        return findings

    def _get_default_severity(self, vuln_type: VulnType) -> Severity:
        severity_map = {
            VulnType.HARDCODED_SECRETS: Severity.CRITICAL,
            VulnType.INSECURE_SERVICES: Severity.HIGH,
            VulnType.SENSITIVE_FILES: Severity.CRITICAL,
            VulnType.WEAK_PERMISSIONS: Severity.HIGH,
            VulnType.COMMAND_INJECTION: Severity.CRITICAL,
            VulnType.DEBUG_ACCOUNTS: Severity.CRITICAL,
            VulnType.DANGEROUS_FUNCTIONS: Severity.HIGH,
            VulnType.FORMAT_STRING: Severity.CRITICAL,
            VulnType.WEAK_CRYPTO: Severity.HIGH,
            VulnType.HARDCODED_ADDRESSES: Severity.MEDIUM,
            VulnType.STACK_CANARY_MISSING: Severity.HIGH,
        }
        return severity_map.get(vuln_type, Severity.MEDIUM)

    def _get_default_remediation(self, vuln_type: VulnType) -> str:
        remediations = {
            VulnType.HARDCODED_SECRETS: "Remove sensitive keys/passwords and use a secure vault or HSM.",
            VulnType.INSECURE_SERVICES: "Disable insecure services (Telnet/FTP) and use SSH/SFTP.",
            VulnType.SENSITIVE_FILES: "Ensure sensitive files like /etc/shadow or SSH keys are not included in production firmware.",
            VulnType.WEAK_PERMISSIONS: "Follow the principle of least privilege; remove world-writable permissions from system files.",
            VulnType.COMMAND_INJECTION: "Sanitize user input before passing to system shells; use parameterized APIs.",
            VulnType.DEBUG_ACCOUNTS: "Remove all diagnostic/backdoor accounts before shipping.",
            CulnType.DANGEROUS_FUNCTIONS: "Replace unsafe functions (strcpy, gets) with bounded alternatives (strncpy, fgets).",
            VulnType.FORMAT_STRING: "Ensure format strings are constants, never user-controlled input.",
            VulnType.WEAK_CRYPTO: "Migrate to modern cryptographic standards like AES-GCM or SHA-256.",
            VulnType.HARDCODED_ADDRESSES: "Use runtime configuration or DNS instead of hardcoded IPs.",
            VulnType.STACK_CANARY_MISSING: "Enable compiler protections like -fstack-protector-all.",
        }
        return remediations.get(vuln_type, "Review findings and apply security best practices for embedded systems.")

    def generate_markdown_report(self, result: IoTAnalysisResult) -> str:
        """Generate a complete Markdown report for IoT security findings."""
        report = f"# IoT Security Analysis Report: {result.target}\n\n"
        report += f"**Architecture**: {result.arch} | **OS Info**: {result.os_info}\n"
        report += f"**Findings**: {len(result.findings)} detected\n"
        report += f"**Duration**: {result.duration:.2f}s\n\n"

        if not result.findings:
            report += "## ✅ No major vulnerabilities found.\n\n"
        else:
            report += f"## ⚠️ {len(result.findings)} Vulnerabilities Detected\n\n"
            
            # Sort findings by severity
            sorted_findings = sorted(
                result.findings, 
                key=lambda f: SEVERITY_WEIGHTS.get(f.severity, 0), 
                reverse=True
            )

            for f in sorted_findings:
                report += f"### [{f.severity.value}] {f.finding_type.value.replace('_', ' ').capitalize()}\n"
                report += f"- **Location**: `{f.file}` (Line {f.line})\n"
                report += f"- **Details**: {f.details}\n"
                report += f"- **Evidence**: `{f.evidence}`\n"
                report += f"- **Remediation**: {f.remediation}\n\n"

        if result.strings_of_interest:
            report += "## 🔍 Interesting Strings\n"
            for s in result.strings_of_interest[:20]:
                report += f"- `{s[:100]}`\n"

        return report

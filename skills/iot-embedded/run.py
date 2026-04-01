"""
IoT/Embedded Systems Security Analyzer

Security analysis for embedded systems and IoT devices:
- Firmware extraction and analysis
- Binary reverse engineering
- Protocol analysis
- Hardware security assessment
"""

import os
import sys
import re
import json
import logging
import subprocess
import struct
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


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
    X86 = "x86"
    X86_64 = "x86_64"
    RISCV = "riscv"


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# Patterns for credential detection
CREDENTIAL_PATTERNS = {
    "password_assign": (r'password\s*[=:]\s*["\']([^"\']+)["\']', Severity.CRITICAL),
    "api_key": (r'api[_-]?key\s*[=:]\s*["\']([^"\']+)["\']', Severity.HIGH),
    "secret": (r'secret\s*[=:]\s*["\']([^"\']+)["\']', Severity.HIGH),
    "private_key": (r'-----BEGIN [A-Z]+ PRIVATE KEY-----', Severity.CRITICAL),
    "aws_key": (r'AKIA[0-9A-Z]{16}', Severity.CRITICAL),
    "default_creds": (r'(admin|root|user)\s*[=:]\s*["\']?(admin|root|password|123456)', Severity.CRITICAL),
}

# Vulnerable functions in binaries
DANGEROUS_FUNCTIONS = {
    "strcpy": ("Buffer overflow", Severity.HIGH),
    "strcat": ("Buffer overflow", Severity.HIGH),
    "sprintf": ("Buffer overflow / Format string", Severity.HIGH),
    "gets": ("Buffer overflow", Severity.CRITICAL),
    "scanf": ("Buffer overflow", Severity.MEDIUM),
    "system": ("Command injection", Severity.HIGH),
    "popen": ("Command injection", Severity.HIGH),
    "exec": ("Command execution", Severity.MEDIUM),
}

# Magic bytes for file type detection
MAGIC_BYTES = {
    b'\x7fELF': 'ELF',
    b'hsqs': 'SquashFS',
    b'sqsh': 'SquashFS',
    b'\x1f\x8b': 'gzip',
    b'BZ': 'bzip2',
    b'\xfd7zXZ': 'xz',
    b'LZMA': 'lzma',
    b'PK\x03\x04': 'zip',
    b'\x85\x19\x01\x00': 'jffs2',
    b'\x27\x05\x19\x56': 'uImage',
}


@dataclass
class IoTFinding:
    """Represents a security finding."""
    id: str
    finding_type: str
    severity: str
    file: str
    line: int = 0
    details: str = ""
    evidence: str = ""
    remediation: str = ""
    confidence: float = 0.0


@dataclass
class ExtractedFile:
    """Represents an extracted file."""
    path: str
    file_type: str
    size: int
    permissions: str = ""
    interesting: bool = False


@dataclass
class IoTAnalysisResult:
    """Result of IoT analysis."""
    status: str
    target: str
    arch: str = ""
    os_info: str = ""
    findings: List[IoTFinding] = field(default_factory=list)
    extracted_files: List[ExtractedFile] = field(default_factory=list)
    strings_of_interest: List[str] = field(default_factory=list)
    report: str = ""
    duration: float = 0.0


class IoTAnalyzer:
    """
    IoT/Embedded Systems Security Analyzer.
    """
    
    # Interesting file patterns
    INTERESTING_FILES = [
        r'/etc/passwd',
        r'/etc/shadow',
        r'\.pem$',
        r'\.key$',
        r'\.crt$',
        r'\.conf$',
        r'\.cfg$',
        r'\.ini$',
        r'\.sqlite$',
        r'\.db$',
    ]
    
    # Interesting string patterns
    INTERESTING_STRINGS = [
        r'http://[^\s"\']+',
        r'https://[^\s"\']+',
        r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
        r'password|passwd|secret|api.?key|token|credential',
    ]
    
    def __init__(self):
        self.finding_counter = 0
    
    def _generate_finding_id(self) -> str:
        """Generate unique finding ID."""
        self.finding_counter += 1
        return f"IOT-{datetime.utcnow().strftime('%Y%m%d')}-{self.finding_counter:04d}"
    
    def _detect_file_type(self, file_path: Path) -> str:
        """Detect file type using magic bytes."""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(16)
            
            for magic, file_type in MAGIC_BYTES.items():
                if header.startswith(magic):
                    return file_type
            
            # Check for ELF architecture
            if header[:4] == b'\x7fELF':
                arch_byte = header[18:19]
                if arch_byte == b'\x03':
                    return "ELF (x86)"
                elif arch_byte == b'\x3e':
                    return "ELF (x86_64)"
                elif arch_byte == b'\x28':
                    return "ELF (ARM)"
                elif arch_byte == b'\x08':
                    return "ELF (MIPS)"
                return "ELF"
            
            return "unknown"
        except Exception:
            return "error"
    
    def _detect_architecture(self, file_path: Path) -> str:
        """Detect binary architecture."""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(20)
            
            if header[:4] != b'\x7fELF':
                return "unknown"
            
            machine = struct.unpack('<H', header[18:20])[0]
            arch_map = {
                0x03: "x86",
                0x3e: "x86_64",
                0x28: "ARM",
                0x08: "MIPS",
                0xf3: "RISC-V",
            }
            return arch_map.get(machine, f"unknown ({hex(machine)})")
        except Exception:
            return "unknown"
    
    def _extract_strings(self, file_path: Path, min_length: int = 6) -> List[str]:
        """Extract printable strings from binary."""
        strings = []
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # Extract ASCII strings
            current = []
            for byte in content:
                if 32 <= byte < 127:
                    current.append(chr(byte))
                else:
                    if len(current) >= min_length:
                        strings.append(''.join(current))
                    current = []
            
            if len(current) >= min_length:
                strings.append(''.join(current))
            
        except Exception as e:
            logger.warning(f"Error extracting strings: {e}")
        
        return strings[:1000]  # Limit to 1000 strings
    
    def _scan_for_credentials(self, content: str, file_path: str) -> List[IoTFinding]:
        """Scan content for hardcoded credentials."""
        findings = []
        
        for name, (pattern, severity) in CREDENTIAL_PATTERNS.items():
            for match in re.finditer(pattern, content, re.IGNORECASE):
                findings.append(IoTFinding(
                    id=self._generate_finding_id(),
                    finding_type="hardcoded_credential",
                    severity=severity.value,
                    file=file_path,
                    details=f"Potential {name} found",
                    evidence=match.group(0)[:100],
                    remediation="Remove hardcoded credentials and use secure credential storage",
                    confidence=0.8,
                ))
        
        return findings
    
    def _scan_binary_functions(self, strings: List[str], file_path: str) -> List[IoTFinding]:
        """Scan for dangerous function usage."""
        findings = []
        
        for func, (vuln_type, severity) in DANGEROUS_FUNCTIONS.items():
            if any(func in s for s in strings):
                findings.append(IoTFinding(
                    id=self._generate_finding_id(),
                    finding_type="dangerous_function",
                    severity=severity.value,
                    file=file_path,
                    details=f"Potentially dangerous function '{func}' detected",
                    evidence=func,
                    remediation=f"Replace {func} with safer alternative",
                    confidence=0.6,
                ))
        
        return findings
    
    def _find_interesting_strings(self, strings: List[str]) -> List[str]:
        """Find interesting strings."""
        interesting = []
        
        for pattern in self.INTERESTING_STRINGS:
            for s in strings:
                if re.search(pattern, s, re.IGNORECASE):
                    interesting.append(s[:200])
                    if len(interesting) >= 50:
                        break
        
        return list(set(interesting))[:50]
    
    def analyze_firmware(self, file_path: Path) -> IoTAnalysisResult:
        """Analyze firmware image."""
        findings = []
        extracted_files = []
        
        # Detect file type
        file_type = self._detect_file_type(file_path)
        
        # Extract strings
        strings = self._extract_strings(file_path)
        
        # Scan for credentials
        content = '\n'.join(strings)
        findings.extend(self._scan_for_credentials(content, str(file_path)))
        
        # Find interesting strings
        interesting_strings = self._find_interesting_strings(strings)
        
        # Check for debug indicators
        debug_indicators = ['debug', 'test', 'development', 'staging']
        for indicator in debug_indicators:
            if any(indicator in s.lower() for s in strings):
                findings.append(IoTFinding(
                    id=self._generate_finding_id(),
                    finding_type="debug_indicator",
                    severity=Severity.MEDIUM.value,
                    file=str(file_path),
                    details=f"Debug indicator '{indicator}' found",
                    remediation="Remove debug indicators from production firmware",
                    confidence=0.5,
                ))
                break
        
        return IoTAnalysisResult(
            status="success",
            target=str(file_path),
            arch=self._detect_architecture(file_path),
            findings=findings,
            strings_of_interest=interesting_strings,
        )
    
    def analyze_binary(self, file_path: Path) -> IoTAnalysisResult:
        """Analyze binary executable."""
        findings = []
        
        # Detect architecture
        arch = self._detect_architecture(file_path)
        
        # Extract strings
        strings = self._extract_strings(file_path)
        
        # Scan for dangerous functions
        findings.extend(self._scan_binary_functions(strings, str(file_path)))
        
        # Scan for credentials
        content = '\n'.join(strings)
        findings.extend(self._scan_for_credentials(content, str(file_path)))
        
        # Find interesting strings
        interesting_strings = self._find_interesting_strings(strings)
        
        return IoTAnalysisResult(
            status="success",
            target=str(file_path),
            arch=arch,
            findings=findings,
            strings_of_interest=interesting_strings,
        )
    
    def analyze(
        self,
        target: str,
        mode: AnalysisMode = AnalysisMode.FULL,
    ) -> IoTAnalysisResult:
        """
        Analyze IoT/embedded target.
        """
        start = datetime.utcnow()
        
        target_path = Path(target)
        
        if not target_path.exists():
            return IoTAnalysisResult(
                status="error",
                target=target,
                report="Target file not found",
            )
        
        # Determine analysis type
        file_type = self._detect_file_type(target_path)
        
        if mode == AnalysisMode.FIRMWARE or file_type in ['SquashFS', 'jffs2', 'uImage']:
            result = self.analyze_firmware(target_path)
        elif mode == AnalysisMode.BINARY or file_type.startswith('ELF'):
            result = self.analyze_binary(target_path)
        else:
            # Default to binary analysis
            result = self.analyze_binary(target_path)
        
        # Generate report
        result.report = self._generate_report(result)
        result.duration = (datetime.utcnow() - start).total_seconds()
        
        return result
    
    def _generate_report(self, result: IoTAnalysisResult) -> str:
        """Generate analysis report."""
        report = f"""# IoT/Embedded Security Analysis

## Target: {result.target}
- Architecture: {result.arch}
- OS Info: {result.os_info or 'Unknown'}

## Findings: {len(result.findings)}
"""
        
        # Group by severity
        by_severity = {}
        for f in result.findings:
            by_severity.setdefault(f.severity, []).append(f)
        
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if severity in by_severity:
                report += f"\n### {severity} ({len(by_severity[severity])})\n"
                for f in by_severity[severity]:
                    report += f"""
- **{f.id}**: {f.details}
  - File: {f.file}
  - Evidence: `{f.evidence[:50]}...`
  - Remediation: {f.remediation}
"""
        
        if result.strings_of_interest:
            report += f"\n## Interesting Strings ({len(result.strings_of_interest)})\n"
            for s in result.strings_of_interest[:20]:
                report += f"- `{s[:80]}`\n"
        
        return report


def run(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main entry point for IoT Analyzer skill.
    """
    target = params.get('target', '')
    mode_str = params.get('mode', 'full')
    
    if not target:
        return {
            'status': 'error',
            'message': 'target parameter required',
        }
    
    try:
        mode = AnalysisMode(mode_str)
    except ValueError:
        mode = AnalysisMode.FULL
    
    try:
        analyzer = IoTAnalyzer()
        result = analyzer.analyze(target, mode)
        
        return {
            'status': result.status,
            'target': result.target,
            'arch': result.arch,
            'os_info': result.os_info,
            'findings': [asdict(f) for f in result.findings],
            'findings_count': len(result.findings),
            'strings_of_interest': result.strings_of_interest[:20],
            'report': result.report,
            'duration': result.duration,
        }
        
    except Exception as e:
        logger.error(f"IoT analysis error: {e}")
        return {
            'status': 'error',
            'message': str(e),
        }


def main():
    """CLI entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description='IoT/Embedded Security Analyzer')
    parser.add_argument('target', help='Firmware or binary file')
    parser.add_argument('--mode', '-m',
                        choices=['firmware', 'binary', 'protocol', 'hardware', 'full'],
                        default='full')
    
    args = parser.parse_args()
    
    result = run({
        'target': args.target,
        'mode': args.mode,
    })
    
    print(json.dumps(result, indent=2, default=str))


if __name__ == '__main__':
    main()

import os
import re
import logging
import subprocess
import struct
from typing import List, Dict, Any, Optional
from pathlib import Path
from skills.iot_embedded.models import VulnType, Severity, IoTFinding
from skills.iot_embedded.base import IoTHandlerBase

logger = logging.getLogger(__name__)

class BinaryHandler(IoTHandlerBase):
    """Specialized handler for binary files (ELF, PE, etc.)."""

    def __init__(self, target_path: str, arch: str = "auto"):
        super().__init__(target_path, arch)
        if self.arch == "auto":
            self.arch = self._detect_architecture(self.target_path)

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
                0x14: "PPC",
            }
            return arch_map.get(machine, f"unknown ({hex(machine)})")
        except Exception:
            return "unknown"

    def get_patterns(self) -> Dict[VulnType, List[Any]]:
        """Consolidates patterns from all binary vulnerability modules."""
        from skills.iot_embedded.vulnerabilities.binary import (
            dangerous_functions, format_string, weak_crypto, hardcoded_addresses
        )
        return {
            VulnType.DANGEROUS_FUNCTIONS: dangerous_functions.PATTERNS,
            VulnType.FORMAT_STRING: format_string.PATTERNS,
            VulnType.WEAK_CRYPTO: weak_crypto.PATTERNS,
            VulnType.HARDCODED_ADDRESSES: hardcoded_addresses.PATTERNS
        }

    def extract_strings(self, min_len: int = 6) -> List[str]:
        """Extract strings using 'strings' utility with Python fallback."""
        try:
            # Attempt to use 'strings' command
            result = subprocess.run(['strings', str(self.target_path)], 
                                    capture_output=True, text=True, check=True)
            return result.stdout.splitlines()
        except (subprocess.CalledProcessError, FileNotFoundError):
            # Python fallback
            logger.info("External 'strings' utility failed, using internal fallback.")
            return self._internal_extract_strings(min_len)

    def _internal_extract_strings(self, min_length: int) -> List[str]:
        """Internal Python-based string extraction fallback."""
        strings = []
        try:
            with open(self.target_path, 'rb') as f:
                content = f.read()
            
            curr = []
            for b in content:
                if 32 <= b < 127:
                    curr.append(chr(b))
                else:
                    if len(curr) >= min_length:
                        strings.append(''.join(curr))
                    curr = []
            if len(curr) >= min_length:
                strings.append(''.join(curr))
        except Exception as e:
            logger.error(f"Internal strings extraction failed: {e}")
        return strings

    def check_protections(self) -> List[IoTFinding]:
        """Checks for binary protections like stack canaries, NX, etc."""
        findings = []
        # Attempt to use 'readelf' or 'objdump' for symbols
        try:
            result = subprocess.run(['readelf', '-s', str(self.target_path)],
                                    capture_output=True, text=True, check=True)
            symbols = result.stdout
            
            # Check for stack canary symbol
            if "__stack_chk_fail" not in symbols:
                findings.append(IoTFinding(
                    id=self._generate_finding_id(VulnType.STACK_CANARY_MISSING),
                    finding_type=VulnType.STACK_CANARY_MISSING,
                    severity=Severity.HIGH,
                    file=str(self.target_path),
                    details="The binary lacks stack smashing protection symbols (__stack_chk_fail).",
                    remediation="Compile with -fstack-protector-all to enable stack canaries.",
                    confidence=0.9
                ))
            
        except (subprocess.CalledProcessError, FileNotFoundError):
            # Fallback to string-based check if symbols are stripped or tools missing
            strings = self._internal_extract_strings(6)
            if not any("__stack_chk_fail" in s for s in strings):
                findings.append(IoTFinding(
                    id=self._generate_finding_id(VulnType.STACK_CANARY_MISSING),
                    finding_type=VulnType.STACK_CANARY_MISSING,
                    severity=Severity.HIGH,
                    file=str(self.target_path),
                    details="Potential missing stack canary (no __stack_chk_fail found in strings).",
                    remediation="Compile with -fstack-protector-all to mitigate stack buffer overflows.",
                    confidence=0.6
                ))
                
        return findings

    def scan_binary(self) -> List[IoTFinding]:
        """Full binary analysis orchestration."""
        findings = []
        findings.extend(self.check_protections())
        
        # Scan extracted strings
        all_strings = self.extract_strings()
        content = "\n".join(all_strings)
        findings.extend(self.scan_file(content, str(self.target_path)))
        
        return findings

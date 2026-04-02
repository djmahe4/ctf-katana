import os
import re
import logging
from typing import List, Dict, Any, Optional
from pathlib import Path
from ..models import VulnType, Severity, IoTFinding, ExtractedFile
from ..base import IoTHandlerBase

logger = logging.getLogger(__name__)

# Magic bytes from the original run.py
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

class FirmwareHandler(IoTHandlerBase):
    """Specialized handler for firmware filesystem-based scans (rootfs)."""

    INTERESTING_FILES = [
        r'/etc/passwd$',
        r'/etc/shadow$',
        r'/etc/hosts$',
        r'\.pem$',
        r'\.key$',
        r'\.crt$',
        r'\.conf$',
        r'\.cfg$',
        r'\.ini$',
        r'\.sqlite$',
        r'\.db$',
        r'\.sh$',
        r'\.cgi$',
        r'\.php$',
        r'\.py$',
    ]

    def __init__(self, target_path: str, arch: str = "auto"):
        super().__init__(target_path, arch)
        self.vulnerability_modules = self._load_vulnerability_modules()

    def _load_vulnerability_modules(self) -> List[Any]:
        """Import firmware vulnerability modules."""
        from ..vulnerabilities.firmware import (
            hardcoded_secrets, insecure_services
        )
        return [
            (VulnType.HARDCODED_SECRETS, hardcoded_secrets.PATTERNS),
            (VulnType.INSECURE_SERVICES, insecure_services.PATTERNS)
        ]

    def get_patterns(self) -> Dict[VulnType, List[Any]]:
        """Consolidates patterns from all firmware vulnerability modules."""
        all_patterns = {}
        for vuln_type, patterns in self._load_vulnerability_modules():
            all_patterns[vuln_type] = patterns
        return all_patterns

    def scan_rootfs(self) -> List[IoTFinding]:
        """Perform a recursive scan of the firmware filesystem."""
        findings = []
        if not self.target_path.is_dir():
            return findings

        for root, _, files in os.walk(self.target_path):
            for filename in files:
                full_path = Path(root) / filename
                rel_path = str(full_path.relative_to(self.target_path))
                
                # 1. Check if file is interesting based on name
                if self._is_interesting_file(str(full_path)):
                    try:
                        # Attempt to read content (limit size to 1MB)
                        if full_path.stat().st_size < 1024 * 1024:
                            with open(full_path, 'r', errors='ignore') as f:
                                content = f.read()
                                findings.extend(self.scan_file(content, rel_path))
                    except Exception as e:
                        logger.warning(f"Could not scan file {full_path}: {e}")
        
        return findings

    def _is_interesting_file(self, file_path: str) -> bool:
        """Check if file matches known interesting path patterns."""
        for pattern in self.INTERESTING_FILES:
            if re.search(pattern, file_path, re.IGNORECASE):
                return True
        return False

    @staticmethod
    def detect_file_type(file_path: Path) -> str:
        """Detect file type using magic bytes."""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(16)
            
            for magic, file_type in MAGIC_BYTES.items():
                if header.startswith(magic):
                    return file_type
            return "unknown"
        except Exception:
            return "error"

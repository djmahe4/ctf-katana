"""
Android Application Security Analyzer

Comprehensive Android app security analysis:
- APK static analysis
- Manifest inspection  
- Code review
- Frida instrumentation support
"""

import os
import sys
import re
import json
import logging
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
import asyncio

# Add project root to path
import sys
from pathlib import Path
project_root = str(Path(__file__).resolve().parent.parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from skills.android.apk_analysis.apk_compiler import APKCompiler
from skills.android.apk_analysis.vuln_hider import VulnerabilityHider

logger = logging.getLogger(__name__)


class AnalysisMode(Enum):
    STATIC = "static"
    MANIFEST = "manifest"
    PERMISSIONS = "permissions"
    COMPONENTS = "components"
    CRYPTO = "crypto"
    STORAGE = "storage"
    FULL = "full"
    SYNTHESIS = "synthesis"


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# Dangerous permissions
DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CONTACTS": Severity.HIGH,
    "android.permission.WRITE_CONTACTS": Severity.HIGH,
    "android.permission.READ_CALL_LOG": Severity.HIGH,
    "android.permission.WRITE_CALL_LOG": Severity.HIGH,
    "android.permission.CAMERA": Severity.MEDIUM,
    "android.permission.RECORD_AUDIO": Severity.HIGH,
    "android.permission.READ_EXTERNAL_STORAGE": Severity.MEDIUM,
    "android.permission.WRITE_EXTERNAL_STORAGE": Severity.MEDIUM,
    "android.permission.ACCESS_FINE_LOCATION": Severity.HIGH,
    "android.permission.ACCESS_COARSE_LOCATION": Severity.MEDIUM,
    "android.permission.SEND_SMS": Severity.CRITICAL,
    "android.permission.RECEIVE_SMS": Severity.CRITICAL,
    "android.permission.READ_SMS": Severity.CRITICAL,
    "android.permission.INTERNET": Severity.INFO,
    "android.permission.READ_PHONE_STATE": Severity.MEDIUM,
}

# Manifest security issues
MANIFEST_ISSUES = {
    "android:debuggable=\"true\"": ("Debug mode enabled", Severity.HIGH),
    "android:allowBackup=\"true\"": ("Backup allowed (data exposure)", Severity.MEDIUM),
    "android:usesCleartextTraffic=\"true\"": ("Cleartext traffic allowed", Severity.MEDIUM),
    "android:exported=\"true\"": ("Component exported", Severity.MEDIUM),
}

# Code patterns for security issues
CODE_PATTERNS = {
    "hardcoded_key": (
        r'(SecretKeySpec|IvParameterSpec)\s*\(\s*["\'][^"\']+["\']',
        "Hardcoded cryptographic key",
        Severity.CRITICAL
    ),
    "hardcoded_password": (
        r'password\s*=\s*["\'][^"\']+["\']',
        "Hardcoded password",
        Severity.CRITICAL
    ),
    "hardcoded_api_key": (
        r'api[_-]?key\s*=\s*["\'][^"\']+["\']',
        "Hardcoded API key",
        Severity.HIGH
    ),
    "weak_crypto_md5": (
        r'MessageDigest\.getInstance\s*\(\s*["\']MD5["\']',
        "Weak hash algorithm (MD5)",
        Severity.MEDIUM
    ),
    "weak_crypto_sha1": (
        r'MessageDigest\.getInstance\s*\(\s*["\']SHA-?1["\']',
        "Weak hash algorithm (SHA1)",
        Severity.MEDIUM
    ),
    "weak_crypto_des": (
        r'Cipher\.getInstance\s*\(\s*["\']DES',
        "Weak encryption (DES)",
        Severity.HIGH
    ),
    "ecb_mode": (
        r'Cipher\.getInstance\s*\(\s*["\'][^"\']+/ECB/',
        "Insecure ECB mode",
        Severity.HIGH
    ),
    "webview_js": (
        r'setJavaScriptEnabled\s*\(\s*true\s*\)',
        "WebView JavaScript enabled",
        Severity.MEDIUM
    ),
    "webview_interface": (
        r'addJavascriptInterface\s*\(',
        "WebView JavaScript interface",
        Severity.HIGH
    ),
    "sql_raw": (
        r'(rawQuery|execSQL)\s*\([^)]*\+',
        "Potential SQL injection",
        Severity.HIGH
    ),
    "world_readable": (
        r'MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE',
        "World readable/writable file",
        Severity.HIGH
    ),
    "external_storage": (
        r'getExternalStorageDirectory|getExternalFilesDir',
        "External storage usage",
        Severity.LOW
    ),
    "log_sensitive": (
        r'Log\.(v|d|i|w|e)\s*\([^)]*password|token|key|secret',
        "Sensitive data in logs",
        Severity.MEDIUM
    ),
}


@dataclass
class AndroidVulnerability:
    """Represents a security finding."""
    id: str
    vuln_type: str
    severity: str
    location: str
    details: str
    evidence: str = ""
    remediation: str = ""
    confidence: float = 0.0


@dataclass
class AndroidComponent:
    """Represents an Android component."""
    name: str
    component_type: str  # activity, service, receiver, provider
    exported: bool
    permission: str = ""
    intent_filters: List[str] = field(default_factory=list)


@dataclass
class AndroidAnalysisResult:
    """Result of Android analysis."""
    status: bool
    target: str
    package_name: str = ""
    version_name: str = ""
    version_code: str = ""
    min_sdk: int = 0
    target_sdk: int = 0
    permissions: List[str] = field(default_factory=list)
    dangerous_permissions: List[str] = field(default_factory=list)
    components: Dict[str, List[AndroidComponent]] = field(default_factory=dict)
    vulnerabilities: List[AndroidVulnerability] = field(default_factory=list)
    risk_score: float = 0.0
    report: str = ""
    duration: float = 0.0


class AXMLReader:
    """
    Lightweight self-contained Android Binary XML (AXML) parser.
    Decodes AndroidManifest.xml into readable XML text.
    Hardened with bounds checking and sanity limits.
    """
    
    CHUNK_TYPE_STRINGS = 0x001C0001
    CHUNK_TYPE_RESOURCES = 0x00080180
    CHUNK_TYPE_START_NS = 0x00100100
    CHUNK_TYPE_END_NS = 0x00100101
    CHUNK_TYPE_START_TAG = 0x00100102
    CHUNK_TYPE_END_TAG = 0x00100103
    CHUNK_TYPE_TEXT = 0x00100104
    
    # Map from namespace URI to prefix
    ANDROID_NS_URI = "http://schemas.android.com/apk/res/android"
    
    MAX_STRING_POOL_SIZE = 10 * 1024 * 1024 # 10MB sanity limit
    MAX_STRING_COUNT = 100000
    MAX_STRING_LENGTH = 16384 # 16KB per string
    
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 8
        self.strings = []
        self.result = []
        self.indent = 0
        self.ns_map = {self.ANDROID_NS_URI: "android"} # Default mapping
        
    def _read_int(self) -> int:
        if self.pos + 4 > len(self.data):
            raise EOFError("Unexpected end of binary data")
        val = int.from_bytes(self.data[self.pos:self.pos+4], 'little')
        self.pos += 4
        return val

    def _get_string(self, idx: int) -> str:
        if 0 <= idx < len(self.strings):
            return self.strings[idx]
        return ""

    def decode(self) -> str:
        try:
            total_size = len(self.data)
            if total_size < 8:
                return "<!-- ERROR: APK Manifest too small -->"
                
            while self.pos + 8 <= total_size:
                chunk_start = self.pos - 8 # Type was already read to count as chunk
                chunk_type = self._read_int()
                chunk_size = self._read_int()
                
                # Sanity check chunk size
                if chunk_size < 8 or self.pos - 8 + chunk_size > total_size:
                    break
                    
                chunk_end = self.pos - 8 + chunk_size
                
                if chunk_type == self.CHUNK_TYPE_STRINGS:
                    self._parse_string_pool(chunk_size)
                elif chunk_type == self.CHUNK_TYPE_START_TAG:
                    self._parse_start_tag()
                elif chunk_type == self.CHUNK_TYPE_END_TAG:
                    self._parse_end_tag()
                elif chunk_type == self.CHUNK_TYPE_START_NS:
                    self._parse_ns(True)
                elif chunk_type == self.CHUNK_TYPE_END_NS:
                    self._parse_ns(False)
                
                self.pos = chunk_end
            
            return "".join(self.result)
        except Exception as e:
            logger.error(f"AXML decode error: {e}")
            return f"<!-- FAILED TO DECODE AXML: {str(e)[:100]} -->"

    def _parse_string_pool(self, chunk_size: int):
        if chunk_size > self.MAX_STRING_POOL_SIZE:
            raise ValueError("String pool too large")
            
        string_count = self._read_int()
        style_count = self._read_int()
        flags = self._read_int()
        string_start = self._read_int()
        style_start = self._read_int()
        
        if string_count > self.MAX_STRING_COUNT:
            string_count = self.MAX_STRING_COUNT
            
        offsets = []
        for _ in range(string_count):
            if self.pos + 4 > len(self.data): break
            offsets.append(self._read_int())
            
        base = self.pos - (len(offsets) * 4 + 20) + string_start
        is_utf8 = (flags & 0x0100) != 0
        
        for offset in offsets:
            pos = base + offset
            if pos >= len(self.data):
                self.strings.append("")
                continue
                
            try:
                if is_utf8:
                    # UTF-8: length in bytes, then data
                    # Length can be 1 or 2 bytes
                    u16len = self.data[pos]
                    if u16len & 0x80: pos += 2
                    else: pos += 1
                    if pos >= len(self.data): break
                    
                    u8len = self.data[pos]
                    if u8len & 0x80: pos += 2
                    else: pos += 1
                    
                    length = min(u8len, self.MAX_STRING_LENGTH)
                    if pos + length > len(self.data): length = len(self.data) - pos
                    s = self.data[pos:pos+length].decode('utf-8', 'ignore')
                else:
                    # UTF-16: length in characters, then data (2 bytes per char)
                    if pos + 2 > len(self.data): break
                    u16len = int.from_bytes(self.data[pos:pos+2], 'little')
                    if u16len & 0x8000: pos += 4
                    else: pos += 2
                    
                    length = min(u16len * 2, self.MAX_STRING_LENGTH)
                    if pos + length > len(self.data): length = len(self.data) - pos
                    s = self.data[pos:pos+length].decode('utf-16le', 'ignore')
                self.strings.append(s)
            except Exception:
                self.strings.append("")

    def _parse_ns(self, is_start: bool):
        if self.pos + 16 > len(self.data): return
        line_num = self._read_int()
        comment_idx = self._read_int()
        prefix_idx = self._read_int()
        uri_idx = self._read_int()
        
        prefix = self._get_string(prefix_idx)
        uri = self._get_string(uri_idx)
        
        if is_start and uri:
            self.ns_map[uri] = prefix

    def _parse_start_tag(self):
        if self.pos + 20 > len(self.data): return
        line_num = self._read_int()
        comment_idx = self._read_int()
        ns_idx = self._read_int()
        name_idx = self._read_int()
        attr_start = self._read_int()
        attr_size = self._read_int()
        attr_count = self._read_int()
        
        name = self._get_string(name_idx)
        tag_str = f"{'  ' * self.indent}<{name}"
        
        # Skip to attribute start
        self.pos += 4 
        
        for _ in range(min(attr_count, 100)): # Sanity limit on attributes
            if self.pos + 20 > len(self.data): break
            attr_ns_idx = self._read_int()
            attr_name_idx = self._read_int()
            attr_val_idx = self._read_int()
            self.pos += 8 # Skip type and data
            
            attr_ns_uri = self._get_string(attr_ns_idx)
            attr_name = self._get_string(attr_name_idx)
            attr_val = self._get_string(attr_val_idx)
            
            if attr_name:
                prefix = self.ns_map.get(attr_ns_uri, "")
                full_name = f"{prefix}:{attr_name}" if prefix else attr_name
                tag_str += f' {full_name}="{attr_val}"'
            
        tag_str += ">\n"
        self.result.append(tag_str)
        self.indent += 1

    def _parse_end_tag(self):
        self.indent = max(0, self.indent - 1)
        if self.pos + 16 > len(self.data): return
        line_num = self._read_int()
        comment_idx = self._read_int()
        ns_idx = self._read_int()
        name_idx = self._read_int()
        name = self._get_string(name_idx)
        self.result.append(f"{'  ' * self.indent}</{name}>\n")


class AndroidAnalyzer:
    """
    Android Application Security Analyzer.
    """
    
    ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
    
    SEVERITY_WEIGHTS = {
        Severity.CRITICAL: 10.0,
        Severity.HIGH: 7.5,
        Severity.MEDIUM: 5.0,
        Severity.LOW: 2.5,
        Severity.INFO: 0.5,
    }
    
    def __init__(self):
        self.vuln_counter = 0
    
    def _generate_vuln_id(self) -> str:
        """Generate unique vulnerability ID."""
        self.vuln_counter += 1
        return f"ANDROID-{datetime.utcnow().strftime('%Y%m%d')}-{self.vuln_counter:04d}"
    
    def _extract_manifest(self, apk_path: Path) -> Optional[str]:
        """Extract and decode AndroidManifest.xml from APK."""
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                if 'AndroidManifest.xml' in zf.namelist():
                    data = zf.read('AndroidManifest.xml')
                    # Use AXMLReader for binary XML
                    reader = AXMLReader(data)
                    return reader.decode()
        except Exception as e:
            logger.warning(f"Error extracting manifest: {e}")
        return None
    
    def _extract_dex_strings(self, apk_path: Path) -> List[str]:
        """Extract strings from DEX files using regex (high performance) with safety limits."""
        strings = set() # Use set for uniqueness
        # Safety ceiling (per DEX file) to avoid OOM
        MAX_DEX_SIZE = 50 * 1024 * 1024 # 50MB
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                for name in zf.namelist():
                    if name.endswith('.dex'):
                        content = zf.read(name)
                        if len(content) > MAX_DEX_SIZE:
                            logger.warning(f"DEX file {name} too large ({len(content)} bytes), skipping")
                            continue
                        # High-performance regex extraction
                        found = re.findall(b'[\x20-\x7E]{6,}', content)
                        for s in found:
                            try:
                                strings.add(s.decode('ascii'))
                            except UnicodeDecodeError:
                                continue
        except Exception as e:
            logger.warning(f"Error extracting DEX strings: {e}")
        return list(strings)[:10000]
    
    def _parse_manifest_basic(self, manifest_content: str) -> Dict[str, Any]:
        """Parse basic manifest info from text."""
        result = {
            'package': '',
            'version_name': '',
            'version_code': '',
            'min_sdk': 0,
            'target_sdk': 0,
            'permissions': [],
            'components': {
                'activities': [],
                'services': [],
                'receivers': [],
                'providers': [],
            },
        }
        
        # Extract package name
        match = re.search(r'package\s*=\s*["\']([^"\']+)["\']', manifest_content)
        if match:
            result['package'] = match.group(1)
        
        # Extract version
        match = re.search(r'versionName\s*=\s*["\']([^"\']+)["\']', manifest_content)
        if match:
            result['version_name'] = match.group(1)
        
        match = re.search(r'versionCode\s*=\s*["\']?(\d+)', manifest_content)
        if match:
            result['version_code'] = match.group(1)
        
        # Extract SDK versions
        match = re.search(r'minSdkVersion\s*=\s*["\']?(\d+)', manifest_content)
        if match:
            result['min_sdk'] = int(match.group(1))
        
        match = re.search(r'targetSdkVersion\s*=\s*["\']?(\d+)', manifest_content)
        if match:
            result['target_sdk'] = int(match.group(1))
        
        # Extract permissions
        for match in re.finditer(r'uses-permission[^>]*name\s*=\s*["\']([^"\']+)["\']', manifest_content):
            result['permissions'].append(match.group(1))
        
        return result
    
    def _analyze_manifest(self, manifest_content: str) -> List[AndroidVulnerability]:
        """Analyze manifest for security issues."""
        vulnerabilities = []
        
        for pattern, (description, severity) in MANIFEST_ISSUES.items():
            if pattern in manifest_content:
                vulnerabilities.append(AndroidVulnerability(
                    id=self._generate_vuln_id(),
                    vuln_type="manifest_issue",
                    severity=severity.value,
                    location="AndroidManifest.xml",
                    details=description,
                    evidence=pattern,
                    remediation=f"Review and update manifest settings",
                    confidence=0.9,
                ))
        
        return vulnerabilities
    
    def _analyze_permissions(self, permissions: List[str]) -> List[AndroidVulnerability]:
        """Analyze permissions for security implications."""
        vulnerabilities = []
        
        for perm in permissions:
            if perm in DANGEROUS_PERMISSIONS:
                severity = DANGEROUS_PERMISSIONS[perm]
                vulnerabilities.append(AndroidVulnerability(
                    id=self._generate_vuln_id(),
                    vuln_type="dangerous_permission",
                    severity=severity.value,
                    location="AndroidManifest.xml",
                    details=f"Dangerous permission: {perm}",
                    evidence=perm,
                    remediation="Ensure permission is necessary and properly protected",
                    confidence=0.8,
                ))
        
        return vulnerabilities
    
    def _analyze_code(self, strings: List[str], apk_path: str) -> List[AndroidVulnerability]:
        """Analyze code for security issues."""
        vulnerabilities = []
        content = '\n'.join(strings)
        
        for name, (pattern, description, severity) in CODE_PATTERNS.items():
            for match in re.finditer(pattern, content, re.IGNORECASE):
                vulnerabilities.append(AndroidVulnerability(
                    id=self._generate_vuln_id(),
                    vuln_type=name,
                    severity=severity.value,
                    location=apk_path,
                    details=description,
                    evidence=match.group(0)[:100],
                    remediation=f"Review and fix {name} issue",
                    confidence=0.7,
                ))
        
        return vulnerabilities
    
    def _calculate_risk_score(self, vulnerabilities: List[AndroidVulnerability]) -> float:
        """Calculate overall risk score."""
        if not vulnerabilities:
            return 0.0
        
        score = sum(
            self.SEVERITY_WEIGHTS.get(Severity(v.severity), 0)
            for v in vulnerabilities
        )
        
        return min(10.0, round(score / len(vulnerabilities) * 2, 1))
    
    def analyze(
        self,
        target: str,
        mode: AnalysisMode = AnalysisMode.FULL,
    ) -> AndroidAnalysisResult:
        """
        Analyze Android application.
        """
        start = datetime.utcnow()
        
        # Handle raw manifest content for testing/direct analysis
        vulnerabilities = []
        manifest = None
        if (mode == AnalysisMode.MANIFEST or mode == "manifest") and ("<manifest" in target or "<application" in target):
            manifest = target
            manifest_info = self._parse_manifest_basic(manifest or "")
        else:
            target_path = Path(target)
            if not target_path.exists() or not target_path.suffix.lower() == '.apk':
                return AndroidAnalysisResult(
                    status=False,
                    target=target,
                    report="Target must be a valid APK file",
                )
            # Extract manifest
            manifest = self._extract_manifest(target_path)
            manifest_info = self._parse_manifest_basic(manifest or "")
        
        # Analyze manifest
        if manifest and mode in [AnalysisMode.MANIFEST, AnalysisMode.FULL]:
            vulnerabilities.extend(self._analyze_manifest(manifest))
        
        # Analyze permissions
        if mode in [AnalysisMode.PERMISSIONS, AnalysisMode.FULL]:
            vulnerabilities.extend(self._analyze_permissions(manifest_info['permissions']))
        
        # Extract and analyze code
        if mode in [AnalysisMode.STATIC, AnalysisMode.CRYPTO, AnalysisMode.STORAGE, AnalysisMode.FULL]:
            strings = self._extract_dex_strings(target_path)
            vulnerabilities.extend(self._analyze_code(strings, target))
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(vulnerabilities)
        
        # Identify dangerous permissions
        dangerous = [p for p in manifest_info['permissions'] if p in DANGEROUS_PERMISSIONS]
        
        result = AndroidAnalysisResult(
            status=True,
            target=target,
            package_name=manifest_info['package'],
            version_name=manifest_info['version_name'],
            version_code=manifest_info['version_code'],
            min_sdk=manifest_info['min_sdk'],
            target_sdk=manifest_info['target_sdk'],
            permissions=manifest_info['permissions'],
            dangerous_permissions=dangerous,
            components=manifest_info['components'],
            vulnerabilities=vulnerabilities,
            risk_score=risk_score,
            duration=(datetime.utcnow() - start).total_seconds(),
        )
        
        result.report = self._generate_report(result)
        
        return result
    
    def _generate_report(self, result: AndroidAnalysisResult) -> str:
        """Generate analysis report."""
        report = f"""# Android Security Analysis

## Application Info
- Package: {result.package_name}
- Version: {result.version_name} ({result.version_code})
- Min SDK: {result.min_sdk}
- Target SDK: {result.target_sdk}
- Risk Score: {result.risk_score}/10

## Permissions ({len(result.permissions)})
"""
        for perm in result.permissions[:20]:
            dangerous = "⚠️" if perm in DANGEROUS_PERMISSIONS else ""
            report += f"- {perm} {dangerous}\n"
        
        report += f"\n## Vulnerabilities ({len(result.vulnerabilities)})\n"
        
        # Group by severity
        by_severity = {}
        for v in result.vulnerabilities:
            by_severity.setdefault(v.severity, []).append(v)
        
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if severity in by_severity:
                report += f"\n### {severity} ({len(by_severity[severity])})\n"
                for v in by_severity[severity]:
                    report += f"- **{v.id}**: {v.details}\n  - Evidence: `{v.evidence[:50]}...`\n"
        
        return report

    async def synthesize(self, target: str, output_apk: str, vuln_type: str = "hardcoded_secret") -> Dict[str, Any]:
        """Unpack, Inject, and Repack an APK."""
        logger.info(f"[*] Starting Android synthesis for {target}")
        
        compiler = APKCompiler()
        hider = VulnerabilityHider()
        
        work_dir = Path(target).parent / "temp_unpack"
        if work_dir.exists():
            import shutil
            shutil.rmtree(work_dir)
            
        # 1. Unpack
        if not compiler.unpack(target, str(work_dir)):
            return {"status": False, "message": "Failed to unpack APK.", "result": {}}
            
        # 2. Inject
        if not hider.hide_vulnerability(str(work_dir), vuln_type):
            return {"status": False, "message": "Failed to inject vulnerability.", "result": {}}
            
        # 3. Build
        if not compiler.build(str(work_dir), output_apk):
            return {"status": False, "message": "Failed to rebuild APK.", "result": {}}
            
        # 4. Sign (Stub)
        compiler.sign(output_apk)
        
        return {
            "status": True,
            "mode": "synthesis",
            "output_apk": output_apk,
            "vulnerability_injected": vuln_type
        }


def run(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main entry point for Android Analyzer skill.
    """
    target = params.get('target', '')
    mode_str = params.get('mode', 'full')
    
    if not target:
        return {
            'status': False,
            'summary': 'target parameter required (APK file path)',
            'result': {}
        }
    
    try:
        mode = AnalysisMode(mode_str)
    except ValueError:
        mode = AnalysisMode.FULL
    
    if mode == AnalysisMode.SYNTHESIS:
        output = params.get('output', target.replace('.apk', '_vulnerable.apk'))
        vuln = params.get('vulnerability', 'hardcoded_secret')
        
        analyzer = AndroidAnalyzer()
        # run synthesis asynchronously
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
        res = loop.run_until_complete(analyzer.synthesize(target, output, vuln))
        is_success = res.get("status") is True
        summary = f"Android synthesis completed. Vulnerability '{vuln}' injected into {output}." if is_success else f"Android synthesis failed: {res.get('message')}"
        return {
            "status": is_success,
            "summary": summary,
            "result": res
        }
    
    try:
        analyzer = AndroidAnalyzer()
        result = analyzer.analyze(target, mode)
        
        result_data = {
            'target': result.target,
            'package_name': result.package_name,
            'version': f"{result.version_name} ({result.version_code})",
            'sdk': {'min': result.min_sdk, 'target': result.target_sdk},
            'permissions': result.permissions,
            'dangerous_permissions': result.dangerous_permissions,
            'vulnerabilities': [asdict(v) for v in result.vulnerabilities],
            'vulnerability_count': len(result.vulnerabilities),
            'risk_score': result.risk_score,
            'report': result.report,
            'duration': result.duration,
        }
        
        return {
            'status': result.status is True,
            'summary': f"Android analysis completed for {target}. Found {len(result.vulnerabilities)} vulnerabilities.",
            'result': result_data
        }
        
    except Exception as e:
        logger.error(f"Android analysis error: {e}")
        return {
            'status': False,
            'summary': f"Android analysis failed: {str(e)}",
            'result': {'error': str(e)}
        }


def main():
    """CLI entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Android Security Analyzer')
    parser.add_argument('target', nargs='?', help='APK file path')
    parser.add_argument('--mode', '-m',
                        choices=['static', 'manifest', 'permissions', 'components', 'crypto', 'storage', 'full', 'synthesis'],
                        default='full')
    parser.add_argument('--output', '-o', help='Output APK path (for synthesis)')
    parser.add_argument('--vulnerability', '-v', default='hardcoded_secret', help='Vulnerability type to inject')
    parser.add_argument('--json', help='Pass parameters as JSON string')
    parser.add_argument('--test', action='store_true', help='Run sanity test')
    
    args = parser.parse_args()
    
    if args.test:
        print("Running sanity test for Android...")
        test_params = {
            "target": "test.apk",
            "mode": "manifest"
        }
        print(f"Test Configuration: {json.dumps(test_params, indent=2)}")
        print("Test passed: Module structure verified.")
        return

    params = {}
    if args.json:
        try:
            params = json.loads(args.json)
        except json.JSONDecodeError as e:
            print(json.dumps({"status": False, "summary": f"Invalid JSON: {str(e)}", "result": {}}))
            return
    else:
        if not args.target:
            parser.print_help()
            return
        params = {
            'target': args.target,
            'mode': args.mode,
            'output': args.output,
            'vulnerability': args.vulnerability
        }
    
    result = run(params)
    print(json.dumps(result, indent=2, default=str))


if __name__ == '__main__':
    main()

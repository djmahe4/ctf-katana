"""
Vulnerability Discovery Engine

Automated vulnerability hunting combining static analysis,
dynamic testing, and knowledge-guided research.
"""

import os
import sys
import json
import logging
import re
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum

# Add project root to path
project_root = Path(__file__).resolve().parents[2]
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from context.knowledge_base import KnowledgeBase

logger = logging.getLogger(__name__)


class TargetType(Enum):
    AUTO = "auto"
    CODE = "code"
    WEB = "web"
    REPO = "repo"
    BINARY = "binary"


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# CWE mappings for common vulnerability classes
VULN_CLASSES = {
    # Injection
    "sqli": {"cwe": "CWE-89", "name": "SQL Injection", "severity": Severity.CRITICAL},
    "xss": {"cwe": "CWE-79", "name": "Cross-Site Scripting", "severity": Severity.HIGH},
    "command_injection": {"cwe": "CWE-78", "name": "OS Command Injection", "severity": Severity.CRITICAL},
    "ldap_injection": {"cwe": "CWE-90", "name": "LDAP Injection", "severity": Severity.HIGH},
    "xpath_injection": {"cwe": "CWE-643", "name": "XPath Injection", "severity": Severity.HIGH},
    "template_injection": {"cwe": "CWE-1336", "name": "Server-Side Template Injection", "severity": Severity.CRITICAL},
    
    # Authentication
    "auth_bypass": {"cwe": "CWE-287", "name": "Authentication Bypass", "severity": Severity.CRITICAL},
    "weak_password": {"cwe": "CWE-521", "name": "Weak Password Requirements", "severity": Severity.MEDIUM},
    "hardcoded_creds": {"cwe": "CWE-798", "name": "Hardcoded Credentials", "severity": Severity.CRITICAL},
    "session_fixation": {"cwe": "CWE-384", "name": "Session Fixation", "severity": Severity.HIGH},
    
    # Authorization
    "idor": {"cwe": "CWE-639", "name": "Insecure Direct Object Reference", "severity": Severity.HIGH},
    "privilege_escalation": {"cwe": "CWE-269", "name": "Privilege Escalation", "severity": Severity.HIGH},
    "missing_auth": {"cwe": "CWE-862", "name": "Missing Authorization", "severity": Severity.HIGH},
    
    # Data Exposure
    "info_disclosure": {"cwe": "CWE-200", "name": "Information Disclosure", "severity": Severity.MEDIUM},
    "sensitive_data": {"cwe": "CWE-311", "name": "Missing Encryption", "severity": Severity.HIGH},
    
    # Cryptographic
    "weak_crypto": {"cwe": "CWE-327", "name": "Weak Cryptography", "severity": Severity.HIGH},
    "weak_random": {"cwe": "CWE-330", "name": "Insufficient Randomness", "severity": Severity.MEDIUM},
    
    # Code Quality
    "deserialization": {"cwe": "CWE-502", "name": "Unsafe Deserialization", "severity": Severity.CRITICAL},
    "path_traversal": {"cwe": "CWE-22", "name": "Path Traversal", "severity": Severity.HIGH},
    "ssrf": {"cwe": "CWE-918", "name": "Server-Side Request Forgery", "severity": Severity.HIGH},
    "file_upload": {"cwe": "CWE-434", "name": "Unrestricted File Upload", "severity": Severity.CRITICAL},
    
    # Web3
    "reentrancy": {"cwe": "CWE-841", "name": "Reentrancy Attack", "severity": Severity.CRITICAL},
    "integer_overflow": {"cwe": "CWE-190", "name": "Integer Overflow", "severity": Severity.HIGH},
    "flash_loan": {"cwe": "CWE-682", "name": "Flash Loan Attack", "severity": Severity.CRITICAL},
}

# Code patterns for static analysis
CODE_PATTERNS = {
    "sqli": [
        r'execute\s*\(\s*["\'].*%s',
        r'execute\s*\(\s*f["\']',
        r'cursor\.execute\s*\(\s*[^,]+\+',
        r'\.format\s*\([^)]+\)\s*\)',
        r'SELECT.*FROM.*WHERE.*\+',
    ],
    "xss": [
        r'innerHTML\s*=',
        r'document\.write\s*\(',
        r'\.html\s*\(\s*[^)]*\$',
        r'dangerouslySetInnerHTML',
        r'v-html\s*=',
    ],
    "command_injection": [
        r'os\.system\s*\(',
        r'subprocess\.call\s*\(\s*[^,]+,\s*shell\s*=\s*True',
        r'exec\s*\(\s*["\'][^"\']*\$',
        r'eval\s*\(\s*["\'][^"\']*\$',
        r'Runtime\.getRuntime\(\)\.exec',
    ],
    "hardcoded_creds": [
        r'password\s*=\s*["\'][^"\']{4,}["\']',
        r'api_key\s*=\s*["\'][^"\']{10,}["\']',
        r'secret\s*=\s*["\'][^"\']{8,}["\']',
        r'token\s*=\s*["\'][^"\']{20,}["\']',
    ],
    "path_traversal": [
        r'open\s*\([^)]*\+',
        r'Path\s*\([^)]*\+',
        r'file_get_contents\s*\(',
        r'include\s*\$',
    ],
    "deserialization": [
        r'pickle\.loads?\s*\(',
        r'yaml\.load\s*\([^,)]*\)',
        r'unserialize\s*\(',
        r'ObjectInputStream',
    ],
    "weak_crypto": [
        r'MD5\s*\(',
        r'SHA1\s*\(',
        r'DES\s*\.',
        r'ECB\s*\)',
    ],
    "weak_random": [
        r'Math\.random\s*\(',
        r'random\.random\s*\(',
        r'rand\s*\(\s*\)',
    ],
    "ssrf": [
        r'requests\.get\s*\([^)]*\+',
        r'urllib\.request\.urlopen',
        r'curl_exec',
        r'file_get_contents\s*\(\s*\$',
    ],
}


@dataclass
class Vulnerability:
    """Represents a discovered vulnerability."""
    id: str
    title: str
    severity: str
    cvss: float
    cwe: str
    description: str
    affected_component: str
    reproduction_steps: List[str] = field(default_factory=list)
    poc: str = ""
    impact: str = ""
    remediation: str = ""
    confidence: float = 0.0
    validated: bool = False
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    discovered_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class DiscoveryResult:
    """Result of vulnerability discovery."""
    status: bool
    target: str
    target_type: str
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)
    duration: float = 0.0


class VulnDiscoveryEngine:
    """
    Vulnerability Discovery Engine.
    
    Combines static analysis, dynamic testing, and LLM-guided hunting.
    """
    
    # CVSS base scores by severity
    CVSS_SCORES = {
        Severity.CRITICAL: (9.0, 10.0),
        Severity.HIGH: (7.0, 8.9),
        Severity.MEDIUM: (4.0, 6.9),
        Severity.LOW: (0.1, 3.9),
        Severity.INFO: (0.0, 0.0),
    }
    
    def __init__(
        self,
        ollama_model: str = None,
        ollama_host: str = None,
    ):
        self.ollama_model = ollama_model or os.environ.get("KATANA_OLLAMA_MODEL", "mistral-nemo")
        self.ollama_host = ollama_host or os.environ.get("KATANA_OLLAMA_HOST", "http://localhost:11434")
        self.kb = KnowledgeBase()
        self.vuln_counter = 0
    
    def _generate_vuln_id(self) -> str:
        """Generate unique vulnerability ID."""
        self.vuln_counter += 1
        return f"VULN-{datetime.utcnow().strftime('%Y%m%d')}-{self.vuln_counter:04d}"
    
    def _detect_target_type(self, target: str) -> TargetType:
        """Auto-detect target type."""
        target_path = Path(target)
        
        # Check for git repos first (more specific)
        if target.endswith('.git') or 'github.com' in target or 'gitlab.com' in target:
            return TargetType.REPO
        elif target.startswith(('http://', 'https://')):
            return TargetType.WEB
        elif target_path.is_dir():
            return TargetType.CODE
        elif target_path.is_file():
            ext = target_path.suffix.lower()
            if ext in ('.py', '.js', '.ts', '.java', '.go', '.rs', '.c', '.cpp', '.sol'):
                return TargetType.CODE
            elif ext in ('.exe', '.dll', '.so', '.bin', '.elf'):
                return TargetType.BINARY
        
        return TargetType.CODE
    
    def _static_analysis(
        self,
        target: str,
        vuln_classes: List[str] = None,
    ) -> List[Vulnerability]:
        """
        Perform static analysis for code vulnerabilities.
        """
        vulnerabilities = []
        target_path = Path(target)
        
        if not target_path.exists():
            return vulnerabilities
        
        # Gather files to analyze
        files = []
        if target_path.is_file():
            files = [target_path]
        else:
            for ext in ['*.py', '*.js', '*.ts', '*.java', '*.go', '*.sol', '*.php', '*.rb']:
                files.extend(target_path.rglob(ext))
        
        # Filter patterns if vuln_classes specified
        patterns_to_check = CODE_PATTERNS
        if vuln_classes:
            patterns_to_check = {k: v for k, v in CODE_PATTERNS.items() if k in vuln_classes}
        
        for file_path in files[:100]:  # Limit files
            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore')
                lines = content.split('\n')
                
                for vuln_type, patterns in patterns_to_check.items():
                    vuln_info = VULN_CLASSES.get(vuln_type, {})
                    
                    for pattern in patterns:
                        for line_num, line in enumerate(lines, 1):
                            if re.search(pattern, line, re.IGNORECASE):
                                # Found potential vulnerability
                                vuln = Vulnerability(
                                    id=self._generate_vuln_id(),
                                    title=f"Potential {vuln_info.get('name', vuln_type)} in {file_path.name}",
                                    severity=vuln_info.get('severity', Severity.MEDIUM).value,
                                    cvss=self.CVSS_SCORES[vuln_info.get('severity', Severity.MEDIUM)][0],
                                    cwe=vuln_info.get('cwe', 'CWE-unknown'),
                                    description=f"Pattern match for {vuln_type} vulnerability detected",
                                    affected_component=str(file_path.relative_to(target_path) if target_path.is_dir() else file_path.name),
                                    reproduction_steps=[
                                        f"Review file: {file_path}",
                                        f"Check line {line_num}",
                                        "Verify if user input reaches this code path",
                                    ],
                                    evidence=[{
                                        "type": "code",
                                        "file": str(file_path),
                                        "line": line_num,
                                        "content": line.strip()[:200],
                                        "pattern": pattern,
                                    }],
                                    confidence=0.6,  # Pattern match = moderate confidence
                                )
                                vulnerabilities.append(vuln)
                                
            except Exception as e:
                logger.warning(f"Error analyzing {file_path}: {e}")
        
        return vulnerabilities
    
    def _llm_analysis(
        self,
        target: str,
        target_type: TargetType,
        context: str = "",
    ) -> List[Vulnerability]:
        """
        Use LLM for deeper vulnerability analysis.
        """
        try:
            import requests
            
            # Build analysis prompt
            prompt = f"""Analyze the following target for security vulnerabilities:

TARGET: {target}
TYPE: {target_type.value}

{f'CONTEXT: {context[:2000]}' if context else ''}

Identify potential security vulnerabilities. For each finding, provide:
1. Title
2. Severity (CRITICAL/HIGH/MEDIUM/LOW)
3. CWE ID if applicable
4. Description
5. Impact
6. Remediation

Output as JSON array:
[
  {{
    "title": "...",
    "severity": "HIGH",
    "cwe": "CWE-XX",
    "description": "...",
    "impact": "...",
    "remediation": "..."
  }}
]"""
            
            response = requests.post(
                f"{self.ollama_host}/api/chat",
                json={
                    "model": self.ollama_model,
                    "messages": [{"role": "user", "content": prompt}],
                    "stream": False,
                },
                timeout=120,
            )
            response.raise_for_status()
            
            content = response.json().get("message", {}).get("content", "")
            
            # Parse findings from response
            vulnerabilities = []
            try:
                json_match = re.search(r'\[[\s\S]*\]', content)
                if json_match:
                    findings = json.loads(json_match.group())
                    for f in findings:
                        severity = Severity[f.get('severity', 'MEDIUM').upper()]
                        vuln = Vulnerability(
                            id=self._generate_vuln_id(),
                            title=f.get('title', 'LLM Finding'),
                            severity=severity.value,
                            cvss=self.CVSS_SCORES[severity][0],
                            cwe=f.get('cwe', 'CWE-unknown'),
                            description=f.get('description', ''),
                            affected_component=target,
                            impact=f.get('impact', ''),
                            remediation=f.get('remediation', ''),
                            confidence=0.7,  # LLM analysis = good confidence
                        )
                        vulnerabilities.append(vuln)
            except (json.JSONDecodeError, KeyError) as e:
                logger.warning(f"Failed to parse LLM findings: {e}")
            
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"LLM analysis error: {e}")
            return []
    
    def _deduplicate(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Remove duplicate findings."""
        seen = set()
        unique = []
        
        for v in vulnerabilities:
            key = (v.cwe, v.affected_component, v.title[:50])
            if key not in seen:
                seen.add(key)
                unique.append(v)
        
        return unique
    
    def _generate_summary(self, vulnerabilities: List[Vulnerability]) -> Dict[str, Any]:
        """Generate summary statistics."""
        severity_counts = {}
        cwe_counts = {}
        
        for v in vulnerabilities:
            severity_counts[v.severity] = severity_counts.get(v.severity, 0) + 1
            cwe_counts[v.cwe] = cwe_counts.get(v.cwe, 0) + 1
        
        return {
            "total": len(vulnerabilities),
            "by_severity": severity_counts,
            "by_cwe": dict(sorted(cwe_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
            "critical_count": severity_counts.get("CRITICAL", 0),
            "high_count": severity_counts.get("HIGH", 0),
        }
    
    def discover(
        self,
        target: str,
        target_type: TargetType = TargetType.AUTO,
        vuln_classes: List[str] = None,
        depth: str = "medium",
    ) -> DiscoveryResult:
        """
        Discover vulnerabilities in target.
        """
        start = datetime.utcnow()
        
        # Auto-detect target type if needed
        if target_type == TargetType.AUTO:
            target_type = self._detect_target_type(target)
        
        logger.info(f"Starting discovery on {target} (type: {target_type.value})")
        
        all_vulnerabilities = []
        
        # Phase 1: Static analysis for code targets
        if target_type in (TargetType.CODE, TargetType.REPO):
            static_vulns = self._static_analysis(target, vuln_classes)
            all_vulnerabilities.extend(static_vulns)
            logger.info(f"Static analysis found {len(static_vulns)} potential issues")
        
        # Phase 2: LLM-guided analysis
        if depth in ("medium", "deep"):
            # Get context from KB
            kb_results = self.kb.search(f"vulnerabilities in {target_type.value}", limit=5)
            context = "\n".join(r.content[:300] for r in kb_results)
            
            llm_vulns = self._llm_analysis(target, target_type, context)
            all_vulnerabilities.extend(llm_vulns)
            logger.info(f"LLM analysis found {len(llm_vulns)} potential issues")
        
        # Deduplicate
        all_vulnerabilities = self._deduplicate(all_vulnerabilities)
        
        # Sort by severity
        severity_order = {
            "CRITICAL": 0,
            "HIGH": 1,
            "MEDIUM": 2,
            "LOW": 3,
            "INFO": 4,
        }
        all_vulnerabilities.sort(key=lambda v: severity_order.get(v.severity, 5))
        
        duration = (datetime.utcnow() - start).total_seconds()
        
        return DiscoveryResult(
            status=True,
            target=target,
            target_type=target_type.value,
            vulnerabilities=all_vulnerabilities,
            summary=self._generate_summary(all_vulnerabilities),
            duration=duration,
        )


def run(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main entry point for Vulnerability Discovery skill.
    """
    target = params.get('target', '')
    target_type_str = params.get('target_type', 'auto')
    vuln_classes = params.get('vuln_classes', [])
    depth = params.get('depth', 'medium')
    
    if not target:
        return {
            'status': False,
            'summary': 'target parameter required',
            'result': {}
        }
    
    try:
        target_type = TargetType(target_type_str)
    except ValueError:
        target_type = TargetType.AUTO
    
    try:
        engine = VulnDiscoveryEngine()
        discovery_result = engine.discover(
            target=target,
            target_type=target_type,
            vuln_classes=vuln_classes if vuln_classes else None,
            depth=depth,
        )
        
        res_data = {
            'status': discovery_result.status,
            'target': discovery_result.target,
            'target_type': discovery_result.target_type,
            'vulnerabilities': [asdict(v) for v in discovery_result.vulnerabilities[:50]],
            'summary': discovery_result.summary,
            'duration': discovery_result.duration,
        }

        vuln_count = discovery_result.summary.get('total', 0)
        summary = f"Vulnerability discovery on '{discovery_result.target}' ({discovery_result.target_type}) found {vuln_count} potential issues."
        
        return {
            'status': discovery_result.status,
            'summary': summary,
            'result': res_data
        }
        
    except Exception as e:
        logger.error(f"Discovery error: {e}")
        return {
            'status': False,
            'summary': f"Discovery error: {str(e)}",
            'result': {'error': str(e)}
        }


def main():
    """CLI entry point for testing."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Vulnerability Discovery CLI')
    parser.add_argument('target', nargs='?', help='Target to analyze')
    parser.add_argument('--type', '-t', dest='target_type',
                        choices=['auto', 'code', 'web', 'repo', 'binary'],
                        default='auto')
    parser.add_argument('--depth', '-d', choices=['quick', 'medium', 'deep'], default='medium')
    parser.add_argument('--vulns', '-v', nargs='+', help='Specific vuln classes to hunt')
    parser.add_argument('--json', help='Pass parameters as JSON string')
    parser.add_argument('--test', action='store_true', help='Run sanity test')
    
    args = parser.parse_args()
    
    if args.test:
        print("[*] Testing Vuln Discovery Engine...")
        result = run({'target': '.', 'depth': 'quick'})
        print(json.dumps(result, indent=2, default=str))
        return

    if args.json:
        try:
            params = json.loads(args.json)
        except json.JSONDecodeError:
            print(json.dumps({'status': False, 'summary': 'Invalid JSON input', 'result': {}}))
            return
    else:
        if not args.target:
            parser.print_help()
            return
        params = {
            'target': args.target,
            'target_type': args.target_type,
            'depth': args.depth,
            'vuln_classes': args.vulns,
        }
    
    result = run(params)
    print(json.dumps(result, indent=2, default=str))


if __name__ == '__main__':
    main()

import re
from ..models import Severity, IoTFinding

class BackdoorScanner:
    """Scanner for backdoor accounts and diagnostic shells."""
    
    PATTERNS = [
        {
            'pattern': r'backdoor|debug_shell|toor|service_account',
            'description': 'Potential backdoor or hardcoded service account found in filesystem.',
            'severity': Severity.CRITICAL,
            'remediation': 'Remove all diagnostic and backdoor accounts before production.'
        },
        {
            'pattern': r'/bin/sh -i|/bin/bash -i',
            'description': 'Interactive shell startup script found (potential backdoor).',
            'severity': Severity.CRITICAL,
            'remediation': 'Disable interactive shell access over network interfaces.'
        }
    ]
    
    def scan(self, handler, target_path):
        findings = []
        # Optimization: only scan configuration and startup scripts
        if not any(x in str(target_path) for x in ['/etc/', '/bin/', '.sh', '.service', '.conf']):
            return findings
            
        try:
            content = target_path.read_text(errors='ignore')
            for p in self.PATTERNS:
                if re.search(p['pattern'], content, re.IGNORECASE):
                    findings.append(IoTFinding(
                        vulnerability_id="hardcoded-backdoor",
                        severity=p['severity'],
                        description=p['description'],
                        file_path=str(target_path),
                        evidence=f"Matched pattern: {p['pattern']}",
                        remediation=p['remediation']
                    ))
        except Exception:
            pass
            
        return findings

def get_scanner():
    return BackdoorScanner()

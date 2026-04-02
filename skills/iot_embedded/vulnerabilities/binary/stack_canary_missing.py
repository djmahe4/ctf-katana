from ..base_model import IoTHandlerBase
from ..models import Severity, IoTFinding

class StackCanaryScanner:
    """Binary scanner for missing stack protector (canaries)."""
    
    def scan(self, handler, target_path):
        """Analyze ELF for stack protection."""
        findings = []
        
        # Check if it's an ELF
        if not str(target_path).endswith(('.elf', '.bin', '.so', '')):
             return findings

        # Attempt to use readelf via handler's check_protections
        protections = handler.check_protections(target_path)
        
        if not protections.get('has_canary', True):
            findings.append(IoTFinding(
                vulnerability_id="stack-canary-missing",
                severity=Severity.HIGH,
                description="Binary lacks stack smashing protection (Stack Canary).",
                file_path=str(target_path),
                evidence="Symbol '__stack_chk_fail' not found in binary.",
                remediation="Compile with -fstack-protector-all or -fstack-protector-strong."
            ))
            
        return findings

def get_scanner():
    return StackCanaryScanner()

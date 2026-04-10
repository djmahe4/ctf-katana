import logging
import re
from typing import Dict, Any, List

from skills.web.models import WebRunResult, WebCategory, WebFinding, WebSeverity
from skills.web.base import WebHandlerBase

logger = logging.getLogger(__name__)

class XSSHandler(WebHandlerBase):
    """Handler for detecting and exploiting Cross-Site Scripting (XSS) vulnerabilities."""

    def analyze(self, target: str, **kwargs) -> WebRunResult:
        result = self.create_empty_result(WebCategory.XSS, target)
        
        # Reflected XSS detection logic
        if self._check_reflected_xss(target):
             self.add_finding(
                vulnerability_id="xss_detected",
                category=WebCategory.XSS,
                description="Potential Cross-Site Scripting (XSS) vulnerability detected via reflection.",
                severity=WebSeverity.HIGH,
                url=target
             )

        result.findings = self.findings
        result.summary = f"XSS analysis complete for {target}."
        result.statistics = {"findings_count": len(self.findings)}
        
        return result

    def _check_reflected_xss(self, target: str) -> bool:
        """Simple Reflected XSS detection by hunting for reflection in response."""
        xss_payloads = [
            "<script>alert(1)</script>",
            "\"><script>alert(1)</script>",
            "'><script>alert(1)</script>"
        ]
        for payload in xss_payloads:
            try:
                response = self.request("GET", target, params={"q": payload})
                if payload in response.text:
                     # Reflection found, should also check for escaping
                     self.add_finding(
                        vulnerability_id="xss_reflection_detected",
                        category=WebCategory.XSS,
                        description=f"Input reflection detected for payload: {payload}",
                        severity=WebSeverity.MEDIUM,
                        url=target,
                        evidence=payload
                     )
                     return True
            except Exception:
                pass
        return False

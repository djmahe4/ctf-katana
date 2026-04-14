import logging
import base64
import json
from typing import Dict, Any, List, Optional

from skills.web.models import WebRunResult, WebCategory, WebFinding, WebSeverity
from skills.web.base import WebHandlerBase

logger = logging.getLogger(__name__)

class AuthHandler(WebHandlerBase):
    """Handler for authentication and session management analysis (JWT, OAuth, Cookies)."""

    def analyze(self, target: str, **kwargs) -> WebRunResult:
        result = self.create_empty_result(WebCategory.AUTH, target)
        
        token = kwargs.get('token')
        if token:
            self._analyze_jwt(token, result)
        
        # Cookie analysis
        self._analyze_session_cookies(target, result)

        result.findings = self.findings
        result.summary = f"Auth analysis complete for {target}."
        result.statistics = {"findings_count": len(self.findings)}
        
        return result

    def _analyze_jwt(self, token: str, result: WebRunResult):
        """Analyzes and tampered with JWT tokens."""
        parts = token.split(".")
        if len(parts) < 2:
            return
            
        decoded: Dict[str, Any] = {}
        for label, segment in zip(("header", "payload"), parts[:2]):
            padded = segment + "=" * (-len(segment) % 4)
            try:
                decoded[label] = json.loads(base64.urlsafe_b64decode(padded))
            except Exception:
                decoded[label] = segment
        
        # Check for 'alg: none'
        header = decoded.get('header', {})
        if isinstance(header, dict) and header.get('alg', '').lower() == 'none':
             self.add_finding(
                vulnerability_id="jwt_none_alg",
                category=WebCategory.JWT,
                description="JWT uses 'none' algorithm, allowing potential signature bypass.",
                severity=WebSeverity.CRITICAL,
                evidence=json.dumps(header)
            )

        # Check for sensitive info in payload
        payload = decoded.get('payload', {})
        if isinstance(payload, dict):
            for key in ["password", "secret", "apikey", "pin"]:
                if key in str(payload).lower():
                    self.add_finding(
                        vulnerability_id="jwt_sensitive_data",
                        category=WebCategory.DATA_EXPOSURE,
                        description=f"JWT payload may contain sensitive data field: {key}",
                        severity=WebSeverity.MEDIUM,
                        evidence=json.dumps(payload)
                    )

    def _analyze_session_cookies(self, target: str, result: WebRunResult):
        try:
            response = self.request("GET", target)
            cookies = response.cookies
            for cookie in cookies:
                if not cookie.secure:
                     self.add_finding(
                        vulnerability_id="cookie_not_secure",
                        category=WebCategory.MISCONFIG,
                        description=f"Cookie '{cookie.name}' is missing Secure flag.",
                        severity=WebSeverity.MEDIUM,
                        url=target
                    )
                if not cookie.has_nonstandard_attr('HttpOnly'):
                     self.add_finding(
                        vulnerability_id="cookie_not_httponly",
                        category=WebCategory.MISCONFIG,
                        description=f"Cookie '{cookie.name}' is missing HttpOnly flag.",
                        severity=WebSeverity.MEDIUM,
                        url=target
                    )
        except Exception:
            pass

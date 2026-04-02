import logging
import re
from typing import Dict, Any, List
from urllib.parse import urljoin

from ..models import WebRunResult, WebCategory, WebFinding, WebSeverity
from ..base import WebHandlerBase

logger = logging.getLogger(__name__)

class DiscoveryHandler(WebHandlerBase):
    """Handler for initial web reconnaissance and discovery."""

    def analyze(self, target: str, **kwargs) -> WebRunResult:
        result = self.create_empty_result(WebCategory.DISCOVERY, target)
        
        # 1. Header Analysis
        self._analyze_headers(target, result)
        
        # 2. robots.txt Analysis
        self._analyze_robots(target, result)
        
        # 3. Security.txt
        self._analyze_security_txt(target, result)

        result.findings = self.findings
        result.summary = f"Discovery complete for {target}. Found {len(self.findings)} initial points of interest."
        result.statistics = {"findings_count": len(self.findings)}
        
        return result

    def _analyze_headers(self, target: str, result: WebRunResult):
        try:
            response = self.request("HEAD", target)
            headers = response.headers
            
            # Check for missing security headers
            security_headers = [
                "Content-Security-Policy",
                "X-Frame-Options",
                "X-Content-Type-Options",
                "Strict-Transport-Security"
            ]
            for sh in security_headers:
                if sh not in headers:
                    self.add_finding(
                        vulnerability_id=f"missing_{sh.lower().replace('-', '_')}",
                        category=WebCategory.MISCONFIG,
                        description=f"Sensitive security header '{sh}' is missing.",
                        severity=WebSeverity.LOW,
                        url=target
                    )

            # Check for server fingerprinting
            if "Server" in headers:
                self.add_finding(
                    vulnerability_id="server_fingerprint",
                    category=WebCategory.MISCONFIG,
                    description=f"Server header identifies backend: {headers['Server']}",
                    severity=WebSeverity.INFO,
                    url=target,
                    evidence=headers['Server']
                )
        except Exception as e:
            logger.debug(f"Header analysis failed: {e}")

    def _analyze_robots(self, target: str, result: WebRunResult):
        robots_url = urljoin(target, "/robots.txt")
        try:
            response = self.request("GET", robots_url)
            if response.status_code == 200:
                self.add_finding(
                    vulnerability_id="robots_txt_found",
                    category=WebCategory.DISCOVERY,
                    description="Found robots.txt. May contain hidden directories.",
                    severity=WebSeverity.INFO,
                    url=robots_url,
                    evidence=response.text[:200]
                )
                
                # Simple parsing for disallowed paths
                disallowed = re.findall(r"Disallow:\s*(.*)", response.text)
                if disallowed:
                    result.summary += f" [Robots.txt has {len(disallowed)} disallowed paths]"
                    for path in disallowed:
                        if path.strip() and path.strip() != "/":
                             result.artifacts.append(f"Disallowed path: {path.strip()}")
        except Exception as e:
            logger.debug(f"Robots.txt analysis failed: {e}")

    def _analyze_security_txt(self, target: str, result: WebRunResult):
        sec_url = urljoin(target, "/.well-known/security.txt")
        try:
            response = self.request("GET", sec_url)
            if response.status_code == 200:
                self.add_finding(
                    vulnerability_id="security_txt_found",
                    category=WebCategory.DISCOVERY,
                    description="Found security.txt for vulnerability reporting info.",
                    severity=WebSeverity.INFO,
                    url=sec_url
                )
        except Exception:
            pass

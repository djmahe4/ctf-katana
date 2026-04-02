import requests
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from .models import WebFinding, WebCategory, WebRunResult, WebSeverity

logger = logging.getLogger(__name__)

class WebHandlerBase(ABC):
    """Abstract base class for all web fuzzer and exploit handlers."""

    def __init__(self, session: Optional[requests.Session] = None):
        self.session = session or requests.Session()
        self.findings: List[WebFinding] = []
        self.artifacts: List[str] = []

    @abstractmethod
    def analyze(self, target: str, **kwargs) -> WebRunResult:
        """Main entry point for the handler to perform analysis/fuzzing/exploit."""
        pass

    def add_finding(self, 
                    vulnerability_id: str, 
                    category: WebCategory, 
                    description: str, 
                    severity: WebSeverity, 
                    **kwargs):
        """Add a standardized finding to the handler's list."""
        finding = WebFinding(
            vulnerability_id=vulnerability_id,
            category=category,
            description=description,
            severity=severity,
            **kwargs
        )
        self.findings.append(finding)
        logger.info(f"[{severity.value}] {vulnerability_id}: {description}")

    def create_empty_result(self, category: WebCategory, target: str) -> WebRunResult:
        """Helper to initialize a WebRunResult."""
        return WebRunResult(category=category, target=target)

    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Execute a session-aware HTTP request with error handling."""
        try:
            response = self.session.request(method, url, timeout=10, **kwargs)
            return response
        except requests.RequestException as e:
            logger.error(f"HTTP Request failed: {e}")
            raise

import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, List
from .models import FuzzRunResult, FuzzCategory, FuzzFinding, FuzzerSeverity

logger = logging.getLogger(__name__)

class FuzzerHandlerBase(ABC):
    """Base class for all fuzzer handlers (Web, Binary, Protocol, Cloud)."""

    def __init__(self):
        self.session = None

    @abstractmethod
    def analyze(self, target: str, **kwargs) -> FuzzRunResult:
        """Execute the fuzzing analysis for the given target."""
        pass

    def _get_requests_session(self):
        """Lazy-load requests session if needed for web/cloud handlers."""
        if self.session is None:
            try:
                import requests
                self.session = requests.Session()
            except ImportError:
                logger.error("requests library NOT found.")
                raise
        return self.session

    def create_empty_result(self, category: FuzzCategory, target: str) -> FuzzRunResult:
        """Helper to create a default result object."""
        return FuzzRunResult(
            category=category,
            target=target,
            summary=f"Fuzzing analysis for {target}"
        )

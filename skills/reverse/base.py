import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional

from .models import ReverseRunResult, ReverseMode, ReverseFinding, ReverseSeverity

logger = logging.getLogger(__name__)

class ReverseHandlerBase(ABC):
    """Base class for all Logic Architect (reverse) handlers."""
    
    def __init__(self):
        self.findings: List[ReverseFinding] = []
        self.artifacts: List[str] = []

    @abstractmethod
    def run(self, target: str, mode: ReverseMode, **kwargs) -> ReverseRunResult:
        """Execute the handler's core logic."""
        pass

    def add_finding(
        self,
        finder_id: str,
        category: str,
        description: str,
        severity: ReverseSeverity = ReverseSeverity.MEDIUM,
        logic_pattern: Optional[str] = None,
        extracted_flag: Optional[str] = None,
        pseudocode: Optional[str] = None
    ):
        finding = ReverseFinding(
            finder_id=finder_id,
            category=category,
            description=description,
            severity=severity,
            logic_pattern=logic_pattern,
            extracted_flag=extracted_flag,
            pseudocode=pseudocode
        )
        self.findings.append(finding)
        logger.info(f"[+] [{finder_id}] Found: {description}")

    def create_empty_result(self, target: str, mode: ReverseMode) -> ReverseRunResult:
        return ReverseRunResult(
            target=target,
            mode=mode,
            success=True,
            summary="",
            findings=[],
            artifacts=[],
            statistics={}
        )

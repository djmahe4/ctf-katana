import logging
import re
from typing import Dict, Any, List

from skills.reverse.models import ReverseRunResult, ReverseMode, ReverseFinding, ReverseSeverity
from skills.reverse.base import ReverseHandlerBase

logger = logging.getLogger(__name__)

class LogicHandler(ReverseHandlerBase):
    """Handler for offensive logic reverse-engineering ('Think like a creator')."""

    def run(self, target: str, mode: ReverseMode, **kwargs) -> ReverseRunResult:
        result = self.create_empty_result(target, mode)
        
        # Scenario: Extracting a flag from a given script/snippet
        if mode == ReverseMode.OFFENSIVE or mode == ReverseMode.SYNERGY:
             self._analyze_logic(target, result, **kwargs)

        result.findings = self.findings
        result.summary = f"Logic analysis complete for {target}."
        result.statistics = {"findings_count": len(self.findings)}
        
        return result

    def _analyze_logic(self, target: str, result: ReverseRunResult, **kwargs):
        """Simulates logic extraction. In practice, this uses LLM 'Think' engine."""
        # Simple regex for finding hardcoded flags in snippets
        flag_patterns = [
            r"CTF\{.*?\}",
            r"flag\{.*?\}",
            r"FLAG\{.*?\}",
            r"secret_key\s*=\s*['\"](.*?)['\"]"
        ]
        
        # If target starts with a snippet-like character or we have snippet in kwargs
        snippet = kwargs.get("snippet", target)
        for pattern in flag_patterns:
            matches = re.findall(pattern, snippet)
            for match in matches:
                 self.add_finding(
                    finder_id="logic_pattern_extractor",
                    category="flag_leak",
                    description="Identified potential hardcoded flag or secret in logic.",
                    severity=ReverseSeverity.HIGH,
                    extracted_flag=match if isinstance(match, str) else match[0]
                 )
        
        # Thinking: How would a creator hide this?
        # Simulate agentic brainstorming
        if "XOR" in snippet.upper():
             self.add_finding(
                finder_id="logic_architect_brainstorm",
                category="obfuscation_analysis",
                description="Detected XOR-based obfuscation. Creators likely use this to hide flags in byte arrays.",
                severity=ReverseSeverity.MEDIUM,
                logic_pattern="XOR Obfuscation"
             )

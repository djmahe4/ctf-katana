import logging
import json
import os
import argparse
import asyncio
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
import requests
from ..models import FuzzRunResult, FuzzCategory, FuzzFinding, FuzzerSeverity
from ..base import FuzzerHandlerBase

logger = logging.getLogger(__name__)

class FfufAIEngine:
    """
    AI-Augmented Fuzzing Engine.
    Wraps ffuf for high-speed discovery and uses LLMs for context-aware strategy and analysis.
    """

    def __init__(self, workspace_root: str):
        self.workspace_root = workspace_root
        self.ffuf_path = self._find_ffuf()

    def _find_ffuf(self) -> Optional[str]:
        """Check if ffuf is in the system path."""
        import shutil
        return shutil.which("ffuf")

    async def analyze_target(self, target_url: str) -> Dict[str, Any]:
        """
        Initial analysis of the target to detect tech stack and suggest a strategy.
        This would ideally call an LLM (free-llm-apis).
        """
        logger.info(f"FfufAI: Analyzing target {target_url}...")
        try:
            response = requests.get(target_url, timeout=10, verify=False)
            headers = dict(response.headers)
            body_preview = response.text[:2000]
            
            # Simple heuristic analysis (to be augmented by LLM later)
            context = {
                "server": headers.get("Server", ""),
                "powered_by": headers.get("X-Powered-By", ""),
                "cookies": list(headers.get("Set-Cookie", [])),
                "is_php": ".php" in body_preview or "PHPSESSID" in str(headers),
                "is_java": "JSESSIONID" in str(headers) or "stacktrace" in body_preview.lower(),
                "is_api": "application/json" in headers.get("Content-Type", "") or "/api/" in target_url
            }
            return context
        except Exception as e:
            logger.error(f"FfufAI: Initial analysis failed: {e}")
            return {}

    def get_ffuf_command(self, target_url: str, context: Dict[str, Any], wordlist_path: str = "common.txt") -> str:
        """Generates an optimized ffuf command based on the target context."""
        base_cmd = f"ffuf -u {target_url.rstrip('/')}/FUZZ -w {wordlist_path} -of json -o ffuf_results.json"
        
        # Add smart flags
        if context.get("is_php"):
            base_cmd += " -e .php,.php.bak,.config.php"
        elif context.get("is_java"):
            base_cmd += " -e .jsp,.jspx,.do,.action"
        
        # Add recursion if it looks like a deep app
        if context.get("is_api"):
            base_cmd += " -recursion -recursion-depth 2"
            
        return base_cmd

    def run_fuzz(self, target_url: str, mode: str = "directory", **kwargs) -> FuzzRunResult:
        """
        Main entry point for the FfufAI engine.
        Executed via the fuzzing skill runner.
        """
        result = FuzzRunResult(
            category=FuzzCategory.WEB,
            target=target_url,
            summary="FfufAI analysis started."
        )
        
        # 1. Target Context Discovery (Sync wrapper for now or use asyncio.run)
        context = asyncio.run(self.analyze_target(target_url))
        
        # 2. Strategy Generation
        ffuf_cmd = self.get_ffuf_command(target_url, context)
        result.summary += f"\nRecommended Command: {ffuf_cmd}"
        
        # 3. Execution (Fallback to internal fuzzer if ffuf missing)
        if self.ffuf_path:
            logger.info(f"FfufAI: Running ffuf...")
            # actual subprocess execution would go here
            pass
        else:
            logger.warning("FfufAI: ffuf not found. Falling back to internal (slow) fuzzer.")
            # Fallback logic would use the existing WebHandler or a custom light fuzzer
            
        return result

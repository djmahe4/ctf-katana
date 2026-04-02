import os
import importlib
import logging
from typing import Dict, List, Any
from ..base import Web3HandlerBase
from ..models import VulnType

logger = logging.getLogger(__name__)

class SolanaHandler(Web3HandlerBase):
    """Handler for Solana (Anchor/Rust) smart contracts."""

    def __init__(self, network: str = "mainnet"):
        super().__init__(chain="solana", network=network)

    def get_patterns(self) -> Dict[VulnType, List[Any]]:
        """Dynamically load Solana patterns from the vulnerabilities directory."""
        patterns_map = {}
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        vulnerabilities_dir = os.path.join(base_dir, "vulnerabilities")

        if not os.path.exists(vulnerabilities_dir):
            return {}

        for vuln_folder in os.listdir(vulnerabilities_dir):
            vuln_path = os.path.join(vulnerabilities_dir, vuln_folder)
            if not os.path.isdir(vuln_path):
                continue
            
            # Check for solana subdirectory
            sol_path = os.path.join(vuln_path, "solana")
            if os.path.isdir(sol_path) and os.path.exists(os.path.join(sol_path, "patterns.py")):
                try:
                    module_name = f"skills.web3.vulnerabilities.{vuln_folder.replace('-', '_')}.solana.patterns"
                    module = importlib.import_module(module_name)
                    
                    if hasattr(module, "PATTERNS"):
                        try:
                            vuln_type = VulnType[vuln_folder.upper().replace("-", "_")]
                        except KeyError:
                            vuln_type = VulnType.OTHER
                        
                        # Collect all pattern definitions (str, tuple, or dict)
                        regex_list = list(module.PATTERNS)
                        
                        if vuln_type in patterns_map:
                            patterns_map[vuln_type].extend(regex_list)
                        else:
                            patterns_map[vuln_type] = regex_list
                except Exception as e:
                    logger.error(f"Failed to load Solana patterns for {vuln_folder}: {e}")

        return patterns_map

    def check_security_features(self, content: str) -> Dict[str, bool]:
        """Check for common Solana/Anchor security features."""
        return {
            "anchor_framework": "anchor_lang" in content or "use anchor_lang" in content,
            "account_info_validation": "AccountInfo" in content and "Check" in content,
            "discriminator_check": "discriminator" in content or "AccountDeserialize" in content,
            "owner_check": "owner" in content and ("key" in content or "owner == program_id" in content)
        }

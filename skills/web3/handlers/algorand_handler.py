import os
import importlib
import logging
from typing import Dict, List, Any
from skills.web3.base import Web3HandlerBase
from skills.web3.models import VulnType

logger = logging.getLogger(__name__)

class AlgorandHandler(Web3HandlerBase):
    """Handler for Algorand (PyTeal/TEAL) smart contracts."""

    def __init__(self, network: str = "mainnet"):
        super().__init__(chain="algorand", network=network)

    def get_patterns(self) -> Dict[VulnType, List[Any]]:
        """Dynamically load Algorand patterns from the vulnerabilities directory."""
        patterns_map = {}
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        vulnerabilities_dir = os.path.join(base_dir, "vulnerabilities")

        if not os.path.exists(vulnerabilities_dir):
            return {}

        for vuln_folder in os.listdir(vulnerabilities_dir):
            vuln_path = os.path.join(vulnerabilities_dir, vuln_folder)
            if not os.path.isdir(vuln_path):
                continue
            
            # Check for algorand subdirectory
            algo_path = os.path.join(vuln_path, "algorand")
            if os.path.isdir(algo_path) and os.path.exists(os.path.join(algo_path, "patterns.py")):
                try:
                    module_name = f"skills.web3.vulnerabilities.{vuln_folder.replace('-', '_')}.algorand.patterns"
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
                    logger.error(f"Failed to load Algorand patterns for {vuln_folder}: {e}")

        return patterns_map

    def check_security_features(self, content: str) -> Dict[str, bool]:
        """Check for common Algorand/PyTeal security features."""
        return {
            "pyteal_framework": "pyteal" in content or "from pyteal import" in content,
            "rekey_checked": "rekey_to" in content and "Check" in content,
            "close_out_checked": "close_remainder_to" in content and "Check" in content,
            "fee_checked": "fee" in content and "Txn" in content
        }

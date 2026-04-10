import os
import importlib
import logging
from typing import Dict, List, Any
from skills.web3.base import Web3HandlerBase
from skills.web3.models import VulnType

logger = logging.getLogger(__name__)

class EthereumHandler(Web3HandlerBase):
    """Handler for Ethereum (EVM) smart contracts."""

    def __init__(self, network: str = "mainnet"):
        super().__init__(chain="ethereum", network=network)

    def get_patterns(self) -> Dict[VulnType, List[Any]]:
        """Dynamically load EVM patterns from the vulnerabilities directory."""
        patterns_map = {}
        
        # Get the path to the vulnerabilities directory
        # Current file: skills/web3/handlers/ethereum_handler.py
        # Vulnerabilities: skills/web3/vulnerabilities/
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        vulnerabilities_dir = os.path.join(base_dir, "vulnerabilities")

        if not os.path.exists(vulnerabilities_dir):
            logger.warning(f"Vulnerabilities directory not found at {vulnerabilities_dir}")
            return {}

        for vuln_folder in os.listdir(vulnerabilities_dir):
            vuln_path = os.path.join(vulnerabilities_dir, vuln_folder)
            if not os.path.isdir(vuln_path):
                continue
            
            # Check for evm subdirectory
            evm_path = os.path.join(vuln_path, "evm")
            if os.path.isdir(evm_path) and os.path.exists(os.path.join(evm_path, "patterns.py")):
                try:
                    # Dynamically import the patterns module
                    # Module name: skills.web3.vulnerabilities.{vuln_folder}.evm.patterns
                    module_name = f"skills.web3.vulnerabilities.{vuln_folder}.evm.patterns"
                    module = importlib.import_module(module_name)
                    
                    if hasattr(module, "PATTERNS"):
                        # Convert folder name to VulnType if possible
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
                    logger.error(f"Failed to load patterns for {vuln_folder}: {e}")

        return patterns_map

    def check_security_features(self, content: str) -> Dict[str, bool]:
        """Check for common Solidity security features."""
        return {
            "reentrancy_guard": "ReentrancyGuard" in content or "nonReentrant" in content,
            "ownable": "Ownable" in content or "onlyOwner" in content,
            "safemath": "SafeMath" in content or "pragma solidity ^0.8" in content,
            "pausable": "Pausable" in content or "whenNotPaused" in content,
            "access_control": "AccessControl" in content or "hasRole" in content
        }

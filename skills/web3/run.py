import logging
import argparse
import sys
import json
from typing import Dict, Any, Optional, List
from pathlib import Path

# Fix imports to use absolute paths from project root
from skills.web3.orchestrator import Web3Orchestrator

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class Web3Analyzer:
    """Compatibility wrapper for Web3Orchestrator."""
    def __init__(self):
        self.orchestrator = Web3Orchestrator()
    
    def analyze(self, target: str, mode: str = 'full') -> Dict[str, Any]:
        """Runs the full analysis pipeline."""
        params = {'target': target, 'mode': mode}
        res = self.orchestrator.analyze(params)
        
        status = res.get("status") is True
        summary = f"Web3 analysis completed for {target[:30]}..." if status else f"Analysis failed: {res.get('summary', 'Unknown error')}"
        
        # If the orchestrator returned a full dict (Web3AnalysisResult.to_dict()), use it as 'result'
        # Otherwise, wrap what we have.
        result_data = res
        if not status and not result_data:
            result_data = {}

        return {
            "status": status,
            "summary": summary,
            "result": result_data
        }

    def detect_reentrancy(self, code: str) -> List[Any]:
        """Detect reentrancy vulnerabilities."""
        res = self.orchestrator.analyze({'target': code, 'mode': 'reentrancy'})
        return res.get("vulnerabilities", [])
    
    def detect_flash_loan_vuln(self, code: str) -> List[Any]:
        """Detect flash loan vulnerabilities."""
        res = self.orchestrator.analyze({'target': code, 'mode': 'flashloan'})
        return res.get("vulnerabilities", [])
    
    def detect_accounting_bugs(self, code: str) -> List[Any]:
        """Detect accounting bugs."""
        res = self.orchestrator.analyze({'target': code, 'mode': 'accounting'})
        return res.get("vulnerabilities", [])

def run(params: Dict[str, Any]) -> Dict[str, Any]:
    """Execute the Web3 analysis skill."""
    target = params.get('target') or params.get('contract_code')
    if not target:
        return {
            'status': False,
            'summary': 'target or contract_code parameter required',
            'result': {}
        }

    try:
        analyzer = Web3Analyzer()
        res_data = analyzer.analyze(target, params.get('mode', 'full'))
        
        return res_data
    except Exception as e:
        logger.error(f"Web3 analysis error: {e}")
        return {
            'status': False,
            'summary': f"Error: {str(e)}",
            'result': {}
        }

if __name__ == "__main__":
    # Add project root to sys.path for standalone execution
    root_path = str(Path(__file__).resolve().parent.parent.parent)
    if root_path not in sys.path:
        sys.path.insert(0, root_path)

    parser = argparse.ArgumentParser(description="Web3 Vulnerability Analyzer")
    parser.add_argument("target", help="Path to contract, address, or repository")
    parser.add_argument("--chain", default="ethereum", help="Blockchain type (ethereum, solana, algorand)")
    parser.add_argument("--network", default="mainnet", help="Network (mainnet, goerli, sepolia, polygon, etc.)")
    parser.add_argument("--mode", default="full", choices=["fast", "deep", "full"], help="Analysis mode")
    parser.add_argument("--json", action="store_true", help="Output result as JSON")
    
    args = parser.parse_args()
    
    params = {
        "target": args.target,
        "chain_type": args.chain,
        "network": args.network,
        "mode": args.mode
    }
    
    result = run(params)
    
    if args.json:
        print(json.dumps(result, indent=2))
        sys.exit(0 if result['status'] is True else 1)

    if result.get("status") is True:
        res_data = result.get("result", {})
        print(res_data.get("report", "Analysis completed successfully (no report)."))
    else:
        print(f"Error: {result.get('summary', 'Unknown error')}")
        sys.exit(1)

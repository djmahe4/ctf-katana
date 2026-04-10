import logging
import argparse
import sys
import json
from typing import Dict, Any, Optional
from pathlib import Path

# Fix imports to use absolute paths from project root
from skills.web3.orchestrator import Web3Orchestrator

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def run(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main entry point for Web3 Analyzer skill.
    Delegates to Web3Orchestrator for multi-chain support.
    """
    target = params.get('target', '')
    chain_type = params.get('chain_type', 'ethereum').lower()
    network = params.get('network', 'mainnet').lower()
    mode = params.get('mode', 'full').lower()
    
    if not target:
        # Try to infer target from 'file' or other common params if available
        target = params.get('file', '')
    
    if not target:
        return {
            'status': 'error',
            'message': 'target parameter required (contract file, address, or repo URL)',
        }
    
    logger.info(f"Starting Web3 analysis: target={target}, chain={chain_type}, network={network}, mode={mode}")
    
    try:
        orchestrator = Web3Orchestrator()
        analysis_result = orchestrator.analyze({
            "target": target,
            "chain_type": chain_type,
            "network": network,
            "mode": mode
        })
        
        if analysis_result.get("status") == "error":
            return {
                "status": "error",
                "summary": f"Web3 analysis failed for {target}: {analysis_result.get('message')}",
                "result": analysis_result
            }

        return {
            "status": "success",
            "summary": f"Web3 analysis completed for {target} ({chain_type}/{network})",
            "result": analysis_result
        }
        
    except Exception as e:
        logger.error(f"Web3 analysis error: {e}", exc_info=True)
        return {
            'status': 'error',
            'summary': f"Web3 analysis exception: {str(e)}",
            'result': {'error_detail': str(e)}
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
        sys.exit(0 if result['status'] == 'success' else 1)

    if result.get("status") == "success":
        res_data = result.get("result", {})
        print(res_data.get("report", "Analysis completed successfully (no report)."))
    else:
        print(f"Error: {result.get('summary', 'Unknown error')}")
        sys.exit(1)

import sys
import os
import argparse
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional

# Standardize path for standalone execution
project_root = Path(__file__).resolve().parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

try:
    from skills.reverse.models import ReverseMode, ReverseSeverity
    from skills.reverse.handlers.logic_handler import LogicHandler
    from skills.reverse.handlers.synthesis_handler import SynthesisHandler
    from skills.reverse.engines.re_designer import REDesigner
except ImportError:
    # Fallback for different execution contexts
    from .models import ReverseMode, ReverseSeverity
    from .handlers.logic_handler import LogicHandler
    from .handlers.synthesis_handler import SynthesisHandler
    from .engines.re_designer import REDesigner

def run(params: Dict[str, Any]) -> Dict[str, Any]:
    """Execute the reverse skill with given parameters."""
    target = params.get('target') or params.get('snippet')
    if not target:
        return {'status': False, 'summary': 'Target or snippet required', 'result': {}}
    
    mode_str = params.get('mode', 'synergy')
    action = params.get('action', 'analyze')
    
    try:
        mode = ReverseMode(mode_str)
        logic_handler = LogicHandler()
        synthesis_handler = SynthesisHandler()
        
        if action == "analyze":
            result = logic_handler.run(target, mode, **params)
        elif action == "create":
            result = synthesis_handler.run(target, mode, **params)
        else:
            return {'status': False, 'summary': f'Unknown action {action}', 'result': {}}
            
        return {
            'status': True,
            'summary': result.summary,
            'result': {
                'findings': [
                    {
                        'id': f.finder_id,
                        'description': f.description,
                        'severity': f.severity.value,
                        'flag': getattr(f, 'extracted_flag', None),
                        'pattern': getattr(f, 'logic_pattern', None)
                    } for f in result.findings
                ],
                'artifacts': result.artifacts,
                'mode': mode.value
            }
        }
    except Exception as e:
        return {
            'status': False, 
            'summary': f"Reverse analysis failed: {str(e)}",
            'result': {'error': str(e)}
        }

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("skills.reverse.run")

def main():
    parser = argparse.ArgumentParser(description="CTF-Katana Logic Architect (Reverse v2)")
    parser.add_argument("target", nargs="?", help="Target: URL, Local File, or Snippet.")
    parser.add_argument("--mode", "-m", choices=["offensive", "synthesis", "synergy"], default="synergy")
    parser.add_argument("--action", "-a", choices=["analyze", "create", "think"], default="analyze")
    
    # Analysis flags
    parser.add_argument("--snippet", help="Raw code snippet for logic analysis.")
    
    # Synthesis flags
    parser.add_argument("--vuln_id", help="Vulnerability ID to transform into a challenge.")
    parser.add_argument("--language", default="solidity", help="Target language for synthesis.")
    parser.add_argument("--difficulty", default="medium", choices=["easy", "medium", "hard", "expert"])
    
    # Thinking flags
    parser.add_argument("--prompt", help="Designer prompt for logic brainstorming.")
    parser.add_argument("--model", default="groq/llama-3.3-70b-versatile", help="LLM model.")

    args = parser.parse_args()

    # Synergy Hub Logic
    if args.action == "think":
        if not args.prompt:
            logger.error("Error: --prompt required for 'think' action.")
            sys.exit(1)
        designer = REDesigner(model=args.model)
        logger.info(f"[*] Triggering Llama-based logic brainstorming: '{args.prompt}'")
        # In practice, the agent loop uses free-llm-apis/think tools here
        sys.exit(0)

    if not args.target and not args.snippet:
        parser.print_help()
        sys.exit(1)

    # Initialize Handlers
    mode = ReverseMode(args.mode)
    logic_handler = LogicHandler()
    synthesis_handler = SynthesisHandler()

    print(f"[*] Starting {mode.value} mode for: {args.target or 'Snippet'}")

    # Logic-Architect Orchestration
    if args.action == "analyze":
        result = logic_handler.run(args.target or args.snippet, mode, **vars(args))
    elif args.action == "create":
        result = int_handler_result = synthesis_handler.run(args.target or args.snippet, mode, **vars(args))
    else:
        logger.error(f"Error: Unknown action '{args.action}'.")
        sys.exit(1)

    # Display Results
    print(f"[*] Logic Architect Result: {result.summary}")
    if result.findings:
        print(f"[*] Findings ({len(result.findings)}):")
        for finding in result.findings:
            print(f"    [{finding.severity.value}] {finding.finder_id}: {finding.description}")
            if finding.extracted_flag: print(f"        Flag: {finding.extracted_flag}")
            if finding.logic_pattern: print(f"        Pattern: {finding.logic_pattern}")
    
    if result.artifacts:
        print("[*] Generated/Identified Artifacts:")
        for art in result.artifacts:
            print(f"    - {art}")

if __name__ == "__main__":
    main()

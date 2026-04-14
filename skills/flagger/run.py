import os
import argparse
import sys
import json
from pathlib import Path
from typing import Dict, Any, Optional

# Add project root to sys.path for standalone execution
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Standardized imports with fallback
try:
    from skills.flagger.core.intensity import IntensityArchitect
    from skills.flagger.handlers.reverse_handler import ReverseHandler
    from skills.flagger.handlers.web_handler import WebHandler
except ImportError:
    from core.intensity import IntensityArchitect
    from handlers.reverse_handler import ReverseHandler
    from handlers.web_handler import WebHandler

def run(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Programmatic entry point for flagger skill.
    
    Returns:
        Dictionary with status, summary, and result
    """
    flag = params.get('flag')
    level = params.get('level', 'moderate')
    handler_type = params.get('handler', 'reverse')
    template = params.get('template', 'python')
    output_path = params.get('output')
    
    if not flag:
        return {
            'status': False, 
            'summary': 'Failed to execute flagger skill: Flag is required',
            'result': {'error': 'Flag is required.'}
        }
        
    try:
        # 1. Harden Flag
        architect = IntensityArchitect()
        try:
            payload = architect.harden_flag(flag, level)
        except Exception as e:
            return {
                'status': False, 
                'summary': f"Error during flag hardening: {e}",
                'result': {'error': f"Hardening error: {e}"}
            }
            
        # 2. Embed into Challenge
        if handler_type == "reverse":
            handler = ReverseHandler()
        elif handler_type == "web":
            handler = WebHandler()
        else:
            return {
                'status': False, 
                'summary': f"Failed to execute flagger skill: Unknown handler {handler_type}",
                'result': {'error': f"Unknown handler: {handler_type}"}
            }
        
        try:
            final_output = handler.embed(payload, template)
        except Exception as e:
            return {
                'status': False, 
                'summary': f"Error during flag embedding: {e}",
                'result': {'error': f"Embedding error: {e}"}
            }
        
        # 3. Handle Output
        if output_path:
            with open(output_path, "w") as f:
                f.write(final_output)
            return {
                'status': True,
                'summary': f'Flag hardened and embedded in {output_path}',
                'result': {
                    'output_file': output_path,
                    'handler': handler_type,
                    'level': level
                }
            }
        else:
            return {
                'status': True,
                'summary': 'Flag hardened and payload generated',
                'result': {
                    'payload': final_output,
                    'handler': handler_type,
                    'level': level
                }
            }
            
    except Exception as e:
        return {
            'status': False,
            'summary': f"Unhandled exception in flagger: {e}",
            'result': {'error': str(e)}
        }

def main():
    parser = argparse.ArgumentParser(description='Flagger Skill')
    parser.add_argument('--json', help='JSON Parameters')
    parser.add_argument('--test', action='store_true', help='Run sanity check')
    
    # Legacy CLI arguments
    parser.add_argument("flag", nargs='?', help="Original flag string to harden.")
    parser.add_argument("--level", "-n", choices=["moderate", "difficult", "expert"], default="moderate",
                        help="Harden intensity level (Moderate, Difficult, or Expert).")
    parser.add_argument("--handler", "-hnd", choices=["reverse", "web"], default="reverse",
                        help="Target challenge type.")
    parser.add_argument("--template", "-t", default="python",
                        help="Language template (e.g., python, html).")
    parser.add_argument("--output", "-o", help="File to write the hardened payload to.")
    
    args = parser.parse_args()
    
    if args.test:
        print("Running sanity check for flagger...")
        try:
            try:
                from skills.flagger.core.intensity import IntensityArchitect
            except ImportError:
                from core.intensity import IntensityArchitect
            print("✓ Successfully imported IntensityArchitect")
            print("✓ Sanity check passed.")
            sys.exit(0)
        except Exception as e:
            print(f"✗ Sanity check failed: {e}")
            sys.exit(1)

    if args.json:
        try:
            params = json.loads(args.json)
        except json.JSONDecodeError:
            params = vars(args)
    else:
        params = vars(args)
        params.pop('json', None)
        params.pop('test', None)
        params = {k: v for k, v in params.items() if v is not None}
        
    result = run(params)
    print(json.dumps(result, indent=2))

if __name__ == '__main__':
    main()

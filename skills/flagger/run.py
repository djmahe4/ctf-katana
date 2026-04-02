import argparse
import sys
import json
from typing import Dict, Any
from skills.flagger.core.intensity import IntensityArchitect
from skills.flagger.handlers.reverse_handler import ReverseHandler
from skills.flagger.handlers.web_handler import WebHandler

def run(params: Dict[str, Any]) -> Dict[str, Any]:
    """Programmatic entry point for flagger skill."""
    flag = params.get('flag')
    level = params.get('level', 'moderate')
    handler_type = params.get('handler', 'reverse')
    template = params.get('template', 'python')
    output_path = params.get('output')
    
    if not flag:
        return {'status': 'error', 'message': 'Flag is required.'}
        
    # 1. Harden Flag
    architect = IntensityArchitect()
    try:
        payload = architect.harden_flag(flag, level)
    except Exception as e:
        return {'status': 'error', 'message': f"Hardening error: {e}"}
        
    # 2. Embed into Challenge
    if handler_type == "reverse":
        handler = ReverseHandler()
    elif handler_type == "web":
        handler = WebHandler()
    else:
        return {'status': 'error', 'message': f"Unknown handler: {handler_type}"}
    
    try:
        final_output = handler.embed(payload, template)
    except Exception as e:
        return {'status': 'error', 'message': f"Embedding error: {e}"}
    
    # 3. Handle Output
    if output_path:
        with open(output_path, "w") as f:
            f.write(final_output)
        return {'status': 'success', 'output_file': output_path}
    else:
        return {'status': 'success', 'payload': final_output}

def main():
    parser = argparse.ArgumentParser(description="CTF-Katana Flagger: Anti-AI Flag Hardening & Poisoning")
    parser.add_argument("flag", help="Original flag string to harden.")
    parser.add_argument("--level", "-n", choices=["moderate", "difficult", "expert"], default="moderate",
                        help="Harden intensity level (Moderate, Difficult, or Expert).")
    parser.add_argument("--handler", "-hnd", choices=["reverse", "web"], default="reverse",
                        help="Target challenge type.")
    parser.add_argument("--template", "-t", default="python",
                        help="Language template (e.g., python, html).")
    parser.add_argument("--output", "-o", help="File to write the hardened payload to.")
    
    args = parser.parse_args()
    
    result = run({
        'flag': args.flag,
        'level': args.level,
        'handler': args.handler,
        'template': args.template,
        'output': args.output
    })
    
    if result['status'] == 'success':
        if 'output_file' in result:
            print(f"Hardened payload written to: {result['output_file']}")
        else:
            print(result['payload'])
    else:
        print(f"Error: {result['message']}")
        sys.exit(1)

if __name__ == "__main__":
    main()

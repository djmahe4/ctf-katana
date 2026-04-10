import sys
import os
import argparse
import json
import logging
from pathlib import Path
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field

# Standardize path for standalone execution
project_root = Path(__file__).resolve().parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from skills.fuzzing.models import FuzzCategory, FuzzerSeverity
from skills.fuzzing.handlers.web_handler import WebHandler
from skills.fuzzing.handlers.binary_handler import BinaryHandler
from skills.fuzzing.handlers.protocol_handler import ProtocolHandler
from skills.fuzzing.handlers.cloud_handler import CloudHandler
from skills.fuzzing.engines.fuzz_designer import FuzzDesigner
from skills.fuzzing.ffufai.engine import FfufAIEngine

logger = logging.getLogger(__name__)

# Compatibility aliases for tests
WebFuzzer = WebHandler
PAYLOADS = {
    "generic": ["admin", "login", "dashboard"],
    "sqli": ["' OR 1=1--"],
    "xss": ["<script>alert(1)</script>"],
    "lfi": ["../../etc/passwd"],
    "rce": ["; id"],
    "ssti": ["{{7*7}}"]
}

class PayloadType:
    GENERIC = "generic"
    SQLI = "sqli"
    XSS = "xss"
    LFI = "lfi"
    RCE = "rce"
    SSTI = "ssti"

class FuzzMode:
    DIRECTORY = "directory"
    PARAMETER = "parameter"

@dataclass
class FuzzResult:
    url: str
    payload: str
    status_code: int
    content_length: int
    interesting: bool = False

def run(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Execute the fuzzing skill with given parameters.
    """
    target = params.get('target')
    if not target:
        return {
            'status': 'error', 
            'summary': 'Target parameter required'
        }
    
    mode = params.get('mode', 'web')
    
    try:
        if mode == "web":
            handler = WebHandler()
        elif mode == "binary":
            handler = BinaryHandler()
        elif mode == "protocol":
            handler = ProtocolHandler()
        elif mode == "cloud":
            handler = CloudHandler()
        else:
            handler = WebHandler() # Default
            
        result_obj = handler.analyze(target, **params)
        
        # Standardized result structure
        fuzz_data = {
            'findings': [
                {
                    'id': f.vulnerability_id,
                    'description': f.description,
                    'severity': f.severity.value,
                    'payload': f.payload
                } for f in result_obj.findings
            ],
            'category': result_obj.category.value,
            'timestamp': result_obj.timestamp,
            'artifacts': result_obj.artifacts
        }
        
        return {
            'status': 'success',
            'summary': result_obj.summary or f"Fuzzing completed for {target}",
            'result': fuzz_data
        }
    except Exception as e:
        logger.error(f"Fuzzing error: {e}")
        return {
            'status': 'error', 
            'summary': f"Error during fuzzing {mode}: {str(e)}"
        }

def main():
    parser = argparse.ArgumentParser(description="Advanced Fuzzing & Target Designer Tool")
    parser.add_argument("target", nargs="?", help="Target URL, binary path, or protocol description.")
    parser.add_argument("--mode", "-m", choices=["web", "binary", "protocol", "cloud", "auto"], default="auto")
    parser.add_argument("--action", "-a", choices=["fuzz", "analyze", "harness", "think", "mutate", "ffufai"], default="fuzz")
    
    # Web/General flags
    parser.add_argument("--payload-type", "-p", choices=["generic", "sqli", "xss", "lfi", "rce", "ssti"], default="generic")
    parser.add_argument("--wordlist", "-w", help="Custom wordlist path.")
    parser.add_argument("--max-requests", "-n", type=int, default=100)
    
    # Binary/Protocol/Cloud flags
    parser.add_argument("--harness", choices=["libfuzzer", "afl"], default="libfuzzer", help="Harness type to generate.")
    parser.add_argument("--proto", default="custom", help="Protocol name for template generation.")
    parser.add_argument("--cloud", choices=["aws", "azure"], default="aws", help="Cloud provider for scaffolding.")
    
    # Designer flags
    parser.add_argument("--prompt", help="Designer prompt for brainstorming a new fuzzer or challenge.")
    parser.add_argument("--model", default="groq/llama-3.3-70b-versatile", help="LLM model for the designer.")

    args = parser.parse_args()

    if args.action == "think":
        if not args.prompt:
            print(json.dumps({"status": "error", "summary": "--prompt required for 'think' action"}))
            sys.exit(1)
        # Placeholder for complex action
        print(json.dumps({
            "status": "success", 
            "summary": f"Brainstorming triggered for: {args.prompt}",
            "result": {"prompt": args.prompt}
        }))
        sys.exit(0)

    if args.action == "mutate":
        if not args.target:
            print(json.dumps({"status": "error", "summary": "Target required for 'mutate' action"}))
            sys.exit(1)
        try:
            designer = FuzzDesigner()
            script = designer.generate_mutation_script(args.target)
            output_path = f"mutator_{args.target}.py"
            with open(output_path, "w") as f:
                f.write(script)
            print(json.dumps({
                "status": "success",
                "summary": f"Mutator script saved to: {output_path}",
                "result": {"path": output_path}
            }))
        except Exception as e:
            print(json.dumps({"status": "error", "summary": str(e)}))
        sys.exit(0)

    if args.action == "ffufai":
        if not args.target:
            print(json.dumps({"status": "error", "summary": "Target URL required for 'ffufai' action"}))
            sys.exit(1)
        try:
            engine = FfufAIEngine(workspace_root=str(project_root))
            result = engine.run_fuzz(args.target, **vars(args))
            print(json.dumps({
                "status": "success",
                "summary": result.summary,
                "result": {"findings_count": len(result.findings)}
            }))
        except Exception as e:
            print(json.dumps({"status": "error", "summary": str(e)}))
        sys.exit(0)

    if not args.target:
        parser.print_help()
        sys.exit(1)

    # Auto-detect mode if needed
    if args.mode == "auto":
        target_path = Path(args.target)
        if args.target.startswith(("http://", "https://")):
            args.mode = "web"
        elif target_path.suffix.lower() in [".elf", ".exe", ".bin"] or os.access(args.target, os.X_OK):
            args.mode = "binary"
        else:
            args.mode = "web"

    # Execute and output JSON
    result = run(vars(args))
    print(json.dumps(result, indent=2, default=str))

if __name__ == "__main__":
    main()

import sys
import os
import argparse
import json
from pathlib import Path

# Add project skills directory to sys.path for standalone execution
sys.path.append(str(Path(__file__).resolve().parent.parent))

from fuzzing.models import FuzzCategory, FuzzerSeverity
from fuzzing.handlers.web_handler import WebHandler
from fuzzing.handlers.binary_handler import BinaryHandler
from fuzzing.handlers.protocol_handler import ProtocolHandler
from fuzzing.handlers.cloud_handler import CloudHandler
from fuzzing.engines.fuzz_designer import FuzzDesigner

def main():
    parser = argparse.ArgumentParser(description="Advanced Fuzzing & Target Designer Tool")
    parser.add_argument("target", nargs="?", help="Target URL, binary path, or protocol description.")
    parser.add_argument("--mode", "-m", choices=["web", "binary", "protocol", "cloud", "auto"], default="auto")
    parser.add_argument("--action", "-a", choices=["fuzz", "analyze", "harness", "think", "mutate"], default="fuzz")
    
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
            print("Error: --prompt required for 'think' action.")
            sys.exit(1)
        designer = FuzzDesigner(model=args.model)
        print(f"[*] Triggering Llama-based brainstorming for: '{args.prompt}'")
        # In actual usage, the user would invoke the free-llm-apis MCP via the agent.
        sys.exit(0)

    if args.action == "mutate":
        if not args.target:
            print("Error: Target format required for 'mutate' action.")
            sys.exit(1)
        designer = FuzzDesigner()
        print(f"[*] Generating Mutation Engine Script for: {args.target}")
        script = designer.generate_mutation_script(args.target)
        output_path = Path(f"mutator_{args.target}.py")
        with open(output_path, "w") as f:
            f.write(script)
        print(f"[*] Mutator script saved to: {output_path}")
        sys.exit(0)

    if not args.target:
        parser.print_help()
        sys.exit(1)

    target_path = Path(args.target)
    
    # Auto-detect mode if needed
    mode = args.mode
    if mode == "auto":
        if args.target.startswith(("http://", "https://")):
            mode = "web"
        elif target_path.suffix.lower() in [".elf", ".exe", ".bin"] or os.access(args.target, os.X_OK):
            mode = "binary"
        else:
            mode = "web" # Default to web if ambiguous

    # Select handler
    if mode == "web":
        handler = WebHandler()
    elif mode == "binary":
        handler = BinaryHandler()
    elif mode == "protocol":
        handler = ProtocolHandler()
    elif mode == "cloud":
        handler = CloudHandler()
    else:
        print(f"Error: Unknown mode '{mode}'.")
        sys.exit(1)

    # Orchestrate analysis
    print(f"[*] Running {mode} handler against: {args.target}")
    result = handler.analyze(args.target, **vars(args))
    
    # Display results
    print(f"[*] Fuzzing Results for: {args.target}")
    print(f"[*] Category: {result.category.value}")
    print(f"[*] Summary: {result.summary}")
    
    if result.findings:
        print(f"[*] Findings ({len(result.findings)}):")
        for finding in result.findings:
            print(f"    [{finding.severity.value}] {finding.vulnerability_id}: {finding.description}")
            print(f"        Payload: {finding.payload}")
            print(f"        Evidence: {finding.evidence}")
    
    if result.artifacts:
        print("[*] Generated Artifacts:")
        for art in result.artifacts:
            print(f"    - {art}")

if __name__ == "__main__":
    main()

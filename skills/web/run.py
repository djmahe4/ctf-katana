import sys
import os
import argparse
import json
from pathlib import Path

# Add project skills directory to sys.path for standalone execution
sys.path.append(str(Path(__file__).resolve().parent.parent))

from web.models import WebCategory, WebSeverity
from web.handlers.discovery_handler import DiscoveryHandler
from web.handlers.injection_handler import InjectionHandler
from web.handlers.auth_handler import AuthHandler
from web.handlers.xss_handler import XSSHandler
from web.handlers.access_handler import AccessHandler
from web.engines.web_designer import WebDesigner
from web.engines.synthesis_engine import WebSynthesisEngine

def main():
    parser = argparse.ArgumentParser(description="Advanced Web Security & Exploit Orchestrator")
    parser.add_argument("target", nargs="?", help="Target URL or local codebase path.")
    parser.add_argument("--mode", "-m", choices=["auto", "discovery", "injection", "auth", "xss", "access", "synthesis"], default="auto")
    parser.add_argument("--action", "-a", choices=["fuzz", "analyze", "exploit", "think", "mutate", "synthesize"], default="analyze")
    
    # Generic flags
    parser.add_argument("--token", help="JWT or session token for auth analysis.")
    parser.add_argument("--payload-type", "-p", choices=["generic", "sqli", "xss", "lfi", "rce", "ssti"], default="generic")
    parser.add_argument("--wordlist", "-w", help="Custom wordlist path.")
    
    # Designer flags
    parser.add_argument("--prompt", help="Designer prompt for brainstorming a new web attack chain.")
    # Synthesis flags
    parser.add_argument("--server-type", choices=["uvicorn_fastapi", "tomcat_java", "nginx"], help="Server type for synthesis.")
    parser.add_argument("--vuln-type", help="Vulnerability profile for synthesis.")
    parser.add_argument("--output", "-o", default="output/synthesis", help="Output directory for generated challenges.")

    args = parser.parse_args()

    if args.action == "think":
        if not args.prompt:
            print("Error: --prompt required for 'think' action.")
            sys.exit(1)
        designer = WebDesigner(model=args.model)
        print(f"[*] Triggering Llama-based brainstorming for: '{args.prompt}'")
        # Agent uses free-llm-apis MCP via its own reasoning loop
        sys.exit(0)

    if args.mode == "synthesis" or args.action == "synthesize":
        if not args.server_type or not args.vuln_type:
            print("Error: --server-type and --vuln-type are required for synthesis.")
            sys.exit(1)
            
        print(f"[*] Synthesizing {args.server_type} challenge with {args.vuln_type} vulnerability...")
        engine = WebSynthesisEngine(workspace_root=str(Path(__file__).resolve().parent))
        artifacts = engine.generate_challenge(args.server_type, args.vuln_type, args.output)
        
        print(f"[*] Synthesis complete! Artifacts generated in {args.output}:")
        for name, path in artifacts.items():
            print(f"    - {name}: {path}")
            
        # HITL (Human-In-The-Loop) approach for exploit generation
        print("\n" + "="*40)
        print("[HITL] Solvability Verification")
        print("="*40)
        choice = input("[?] Should I generate an exploit script (using web_exploit skill) to verify? [y/N]: ").strip().lower()
        if choice == 'y':
            print("[*] Handing off to web_exploit skill for verification...")
            # Hand-off logic would go here
            #TODO: implement handoff
        else:
            print("[*] Skipping exploit generation.")
        sys.exit(0)

    if not args.target:
        parser.print_help()
        sys.exit(1)

    # Auto-detect mode if needed
    mode = args.mode
    if mode == "auto":
        if args.target.startswith(("http://", "https://")):
             # We start with discovery then chain to other handlers
             mode = "discovery"
        else:
             mode = "discovery" # Default

    # Select handler
    if mode == "discovery":
        handler = DiscoveryHandler()
    elif mode == "injection":
        handler = InjectionHandler()
    elif mode == "auth":
        handler = AuthHandler()
    elif mode == "xss":
        handler = XSSHandler()
    elif mode == "access":
        handler = AccessHandler()
    else:
        print(f"Error: Unknown mode '{mode}'.")
        sys.exit(1)

    # Orchestrate analysis
    print(f"[*] Running {mode} handler against: {args.target}")
    result = handler.analyze(args.target, **vars(args))
    
    # Display results
    print(f"[*] Web Analysis Results for: {args.target}")
    print(f"[*] Category: {result.category.value}")
    print(f"[*] Summary: {result.summary}")
    
    if result.findings:
        print(f"[*] Findings ({len(result.findings)}):")
        for finding in result.findings:
            print(f"    [{finding.severity.value}] {finding.vulnerability_id}: {finding.description}")
            if finding.payload: print(f"        Payload: {finding.payload}")
            if finding.evidence: print(f"        Evidence: {finding.evidence}")
    
    if result.artifacts:
        print("[*] Generated/Identified Artifacts:")
        for art in result.artifacts:
            print(f"    - {art}")

if __name__ == "__main__":
    main()

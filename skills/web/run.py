from typing import Dict, Any, List, Optional
from pathlib import Path

# Fix imports to use absolute paths from project root
from skills.web.models import WebCategory, WebSeverity
from skills.web.handlers.discovery_handler import DiscoveryHandler
from skills.web.handlers.injection_handler import InjectionHandler
from skills.web.handlers.auth_handler import AuthHandler
from skills.web.handlers.xss_handler import XSSHandler
from skills.web.handlers.access_handler import AccessHandler
from skills.web.engines.web_designer import WebDesigner
from skills.web.engines.synthesis_engine import WebSynthesisEngine

def run(params: Dict[str, Any]) -> Dict[str, Any]:
    """Execute the web security skill with given parameters."""
    target = params.get('target')
    mode = params.get('mode', 'auto')
    action = params.get('action', 'analyze')
    
    if action == "think":
        prompt = params.get('prompt')
        if not prompt:
            return {'status': 'error', 'summary': '--prompt required for "think" action'}
        designer = WebDesigner(model=params.get('model'))
        # Designer logic usually involves agentic loop, returning a plan
        return {
            'status': 'success', 
            'summary': f"Brainstorming triggered for: {prompt}",
            'result': {'action': 'think'}
        }

    if mode == "synthesis" or action == "synthesize":
        server_type = params.get('server_type')
        vuln_type = params.get('vuln_type')
        if not server_type or not vuln_type:
            return {'status': 'error', 'summary': '--server-type and --vuln-type are required for synthesis'}
            
        output = params.get('output', 'output/synthesis')
        engine = WebSynthesisEngine(workspace_root=str(Path(__file__).resolve().parent))
        artifacts = engine.generate_challenge(server_type, vuln_type, output)
        
        return {
            'status': 'success',
            'summary': f"Synthesized {server_type} challenge with {vuln_type} vulnerability",
            'result': {
                'artifacts': artifacts
            }
        }

    if not target:
        return {'status': 'error', 'summary': 'Target required'}

    # Auto-detect mode if needed
    if mode == "auto":
        if target.startswith(("http://", "https://")):
             mode = "discovery"
        else:
             mode = "discovery" # Default

    try:
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
            return {'status': 'error', 'summary': f"Unknown mode '{mode}'"}

        result = handler.analyze(target, **params)
        
        return {
            'status': 'success',
            'summary': result.summary,
            'result': {
                'findings': [
                    {
                        'id': f.vulnerability_id,
                        'description': f.description,
                        'severity': f.severity.value,
                        'payload': f.payload,
                        'evidence': f.evidence
                    } for f in result.findings
                ],
                'category': result.category.value,
                'artifacts': result.artifacts
            }
        }
    except Exception as e:
        return {
            'status': 'error', 
            'summary': f"Web analysis failed: {str(e)}",
            'result': {'error_detail': str(e)}
        }

def main():
    import sys
    import os
    import argparse
    import json
    
    # Add project root to sys.path for standalone execution
    root_path = str(Path(__file__).resolve().parent.parent.parent)
    if root_path not in sys.path:
        sys.path.insert(0, root_path)

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
    parser.add_argument("--json", action="store_true", help="Output JSON results")

    args = parser.parse_args()
    params = vars(args)
    
    # Run the standardized entry point
    result = run(params)
    
    if args.json:
        print(json.dumps(result, indent=2))
        sys.exit(0 if result['status'] == 'success' else 1)

    if result['status'] == 'error':
        print(f"Error: {result['summary']}")
        sys.exit(1)
        
    res_data = result.get('result', {})
    if res_data.get('action') == 'think':
        print(result['summary'])
        sys.exit(0)

    if params.get('mode') == 'synthesis' or params.get('action') == 'synthesize':
        print(f"[*] {result['summary']}")
        print(f"[*] Artifacts generated:")
        for name, path in res_data.get('artifacts', {}).items():
            print(f"    - {name}: {path}")
            
        # HITL (Human-In-The-Loop) approach for exploit generation
        print("\n" + "="*40)
        print("[HITL] Solvability Verification")
        print("="*40)
        choice = input("[?] Should I generate an exploit script (using web_exploit skill) to verify? [y/N]: ").strip().lower()
        if choice == 'y':
            print("[*] Handing off to web_exploit skill for verification...")
        sys.exit(0)

    # Display results
    print(f"[*] Web Analysis Results for: {params.get('target')}")
    print(f"[*] Category: {res_data.get('category')}")
    print(f"[*] Summary: {result.get('summary')}")
    
    findings = res_data.get('findings', [])
    if findings:
        print(f"[*] Findings ({len(findings)}):")
        for finding in findings:
            print(f"    [{finding['severity']}] {finding['id']}: {finding['description']}")
            if finding.get('payload'): print(f"        Payload: {finding['payload']}")
            if finding.get('evidence'): print(f"        Evidence: {finding['evidence']}")
    
    artifacts = res_data.get('artifacts', [])
    if artifacts:
        print("[*] Generated/Identified Artifacts:")
        if isinstance(artifacts, list):
            for art in artifacts:
                print(f"    - {art}")
        else:
            for name, path in artifacts.items():
                print(f"    - {name}: {path}")

if __name__ == "__main__":
    main()

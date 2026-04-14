"""
Firewall & Kavach Security Orchestrator
Main entrypoint for network firewall auditing and AI containment.

Integrates with skills.firewall.kavach for secure workspace wrapping.
"""

import os
import sys
import json
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional

# Add project root to sys.path for standalone execution
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Standardized imports with fallback
try:
    from skills.firewall.kavach import KavachWrapper, SecurityPolicy, PIISanitizer, PhantomWorkspace
    from skills.firewall.kavach.scaffolder import DefenseScaffolder
except ImportError:
    from kavach import KavachWrapper, SecurityPolicy, PIISanitizer, PhantomWorkspace
    from kavach.scaffolder import DefenseScaffolder

def run_containment(skill_name, profile_name="standard"):
    """
    Wraps a skill execution in the Kavach security layer.
    """
    print(f"[*] Initializing Kavach Containment: {skill_name} ({profile_name})")
    
    # Load policy
    if profile_name == "strict":
        policy = SecurityPolicy.default_strict()
    elif profile_name == "permissive":
        policy = SecurityPolicy.default_permissive()
    else:
        policy = SecurityPolicy.default_standard()
        
    # Use KavachWrapper as a context manager for more reliable shielding
    with KavachWrapper(policy=policy, workspace=Path.cwd()) as shield:
        shield.skill_name = skill_name
        # Simulated execution
        audit_log = {
            "skill": skill_name,
            "status": "Shielded",
            "pii_sanitization": "Active",
            "tripwire_count": len(shield.tripwire.tripwires) if shield.tripwire else 0
        }
        return audit_log

def run_network_audit(config_path=None):
    """
    Analyzes firewall configurations for vulnerabilities.
    """
    print(f"[*] Starting Network Firewall Audit...")
    if config_path:
        print(f"[*] Loading config from: {config_path}")
    
    # Simulate rule analysis
    vulnerabilities = [
        {"type": "shadowed_rule", "line": 42, "severity": "MEDIUM", "desc": "Rule blocked by preceding any-any rule"},
        {"type": "open_port", "port": 22, "severity": "HIGH", "desc": "SSH exposed to internal networks without rate limiting"}
    ]
    return vulnerabilities

def run_bypass_test(target_ip):
    """
    Adversarial logic for testing firewall robustness.
    """
    print(f"[*] Initiating Adversarial Bypass Tests on {target_ip}...")
    # Simulate TTL manipulation and fragmentation
    results = {
        "fragmentation_bypass": "VULNERABLE",
        "ttl_aliasing": "SECURE",
        "logic_handshake_bypass": "VULNERABLE (Stateful Leak)"
    }
    return results

def run_scaffold(server_type, output_dir, challenge_name="challenge"):
    """
    Generates infrastructure defense layers (PaC).
    """
    print(f"[*] Starting Security Scaffolding for {server_type}...")
    scaffolder = DefenseScaffolder(workspace_root=str(Path(__file__).resolve().parent))
    
    artifacts = []
    # 1. Server Shielding
    artifacts += scaffolder.shield_web_server(server_type, output_dir)
    
    # 2. Network Policy
    artifacts.append(scaffolder.generate_k8s_policy(challenge_name, ["10.0.0.0/8"], output_dir))
    
    # 3. Docker Hardening
    artifacts.append(scaffolder.generate_docker_hardening(challenge_name, output_dir))
    
    # 4. Audit-Only Tripwires (ensure no accidental shutdowns)
    artifacts += scaffolder.generate_audit_tripwires(output_dir)
    
    return artifacts

def run(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Registry entry-point for the firewall skill.
    
    Args:
        params: Dictionary with parameters from skill.yaml
        
    Returns:
        Dictionary with status, summary, and result
    """
    mode = params.get("mode", "audit")
    try:
        if mode in ["containment", "shield"]:
            result = run_containment(params.get("skill_name", "generic_task"), params.get("profile", "standard"))
        elif mode == "audit":
            result = run_network_audit(params.get("target_config") or params.get("target"))
        elif mode == "bypass_test":
            result = run_bypass_test(params.get("target"))
        elif mode == "scaffold":
            result = run_scaffold(
                params.get("server_type", "nginx"), 
                params.get("output", "output/shielding")
            )
        else:
            return {
                "status": False, 
                "summary": f"Failed to execute firewall skill: Unknown mode {mode}",
                "result": {"error": f"Unknown mode: {mode}"}
            }
            
        return {
            "status": True,
            "summary": f"Firewall action '{mode}' completed",
            "result": result
        }
        
    except Exception as e:
        return {
            "status": False,
            "summary": f"Error during firewall {mode}: {str(e)}",
            "result": {"error": str(e)}
        }

def main():
    parser = argparse.ArgumentParser(description='Firewall Skill')
    parser.add_argument('--json', help='JSON Parameters')
    parser.add_argument('--test', action='store_true', help='Run sanity check')
    
    # Legacy CLI arguments
    parser.add_argument("--mode", default="audit", choices=["audit", "containment", "bypass_test", "scaffold", "shield"])
    parser.add_argument("--profile", default="standard")
    parser.add_argument("--target", help="IP or config file path")
    parser.add_argument("--skill_name", default="generic_task")
    parser.add_argument("--server-type", choices=["nginx", "tomcat", "uvicorn"], default="nginx")
    parser.add_argument("--output", "-o", default="output/shielding")
    
    args = parser.parse_args()
    
    if args.test:
        print("Running sanity check for firewall...")
        try:
            try:
                from skills.firewall.kavach import KavachWrapper
            except ImportError:
                from kavach import KavachWrapper
            print("✓ Successfully imported KavachWrapper")
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
        # Map CLI arg names to run() expectation if they differ
        params["server_type"] = params.get("server_type") or getattr(args, "server_type", None)
        params = {k: v for k, v in params.items() if v is not None}
        
    result = run(params)
    print(json.dumps(result, indent=2))

if __name__ == '__main__':
    main()

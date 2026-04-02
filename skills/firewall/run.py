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

# Add the parent directory to sys.path to allow imports from skills.firewall
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from firewall.kavach import KavachWrapper, SecurityPolicy, PIISanitizer, PhantomWorkspace
from firewall.kavach.scaffolder import DefenseScaffolder

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

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", default="audit", choices=["audit", "containment", "bypass_test", "scaffold", "shield"])
    parser.add_argument("--profile", default="standard")
    parser.add_argument("--target", help="IP or config file path")
    parser.add_argument("--skill_name", default="generic_task")
    parser.add_argument("--server-type", choices=["nginx", "tomcat", "uvicorn"], default="nginx")
    parser.add_argument("--output", "-o", default="output/shielding")
    args = parser.parse_args()
    
    if args.mode == "containment" or args.mode == "shield":
        result = run_containment(args.skill_name, args.profile)
    elif args.mode == "audit":
        result = run_network_audit(args.target)
    elif args.mode == "bypass_test":
        result = run_bypass_test(args.target)
    elif args.mode == "scaffold":
        result = run_scaffold(args.server_type, args.output)
        
    print(json.dumps(result, indent=2))

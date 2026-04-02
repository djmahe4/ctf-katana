import os
import logging
from typing import Dict, List, Optional
from pathlib import Path

logger = logging.getLogger(__name__)

class DefenseScaffolder:
    """
    Scaffolds security configurations and network policies for challenges.
    Provides 'Shielding' layers for Uvicorn, Tomcat, and Nginx.
    """

    def __init__(self, workspace_root: str):
        self.workspace_root = Path(workspace_root)
        self.templates_dir = self.workspace_root / "templates" / "shielding"

    def shield_web_server(self, server_type: str, output_dir: str) -> List[str]:
        """
        Generates security-hardened configuration files for the specified server.
        """
        target_dir = Path(output_dir)
        target_dir.mkdir(parents=True, exist_ok=True)
        
        artifacts = []
        
        # 1. Server-specific hardening
        server_tmpl_dir = self.templates_dir / server_type
        if server_tmpl_dir.exists():
            for tmpl in server_tmpl_dir.glob("*.template"):
                new_filename = tmpl.name.replace(".template", "")
                target_path = target_dir / new_filename
                
                with open(tmpl, "r") as f:
                    content = f.read()
                
                # Custom replacement logic can go here
                with open(target_path, "w") as f:
                    f.write(content)
                artifacts.append(str(target_path))
                
        return artifacts

    def generate_k8s_policy(self, challenge_name: str, allowed_cidrs: List[str], output_dir: str) -> str:
        """
        Generates a Kubernetes NetworkPolicy YAML for challenge isolation.
        """
        target_dir = Path(output_dir)
        target_dir.mkdir(parents=True, exist_ok=True)
        
        # Simple policy: Deny all ingress except from allowed CIDRs
        policy = f"""apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: {challenge_name}-isolation
spec:
  podSelector:
    matchLabels:
      app: {challenge_name}
  policyTypes:
  - Ingress
  ingress:
  - from:
"""
        for cidr in allowed_cidrs:
            policy += f"    - ipBlock:\n        cidr: {cidr}\n"
        
        output_path = target_dir / "network-policy.yaml"
        with open(output_path, "w") as f:
            f.write(policy)
            
        return str(output_path)

    def generate_docker_hardening(self, challenge_name: str, output_dir: str) -> str:
        """
        Generates a hardened docker-compose fragment.
        """
        target_dir = Path(output_dir)
        target_dir.mkdir(parents=True, exist_ok=True)
        
        hardened_yaml = f"""# Docker Hardening for {challenge_name}
services:
  {challenge_name}:
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp
      - /run
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    deploy:
      resources:
        limits:
          cpus: '0.1'
          memory: 128M
"""
        output_path = target_dir / "docker-hardened.yml"
        with open(output_path, "w") as f:
            f.write(hardened_yaml)
            
        return str(output_path)

    def generate_audit_tripwires(self, output_dir: str) -> List[str]:
        """
        Deploys honeypot files in 'AUDIT' mode for challenge monitoring.
        """
        target_dir = Path(output_dir)
        target_dir.mkdir(parents=True, exist_ok=True)
        
        # We manually create these to ensure they are marked for the web skill's security logic
        # if it chooses to use them for active logging.
        tripwires = {
            "system_auth_tokens.json": '{"aws_key": "AKIA1234567890ABCDEF", "mode": "audit"}',
            "credentials.txt": "username: ctf_admin\npassword: ThisIsAFakePassword123",
        }
        
        artifacts = []
        for name, content in tripwires.items():
            path = target_dir / name
            with open(path, "w") as f:
                f.write(content)
            artifacts.append(str(path))
            
        return artifacts

import os
import logging
from typing import Dict, List, Optional, Any
from pathlib import Path

logger = logging.getLogger(__name__)

class WebSynthesisEngine:
    """
    Engine for synthesizing vulnerable web server environments.
    Supports Uvicorn, Tomcat, and Nginx with Docker and Kubernetes configurations.
    """

    def __init__(self, workspace_root: str):
        self.workspace_root = Path(workspace_root)
        self.templates_dir = self.workspace_root / "templates" / "synthesis"

    def get_available_servers(self) -> List[str]:
        return ["uvicorn_fastapi", "tomcat_java", "nginx"]

    def get_vulnerability_profiles(self, server_type: str) -> List[str]:
        profiles = {
            "uvicorn_fastapi": ["pydantic_bypass", "dependency_confusion", "open_redirect"],
            "tomcat_java": ["ghostcat", "manager_leak", "traversal"],
            "nginx": ["alias_traversal", "header_injection", "proxy_leak"]
        }
        return profiles.get(server_type, [])

    def generate_challenge(self, server_type: str, vuln_type: str, output_dir: str) -> Dict[str, str]:
        """
        Generates Docker and Kubernetes artifacts for a specific challenge.
        """
        if server_type not in self.get_available_servers():
            raise ValueError(f"Unknown server type: {server_type}")
        
        target_dir = Path(output_dir)
        target_dir.mkdir(parents=True, exist_ok=True)
        
        artifacts = {}
        
        # 1. Generate Dockerfile
        docker_tmpl = self.templates_dir / server_type / "Dockerfile.template"
        if docker_tmpl.exists():
            with open(docker_tmpl, "r") as f:
                content = f.read()
            
            # Simple replacement logic (can be made more complex with Jinja2 if available)
            content = content.replace("{{ VULN_TYPE }}", vuln_type)
            
            docker_file_path = target_dir / "Dockerfile"
            with open(docker_file_path, "w") as f:
                f.write(content)
            artifacts["Dockerfile"] = str(docker_file_path)
            
        # 2. Generate Kubernetes Deployment
        k8s_tmpl = self.templates_dir / server_type / "deployment.yaml.template"
        if k8s_tmpl.exists():
            with open(k8s_tmpl, "r") as f:
                content = f.read()
            
            content = content.replace("{{ VULN_TYPE }}", vuln_type)
            content = content.replace("{{ CHALLENGE_NAME }}", f"{server_type}-{vuln_type}".replace("_", "-"))
            
            k8s_file_path = target_dir / "deployment.yaml"
            with open(k8s_file_path, "w") as f:
                f.write(content)
            artifacts["deployment.yaml"] = str(k8s_file_path)

        return artifacts

    def get_hitl_exploit_prompt(self, server_type: str, vuln_type: str) -> str:
        """
        Returns a prompt for the user to confirm/edit exploit generation.
        """
        return (f"[*] Challenge synthesized: {server_type} ({vuln_type})\n"
                f"[*] Should I now generate a matching 'web_exploit' script to verify its solvability?\n"
                f"[*] (Y/N/Edit)")

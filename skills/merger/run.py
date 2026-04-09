import os
import json
import yaml
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

def run(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Local skill entrypoint for merging multiple CTF challenge components.
    """
    selected_components = params.get("selected_components", [])
    target_session = params.get("target_session", "merged_challenge")
    layout_plan = params.get("layout_plan", {}) # Provided by Agentic Execution
    
    if not selected_components:
        return {"status": "error", "message": "No components selected for merging."}

    logger.info(f"Merging {len(selected_components)} components for session: {target_session}")

    merged_files = []
    compose_services = {}
    landing_links = []

    # 1. Process each component based on the layout plan
    for i, component in enumerate(selected_components):
        service_info = layout_plan.get("services", [])[i] if i < len(layout_plan.get("services", [])) else None
        
        if not service_info:
            # Fallback remapping if layout_plan is incomplete
            service_name = component.get("name", f"service_{i}").lower().replace(" ", "_")
            external_port = 8080 + i + 1
            internal_port = 80
        else:
            service_name = service_info["name"]
            external_port = service_info["external_port"]
            internal_port = service_info["internal_port"]

        # Extract files and adjust paths if necessary
        files = component.get("generated_files", [])
        component_dir = f"services/{service_name}"
        
        for file in files:
            # Adjust file name to be relative to the service directory
            orig_name = file.get("name", "artifact")
            file_content = file.get("content", "")
            merged_files.append({
                "name": f"{component_dir}/{orig_name}",
                "content": file_content
            })

        # Define service in Docker-Compose
        compose_services[service_name] = {
            "build": f"./{component_dir}",
            "ports": [f"{external_port}:{internal_port}"],
            "networks": ["katana_net"]
        }
        
        landing_links.append({
            "name": component.get("name", service_name).title(),
            "url": f"http://localhost:{external_port}"
        })

    # 2. Generate Unified Docker-Compose
    docker_compose = {
        "version": "3.8",
        "services": compose_services,
        "networks": {
            "katana_net": {
                "driver": "bridge"
            }
        }
    }
    
    merged_files.append({
        "name": "docker-compose.yml",
        "content": yaml.dump(docker_compose, sort_keys=False)
    })

    # 3. Generate Landing Page
    landing_html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Katana Unified - {target_session}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f172a; color: #f8fafc; display: flex; flex-direction: column; align-items: center; padding: 2rem; }}
        .container {{ max-width: 800px; width: 100%; }}
        h1 {{ color: #38bdf8; border-bottom: 2px solid #1e293b; padding-bottom: 1rem; }}
        .card {{ background: #1e293b; padding: 1.5rem; border-radius: 0.5rem; margin-top: 1rem; border: 1px solid #334155; transition: transform 0.2s; }}
        .card:hover {{ transform: translateY(-2px); border-color: #38bdf8; }}
        a {{ color: #38bdf8; text-decoration: none; font-weight: bold; font-size: 1.2rem; }}
        p {{ color: #94a3b8; font-size: 0.9rem; margin-top: 0.5rem; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Katana Unified Challenges</h1>
        <p>Session ID: {target_session}</p>
        {''.join([f'<div class="card"><a href="{l["url"]}" target="_blank">{l["name"]}</a><p>Access via port {l["url"].split(":")[-1]}</p></div>' for l in landing_links])}
    </div>
</body>
</html>
    """
    
    merged_files.append({
        "name": "index.html",
        "content": landing_html
    })

    return {
        "status": "success",
        "merged_challenge": {
            "name": f"Unified: {target_session}",
            "category": "web-merged",
            "generated_files": merged_files,
            "manifest": {
                "components": [c.get("name") for c in selected_components],
                "layout": layout_plan
            }
        }
    }

if __name__ == "__main__":
    # Test script would go here
    pass

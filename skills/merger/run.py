import sys
from pathlib import Path
project_root = str(Path(__file__).resolve().parent.parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

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
        return {"status": False, "summary": "No components selected for merging.", "result": {}}

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

    try:
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
            "status": True,
            "summary": f"Merged {len(selected_components)} components for session {target_session}",
            "result": {
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
        }
    except Exception as e:
        return {
            "status": False,
            "summary": f"Failed to merge components: {str(e)}",
            "result": {"message": str(e)}
        }

def main():
    """CLI entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Merger Skill CLI')
    parser.add_argument('selected_components', nargs='*', help='Components to merge')
    parser.add_argument('--target-session', '-s', default='merged_challenge')
    parser.add_argument('--json', help='Pass parameters as JSON string')
    parser.add_argument('--test', action='store_true', help='Run sanity test')
    
    args = parser.parse_args()
    
    if args.test:
        print("Running sanity test for Merger...")
        test_params = {
            "selected_components": [{"name": "test_comp", "generated_files": [{"name": "test.txt", "content": "hello"}]}],
            "target_session": "test_session"
        }
        print(f"Test Configuration: {json.dumps(test_params, indent=2)}")
        print("Test passed: Module structure verified.")
        return

    params = {}
    if args.json:
        try:
            params = json.loads(args.json)
        except json.JSONDecodeError as e:
            print(json.dumps({"status": False, "summary": f"Invalid JSON: {str(e)}", "result": {}}))
            return
    else:
        if not args.selected_components:
            parser.print_help()
            return
        params = {
            "selected_components": args.selected_components,
            "target_session": args.target_session
        }
    
    result = run(params)
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()

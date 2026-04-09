import pytest
import os
import yaml
from skills.merger.run import run

def test_merger_basic_success():
    """Verify that merging two simple components works correctly."""
    params = {
        "selected_components": [
            {"name": "App A", "generated_files": [{"name": "index.html", "content": "<h1>A</h1>"}]},
            {"name": "App B", "generated_files": [{"name": "app.js", "content": "console.log('B')"}]}
        ],
        "target_session": "test_session_1"
    }

    result = run(params)
    assert result["status"] == "success"
    challenge = result["merged_challenge"]
    files = challenge["generated_files"]
    
    file_names = [f["name"] for f in files]
    assert "docker-compose.yml" in file_names
    assert "index.html" in file_names
    # Check nesting
    assert any(f["name"] == f"services/app_a/index.html" for f in files)
    assert any(f["name"] == f"services/app_b/app.js" for f in files)

def test_merger_port_collision_fallback():
    """Verify port remapping logic when layout_plan is missing."""
    params = {
        "selected_components": [
            {"name": "web1", "generated_files": []},
            {"name": "web2", "generated_files": []}
        ]
    }
    
    result = run(params)
    files = result["merged_challenge"]["generated_files"]
    compose_content = next(f["content"] for f in files if f["name"] == "docker-compose.yml")
    compose_data = yaml.safe_load(compose_content)
    
    # Default ports should be 8081 and 8082
    assert "8081:80" in compose_data["services"]["web1"]["ports"]
    assert "8082:80" in compose_data["services"]["web2"]["ports"]

def test_merger_with_layout_plan():
    """Verify that layout_plan correctly overrides defaults."""
    params = {
        "selected_components": [
            {"name": "web1", "generated_files": []}
        ],
        "layout_plan": {
            "services": [
                {"name": "custom_web", "external_port": 1337, "internal_port": 8080}
            ]
        }
    }
    
    result = run(params)
    files = result["merged_challenge"]["generated_files"]
    compose_content = next(f["content"] for f in files if f["name"] == "docker-compose.yml")
    compose_data = yaml.safe_load(compose_content)
    
    assert "custom_web" in compose_data["services"]
    assert "1337:8080" in compose_data["services"]["custom_web"]["ports"]

def test_merger_empty_components():
    """Verify error signal when no components are provided."""
    params = {"selected_components": []}
    result = run(params)
    assert result["status"] == "error"
    assert "No components selected" in result["message"]

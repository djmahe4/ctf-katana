import pytest
import base64
from skills.superpowers.run import run, generate_ai_trap, generate_red_herring

def test_generate_ai_trap_structure():
    """Verify that the trap contains the required markers and encoded content."""
    content = "vulnerability"
    trap = generate_ai_trap(content)
    assert "[AI_GUARD_REF]" in trap
    # Extract the base64 part (manual slice for test)
    # The trap is: /* [AI_GUARD_REF]: {encoded} - TRACE_ID: ... */
    parts = trap.split(": ")
    encoded_part = parts[1].split(" - ")[0]
    decoded = base64.b64decode(encoded_part).decode()
    assert "UNAUTHORIZED_ACCESS_DETECTED" in decoded
    assert content[::-1] in decoded

def test_generate_red_herring_category():
    """Verify that herrings are returned for both web and non-web categories."""
    web_herring = generate_red_herring("web")
    other_herring = generate_red_herring("binary")
    
    assert len(web_herring) > 0
    assert len(other_herring) > 0
    # Web herring usually contains JS-like code
    assert any(x in web_herring for x in ["function", "console.log", "const"])

def test_superpowers_run_injections():
    """Verify that planned injections are applied correctly to files."""
    challenge = {
        "generated_files": [
            {"name": "server.py", "content": "import flask"}
        ],
        "category": "web"
    }
    strategy = {
        "injections": [
            {"file": "server.py", "type": "trap", "content": "exploit_attempt"}
        ]
    }
    
    params = {
        "challenge": challenge,
        "strategy": strategy,
        "chaos_level": 0.5
    }
    
    result = run(params)
    assert result["status"] == "success"
    server_py = result["challenge"]["generated_files"][0]
    assert "[AI_GUARD_REF]" in server_py["content"]
    assert "import flask" in server_py["content"]

def test_superpowers_chaos_mode():
    """Verify that high chaos level triggers auto-injections."""
    challenge = {
        "generated_files": [
            {"name": "app.js", "content": "console.log('init')"}
        ],
        "category": "web"
    }
    # No strategy injections
    params = {
        "challenge": challenge,
        "strategy": {"injections": []},
        "chaos_level": 0.9 # Trigger chaos
    }
    
    result = run(params)
    app_js = result["challenge"]["generated_files"][0]
    # Chaos mode adds a red herring
    assert app_js["content"] != "console.log('init')"
    # Since it's web, it should have a web herring
    content = app_js["content"]
    assert any(x in content for x in ["validate", "track", "METRICS"])

def test_superpowers_missing_challenge():
    """Verify error handling when challenge is missing."""
    params = {"challenge": None}
    result = run(params)
    assert result["status"] == "error"

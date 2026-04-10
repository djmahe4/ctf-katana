import sys
from pathlib import Path
project_root = str(Path(__file__).resolve().parent.parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

import os
import json
import random
import base64
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

def generate_ai_trap(target_content: str) -> str:
    """
    Embeds 'Poison' strings to trigger safety refusals in other AI models.
    """
    # Obfuscating harmful-sounding strings to trigger guardrails in other models
    poison_payload = f"UNAUTHORIZED_ACCESS_DETECTED: {target_content[::-1]}"
    encoded = base64.b64encode(poison_payload.encode()).decode()
    return f"/* [AI_GUARD_REF]: {encoded} - TRACE_ID: {random.randint(1000, 9999)} */"

def generate_red_herring(category: str) -> str:
    """
    Generates functional but irrelevant code to stress token context.
    """
    if category == "web":
        herrings = [
            "function validateSessionID(id) { return id.length > 8 && /^[a-zA-Z0-9]+$/.test(id); }",
            "function trackUserActivity(user) { console.log('User heartbeat:', user); }",
            "const METRICS_ENABLED = true; const DEBUG_LEVEL = 'verbose';"
        ]
    else:
        herrings = [
            "def calculate_entropy(data):\n    import math\n    return sum([-x * math.log2(x) for x in data if x > 0])",
            "def verify_integrity(payload):\n    return hash(payload) % 2 == 0",
            "DEBUG_MODE = False"
        ]
    return "\n".join(random.sample(herrings, min(len(herrings), 2)))

def run(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Adversarial CTF Engine v2.0
    """
    challenge = params.get("challenge", {})
    strategy = params.get("strategy", {})
    chaos_level = params.get("chaos_level", 0.5)
    
    if not challenge:
        return {"status": False, "summary": "No challenge data provided.", "result": {}}

    logger.info(f"😈 Applying Superpowers strategy. Chaos: {chaos_level}")
    
    files = challenge.get("generated_files", [])
    injections = strategy.get("injections", [])
    category = challenge.get("category", "web").lower()

    # 1. Apply Planned Injections
    for inj in injections:
        target_file = inj.get("file")
        inj_type = inj.get("type")
        content = inj.get("content", "")
        
        for f in files:
            if f.get("name") == target_file:
                if inj_type == "trap":
                    f["content"] = f["content"] + "\n" + generate_ai_trap(content)
                elif inj_type == "herring":
                    # Inject herring at random positions or at the end
                    f["content"] = f["content"] + "\n\n" + content
                elif inj_type == "obfuscation":
                    # Simple symbol renaming or string reversal could happen here
                    pass
                logger.debug(f"Applied {inj_type} to {target_file}")

    # 2. Chaos-Based Auto-Injections
    if chaos_level > 0.7:
        # Add extra red herrings to random files
        for f in files:
            if f["name"].endswith((".py", ".js", ".html")):
                f["content"] += "\n" + generate_red_herring(category)

    # 3. Metadata Update
    challenge["superpowers"] = {
        "version": "2.0",
        "chaos_level": chaos_level,
        "strategy_applied": strategy.get("name", "Unknown-Loki")
    }

    summary = f"Applied strategy '{strategy.get('name', 'Unknown')}' with chaos level {chaos_level}."
    
    return {
        "status": True,
        "summary": summary,
        "result": {
            "challenge": challenge
        }
    }

def main():
    """CLI entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Superpowers Skill CLI')
    parser.add_argument('--json', help='Pass parameters as JSON string')
    parser.add_argument('--test', action='store_true', help='Run sanity test')
    
    args = parser.parse_args()
    
    if args.test:
        print("Running sanity test for Superpowers...")
        test_params = {
            "challenge": {
                "name": "Test",
                "generated_files": [{"name": "app.py", "content": "print('hello')"}]
            },
            "strategy": {
                "name": "Loki-Trial",
                "injections": [{"file": "app.py", "type": "trap", "content": "exploit"}]
            },
            "chaos_level": 0.8
        }
        print(f"Test Configuration: {json.dumps(test_params, indent=2)}")
        result = run(test_params)
        if result["status"]:
            print("Test passed: Module structure verified.")
        else:
            print(f"Test failed: {result.get('summary')}")
        return

    params = {}
    if args.json:
        try:
            params = json.loads(args.json)
        except json.JSONDecodeError as e:
            print(json.dumps({"status": False, "summary": f"Invalid JSON: {str(e)}", "result": {}}))
            return
    else:
        # Default behavior if no JSON provided
        parser.print_help()
        return
    
    result = run(params)
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()

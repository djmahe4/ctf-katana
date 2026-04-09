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
        return {"status": "error", "message": "No challenge data provided."}

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

    return {
        "status": "success",
        "challenge": challenge
    }

if __name__ == "__main__":
    # Test stub
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
    print(json.dumps(run(test_params), indent=2))

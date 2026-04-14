import requests
import json
import os
from typing import Dict, Any, Optional

class AgenticExplainer:
    """
    Interfaces with Ollama to generate educational walkthroughs.
    """
    def __init__(self, model: str = "llama3", host: str = "http://localhost:11434"):
        self.model = os.environ.get("KATANA_OLLAMA_MODEL", model)
        self.host = os.environ.get("KATANA_OLLAMA_HOST", host)
        
    def generate_walkthrough(self, tool_name: str, result: Any, context: str = "") -> str:
        prompt = f"""
You are the 'Purple Engine' AI Tutor. Your goal is to explain a CTF challenge solution step to a B.Tech student clearly.

### TOOL EXECUTED: {tool_name}
### RESULT: {json.dumps(result, indent=2)}
### ADDITIONAL CONTEXT: {context}

---
INSTRUCTIONS:
1. Explain **Why** this tool was used in the current phase of the 'Purple Loop'.
2. Explain **What** the result means in plain English.
3. Provide a 'Learning Moment' – one key cybersecurity concept related to this result.
4. Use a professional, encouraging tone.
"""
        try:
            response = requests.post(
                f"{self.host}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False
                }
            )
            response.raise_for_status()
            return response.json().get("response", "Error: No response from Ollama.")
        except Exception as e:
            return f"❌ Failed to connect to Ollama ({self.model}): {str(e)}"

# Global explainer instance
_explainer = AgenticExplainer()

def get_explainer():
    return _explainer

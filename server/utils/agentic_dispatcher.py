import logging
import json
import asyncio
import httpx
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

class AgenticSkillDispatcher:
    """
    The 'Brain' of the Purple Loop.
    Converts PipelineMemory context into precise parameters for local Python skills
    using LLM-driven observation and preparation.
    """
    
    def __init__(self, workspace_root: str):
        self.workspace_root = workspace_root
        
    async def prepare_params(self, skill_name: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Uses Agentic Reasoning to analyze memory context and prepare parameters for a skill.
        For challenge generation, it performs the 'Deep Thinking' step via local Ollama.
        """
        logger.info(f"🧠 Agentic Preparation for skill: {skill_name}")
        
        research = context.get("research_results", {})
        purple_loop = research.get("purple_loop", {})
        
        if skill_name == "scaffolding":
            # 1. Perform Deep Thinking (Ollama Local)
            draft = await self._draft_challenge_code(research)
            
            # 2. Return params with HITL Flag
            params = {
                "finding": purple_loop.get("finding", {}),
                "vuln_type": research.get("local", {}).get("category", "vulnerability"),
                "draft": draft,
                "difficulty": "medium",
                "category": research.get("local", {}).get("category", "web"),
                "interactive": True # Triggers HITL Gate in Orchestrator
            }
            return params
            
        elif skill_name == "flagger":
            challenge = context.get("challenge", {})
            return {
                "challenge_id": challenge.get("id"),
                "flag_format": "katana{...}"
            }

        return {}

    async def _get_best_model(self) -> str:
        """Discovers available models and returns the best match."""
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get("http://localhost:11434/api/tags")
                if resp.status_code == 200:
                    models = [m['name'] for m in resp.json().get('models', [])]
                    # Priority list
                    priorities = ["mistral-nemo:latest", "mistral-nemo", "llama3:latest", "llama3"]
                    for p in priorities:
                        if p in models:
                            return p
                    if models:
                        return models[0]
        except Exception as e:
            logger.warning(f"Model discovery failed: {e}")
        return "mistral-nemo:latest" # Default fallback

    async def _draft_challenge_code(self, research: Dict[str, Any]) -> Dict[str, Any]:
        """
        The 'Deep Thinking' step: Orchestrates local Ollama to synthesize the challenge.
        It identifies the core vulnerability from intelligence snippets and manifests it in code.
        """
        logger.info("🎨 Drafting challenge artifacts via Local Ollama (Deep Thinking)...")
        
        snippets = research.get('purple_loop', {}).get('snippets', [])
        # Grounding: Use up to 5 highest-relevance snippets
        content_context = "\n".join([f"- {s.get('context', 'Snippet')}: {s.get('content', '')}" for s in snippets[:5]])

        # ... (prompt remains the same) ...
        # [REDACTED FOR BREVITY - assuming prompt is unchanged or slightly optimized]
        
        # [DEBUG: Recovering prompt from previous lines to ensure complete replacement]
        prompt = f"""
        Analyze the following vulnerability research snippets and synthesize a complete, vulnerable CTF challenge source code. 
        The output must be in valid JSON format for direct file manifestation.

        Snippets Data:
        {content_context}

        Requirements:
        1. **Core Vulnerability**: Identify and implement the exact vulnerability described in the snippets.
        2. **Minimal Application**: Create a realistic web application (Python/Flask or Node/Express) that demonstrates the vulnerability.
        3. **Exploitable**: Ensure the vulnerability is exploitable exactly as described in the research.
        4. **Flag Location**: Include a flag at `/app/flag.txt` or similar identifiable location.
        5. **Docker Support**: Provide a `Dockerfile` for easy deployment.

        Output Format (Strict JSON):
        {{
            "explanation": "Brief reasoning of the vulnerability implementation.",
            "files": [
                {{
                    "name": "app.py",
                    "content": "Full source code here..."
                }},
                {{
                    "name": "Dockerfile",
                    "content": "Dockerfile content here..."
                }}
            ]
        }}

        Constraints:
        - Output ONLY valid JSON. 
        - Ensure reproducing the vulnerability requires the specific logic from the snippets.
        - No conversational filler.
        """

        model = await self._get_best_model()
        logger.info(f"Using Ollama model: {model}")

        # Try multiple endpoints for resilience
        endpoints = [
            ("http://localhost:11434/api/generate", {"model": model, "prompt": prompt, "stream": False, "format": "json"}),
            ("http://localhost:11434/v1/chat/completions", {
                "model": model, 
                "messages": [{"role": "user", "content": prompt}],
                "response_format": {"type": "json_object"}
            })
        ]

        last_error = None
        for url, payload in endpoints:
            try:
                async with httpx.AsyncClient(timeout=90.0) as client:
                    response = await client.post(url, json=payload)
                    if response.status_code == 200:
                        result = response.json()
                        # Extract response based on endpoint type
                        if "api/generate" in url:
                            response_text = result.get("response", "{}")
                        else:
                            response_text = result.get("choices", [{}])[0].get("message", {}).get("content", "{}")
                        
                        return json.loads(response_text)
                    else:
                        last_error = f"Status {response.status_code} from {url}"
                        logger.warning(f"Endpoint {url} failed: {response.text}")
            except Exception as e:
                last_error = str(e)
                logger.warning(f"Failed to call {url}: {e}")

        logger.error(f"All Ollama endpoints failed. Last error: {last_error}")
        return {
            "explanation": f"Fallback due to Ollama error: {last_error}",
            "files": []
        }


    async def validate_output(self, skill_name: str, output: Any, context: Dict[str, Any]) -> bool:
        """
        Agentic Validation of skill output.
        """
        logger.info(f"⚖️ Agentic Validation for: {skill_name}")
        # Logic: If scaffolding output is missing files, return False
        if skill_name == "scaffolding":
            if not output.get('challenge', {}).get('generated_files'):
                return False
        return True

    def execute_local(self, skill_fn, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Wraps local function execution with error handling.
        """
        try:
            return skill_fn(params)
        except Exception as e:
            logger.error(f"Execution failed for skill: {e}")
            return {"status": "error", "message": str(e)}

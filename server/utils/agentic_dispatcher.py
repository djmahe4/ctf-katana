import logging
import json
import asyncio
import httpx
import os
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
            # Infer handler and template from challenge artifacts
            challenge = context.get("challenge", {})
            files = challenge.get("generated_files", [])
            category = challenge.get("category", "").lower()
            
            # 1. Defaults
            handler_type = "reverse"
            template = "python"
            target_file = "unknown"
            
            # 2. Category Inference
            if category in ["web", "web3", "mobile"]:
                handler_type = "web"
                template = "html"
            
            # 3. File-Based Overrides (Stronger Signal)
            has_py = any(f.get("name", "").endswith(".py") for f in files)
            has_web = any(f.get("name", "").endswith((".html", ".js")) for f in files)
            
            if has_py and not has_web:
                handler_type = "reverse"
                template = "python"
            elif has_web and not has_py:
                handler_type = "web"
                template = "html"
                
            # 4. Target Selection
            if handler_type == "reverse":
                target_file = next((f.get("name") for f in files if f.get("name").endswith(".py")), "unknown")
            else:
                target_file = next((f.get("name") for f in files if f.get("name").endswith((".html", ".js"))), "unknown")

            # Get Flag from research or default
            vuln_id = context.get("research_results", {}).get("local", {}).get("vuln_id", "CTF_CHALLENGE")
            flag = f"katana{{{vuln_id.replace('-', '_')}_pwned}}"
            
            logger.info(f"🎯 Inferred Flagger Params: handler={handler_type}, template={template}, target={target_file}")
            
            return {
                "flag": flag,
                "handler": handler_type,
                "template": template,
                "level": "moderate",
                "metadata": { # Carry these for the ReviewManager
                    "original_flag": flag,
                    "target_file": target_file
                }
            }
            
        elif skill_name == "merger":
            # 1. Fetch the merger prompt
            sys_prompt = await self._read_skill_prompt("merger")
            
            # 2. Prepare the context for the LLM
            # Memory usually stores challenges in 'challenge_history' or similar
            challenges = context.get("challenge_history", [])
            if not challenges and "challenge" in context:
                challenges = [context["challenge"]]
                
            input_context = json.dumps([{
                "name": c.get("name"),
                "category": c.get("category"),
                "files": [f.get("name") for f in c.get("generated_files", [])]
            } for c in challenges], indent=2)

            # 3. Plan the merger layout via LLM
            layout_plan = await self._plan_merger_layout(sys_prompt, input_context)
            
            return {
                "selected_components": challenges,
                "target_session": context.get("session_id", "katana_unified"),
                "layout_plan": layout_plan
            }

        elif skill_name == "superpowers":
            # 1. Fetch the adversarial prompt
            sys_prompt = await self._read_skill_prompt("superpowers")
            
            # 2. Extract challenge context
            challenge = context.get("challenge", {})
            files_context = json.dumps([f.get("name") for f in challenge.get("generated_files", [])])
            
            # 3. Plan adversarial strategy
            strategy = await self._plan_adversarial_strategy(sys_prompt, files_context, context.get("chaos_level", 0.5))
            
            return {
                "challenge": challenge,
                "strategy": strategy,
                "chaos_level": context.get("chaos_level", 0.5)
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

    async def _read_skill_prompt(self, skill_name: str) -> str:
        """Helper to read the prompt.md from a local skill directory."""
        prompt_path = os.path.join(self.workspace_root, "skills", skill_name, "prompt.md")
        if os.path.exists(prompt_path):
            with open(prompt_path, 'r') as f:
                return f.read()
        return ""

    async def _plan_merger_layout(self, sys_prompt: str, input_context: str) -> Dict[str, Any]:
        """Calls the LLM to perform architectural check and layout planning."""
        logger.info("📐 Planning merger layout via LLM...")
        
        prompt = f"""
        {sys_prompt}

        Available Components Context:
        {input_context}

        Analyze and generate the layout plan JSON.
        """
        
        # Use the existing Ollama channel for now, or use_free_llm if available
        # But dispatcher is designed for local processing.
        # We'll stick to the dispatcher's existing ollama pattern for consistency.
        
        # Note: If we had a more complex requirement, we'd use use_free_llm.
        # For structural JSON inference, local Ollama is usually enough.
        
        model = await self._get_best_model()
        url = "http://localhost:11434/api/generate"
        payload = {"model": model, "prompt": prompt, "stream": False, "format": "json"}
        
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(url, json=payload)
                if response.status_code == 200:
                    text = response.json().get("response", "{}")
                    return json.loads(text)
        except Exception as e:
            logger.error(f"Merger planning failed: {e}")
            
        return {"mergeable": True, "services": []} # Fallback

    async def _plan_adversarial_strategy(self, sys_prompt: str, files_context: str, chaos_level: float) -> Dict[str, Any]:
        """Calls the LLM to design adversarial traps and red herrings."""
        logger.info(f"😈 Planning adversarial strategy (Chaos: {chaos_level})...")
        
        prompt = f"""
        {sys_prompt}

        Target Challenge Files:
        {files_context}

        Current Chaos Level: {chaos_level}

        Generate the adversarial strategy JSON.
        """
        
        model = await self._get_best_model()
        url = "http://localhost:11434/api/generate"
        payload = {"model": model, "prompt": prompt, "stream": False, "format": "json"}
        
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(url, json=payload)
                if response.status_code == 200:
                    text = response.json().get("response", "{}")
                    return json.loads(text)
        except Exception as e:
            logger.error(f"Adversarial planning failed: {e}")
            
        return {"status": "failed", "injections": []}

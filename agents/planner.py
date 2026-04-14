"""Planner agent – builds a step-by-step strategy from an analysis."""

from __future__ import annotations

import json
import re

from agents.base import BaseAgent

_SYSTEM = """\
You are the **Planner** agent in the CTF-Katana system.
Given an analysis of a CTF challenge, produce a numbered, step-by-step plan
to solve it.  Each step should specify:
  - step: step number
  - action: what to do (human-readable)
  - tool: which Katana skill/tool to invoke (if applicable)
  - args: arguments for the tool (dict)

Respond with a JSON object: {"steps": [...]}.
"""


class PlannerAgent(BaseAgent):
    """Generates a solving strategy from an artifact analysis."""

    def __init__(self, **kwargs):
        super().__init__(system_prompt=_SYSTEM, **kwargs)

    def plan(self, analysis: str, knowledge_context: str = "") -> dict:
        """Create a plan from the *analysis* text."""
        prompt = f"Create a step-by-step plan for this challenge analysis:\n\n{analysis}"
        if knowledge_context:
            prompt += f"\n\nRelevant knowledge:\n{knowledge_context}"
        return self.chat_json(prompt)

    async def aplan(self, analysis: str, knowledge_context: str = "") -> dict:
        """Async variant of :meth:`plan`."""
        prompt = f"Create a step-by-step plan for this challenge analysis:\n\n{analysis}"
        if knowledge_context:
            prompt += f"\n\nRelevant knowledge:\n{knowledge_context}"
        raw = await self.achat(prompt)
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            m = re.search(r"```(?:json)?\s*([\s\S]*?)```", raw)
            if m:
                try:
                    return json.loads(m.group(1))
                except json.JSONDecodeError:
                    pass
            return {"raw": raw}

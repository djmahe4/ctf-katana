"""Executor agent – runs planned steps using agent skills."""

from __future__ import annotations

from katana.agents.base import BaseAgent

_SYSTEM = """\
You are the **Executor** agent in the CTF-Katana system.
You receive tool outputs from executed plan steps and decide the next action.
When a step produces useful output, explain what was found.
When a step fails, suggest an alternative approach.
Respond in JSON: {"result": "...", "next_action": "continue"|"retry"|"done", "flag": null|"FLAG{...}"}.
"""


class ExecutorAgent(BaseAgent):
    """Interprets tool outputs and decides next actions during plan execution."""

    def __init__(self, **kwargs):
        super().__init__(system_prompt=_SYSTEM, **kwargs)

    def interpret(self, step_description: str, tool_output: str) -> dict:
        """Interpret the *tool_output* from a plan step."""
        prompt = (
            f"Step: {step_description}\n\n"
            f"Tool output:\n```\n{tool_output}\n```\n\n"
            "Interpret this output. Did we make progress? Is there a flag?"
        )
        return self.chat_json(prompt)

    async def ainterpret(self, step_description: str, tool_output: str) -> dict:
        """Async variant of :meth:`interpret`."""
        prompt = (
            f"Step: {step_description}\n\n"
            f"Tool output:\n```\n{tool_output}\n```\n\n"
            "Interpret this output. Did we make progress? Is there a flag?"
        )
        raw = await self.achat(prompt)
        import json, re
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

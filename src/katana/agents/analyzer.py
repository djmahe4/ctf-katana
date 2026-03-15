"""Analyzer agent – inspects challenge artifacts and identifies the challenge type."""

from __future__ import annotations

from katana.agents.base import BaseAgent

_SYSTEM = """\
You are the **Analyzer** agent in the CTF-Katana system.
Your job is to inspect challenge files and descriptions, then produce a
structured analysis containing:
  - file_type: what kind of file(s) are provided
  - category: the CTF category (crypto, stego, forensics, web, pwn, reversing, recon, misc)
  - observations: a list of interesting things you noticed
  - suggested_tools: tools from the Katana knowledge base that may help

Always respond in valid JSON.
"""


class AnalyzerAgent(BaseAgent):
    """Examines challenge artifacts and produces a structured analysis."""

    def __init__(self, **kwargs):
        super().__init__(system_prompt=_SYSTEM, **kwargs)

    def analyze(self, artifact_info: str, knowledge_context: str = "") -> dict:
        """Analyze the artifact described in *artifact_info*.

        *knowledge_context* is optional relevant knowledge-base content.
        """
        prompt = f"Analyze the following CTF challenge artifact:\n\n{artifact_info}"
        if knowledge_context:
            prompt += (
                f"\n\nRelevant knowledge-base entries:\n{knowledge_context}"
            )
        return self.chat_json(prompt)

    async def aanalyze(self, artifact_info: str, knowledge_context: str = "") -> dict:
        """Async variant of :meth:`analyze`."""
        prompt = f"Analyze the following CTF challenge artifact:\n\n{artifact_info}"
        if knowledge_context:
            prompt += (
                f"\n\nRelevant knowledge-base entries:\n{knowledge_context}"
            )
        raw = await self.achat(prompt)
        import json
        import re
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

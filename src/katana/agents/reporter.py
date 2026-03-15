"""Reporter agent – generates write-ups and exploit PoCs."""

from __future__ import annotations

from katana.agents.base import BaseAgent

_SYSTEM = """\
You are the **Reporter** agent in the CTF-Katana system.
Given the full execution log of a CTF challenge solve, produce:
1. A markdown write-up explaining the challenge, the approach, and the solution.
2. If applicable, a proof-of-concept exploit script (Python).

Respond in JSON:
{
  "writeup": "# Title\\n\\n...",
  "exploit_code": "#!/usr/bin/env python3\\n..."  // or null
}
"""


class ReporterAgent(BaseAgent):
    """Produces write-ups and exploit PoCs from execution logs."""

    def __init__(self, **kwargs):
        super().__init__(system_prompt=_SYSTEM, **kwargs)

    def generate(self, execution_log: str, challenge_name: str = "CTF Challenge") -> dict:
        """Generate a write-up (and optional exploit) from *execution_log*."""
        prompt = (
            f"Challenge: {challenge_name}\n\n"
            f"Execution log:\n{execution_log}\n\n"
            "Generate a write-up and, if applicable, a proof-of-concept exploit script."
        )
        return self.chat_json(prompt)

    async def agenerate(self, execution_log: str, challenge_name: str = "CTF Challenge") -> dict:
        """Async variant of :meth:`generate`."""
        prompt = (
            f"Challenge: {challenge_name}\n\n"
            f"Execution log:\n{execution_log}\n\n"
            "Generate a write-up and, if applicable, a proof-of-concept exploit script."
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

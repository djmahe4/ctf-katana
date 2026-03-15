"""Write-up generator skill – produces Markdown write-ups via Ollama."""

from __future__ import annotations

import os
from pathlib import Path

from agents.reporter import ReporterAgent


def run(inputs: dict) -> dict:
    """Generate a write-up using the Reporter agent."""
    log = inputs.get("execution_log", "")
    challenge = inputs.get("challenge_name", "CTF Challenge")

    agent = ReporterAgent(
        model=os.environ.get("KATANA_OLLAMA_MODEL", "mistral"),
        ollama_host=os.environ.get("KATANA_OLLAMA_HOST", "http://localhost:11434"),
    )

    # Read the skill prompt for context
    prompt_file = Path(__file__).parent / "prompt.md"
    prompt_context = prompt_file.read_text() if prompt_file.exists() else ""

    result = agent.generate(
        f"{prompt_context}\n\nExecution log:\n{log}",
        challenge,
    )
    return result

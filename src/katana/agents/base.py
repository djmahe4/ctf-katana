"""Base agent – shared Ollama-backed reasoning for all agent types."""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Optional

import ollama

log = logging.getLogger(__name__)

DEFAULT_MODEL = "mistral"


class BaseAgent:
    """Thin wrapper around Ollama chat for structured agent interactions.

    Parameters
    ----------
    model:
        Ollama model name (e.g. ``"mistral"``, ``"llama3"``).
    system_prompt:
        System message that defines the agent's personality and constraints.
    ollama_host:
        Ollama server URL.  Defaults to ``http://localhost:11434``.
    """

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        system_prompt: str = "",
        ollama_host: str = "http://localhost:11434",
    ) -> None:
        self.model = model
        self.system_prompt = system_prompt
        self._client = ollama.Client(host=ollama_host)
        self._history: list[dict[str, str]] = []
        if system_prompt:
            self._history.append({"role": "system", "content": system_prompt})

    # ------------------------------------------------------------------
    # Core chat
    # ------------------------------------------------------------------

    def chat(self, user_message: str) -> str:
        """Send *user_message* and return the assistant reply."""
        self._history.append({"role": "user", "content": user_message})
        try:
            response = self._client.chat(
                model=self.model,
                messages=self._history,
            )
            reply = response["message"]["content"]
        except Exception as exc:
            log.warning("Ollama call failed: %s", exc)
            reply = f"[Ollama unavailable: {exc}]"
        self._history.append({"role": "assistant", "content": reply})
        return reply

    async def achat(self, user_message: str) -> str:
        """Async variant of :meth:`chat`."""
        self._history.append({"role": "user", "content": user_message})
        try:
            aclient = ollama.AsyncClient(host=self._client._client.base_url.__str__().rstrip("/"))
            response = await aclient.chat(
                model=self.model,
                messages=self._history,
            )
            reply = response["message"]["content"]
        except Exception as exc:
            log.warning("Ollama call failed: %s", exc)
            reply = f"[Ollama unavailable: {exc}]"
        self._history.append({"role": "assistant", "content": reply})
        return reply

    def chat_json(self, user_message: str) -> Any:
        """Like :meth:`chat` but parse the reply as JSON.

        Falls back to returning ``{"raw": <text>}`` when parsing fails.
        """
        raw = self.chat(user_message)
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            # Try to extract JSON from markdown code block
            m = re.search(r"```(?:json)?\s*([\s\S]*?)```", raw)
            if m:
                try:
                    return json.loads(m.group(1))
                except json.JSONDecodeError:
                    pass
            return {"raw": raw}

    def reset(self) -> None:
        """Clear conversation history (keeps system prompt)."""
        self._history = [
            msg for msg in self._history if msg["role"] == "system"
        ]

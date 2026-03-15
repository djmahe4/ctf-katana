"""Reverse-engineering skill – disassembly, symbols, ELF analysis."""

from __future__ import annotations

from tools.objdump_runner import disassemble, show_symbols, show_elf_info

_ACTIONS = {
    "disassemble": lambda i: disassemble(i["path"]),
    "symbols": lambda i: show_symbols(i["path"]),
    "elf_info": lambda i: show_elf_info(i["path"]),
}


def run(inputs: dict) -> dict:
    """Skill entry-point called by the registry."""
    action = inputs.get("action", "")
    fn = _ACTIONS.get(action)
    if fn is None:
        return {"error": f"Unknown action: {action}", "available": list(_ACTIONS)}
    try:
        return {"result": fn(inputs)}
    except Exception as exc:
        return {"error": str(exc)}

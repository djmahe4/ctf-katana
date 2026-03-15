"""Forensics skill – file carving, magic bytes, PDF/PNG inspection."""

from __future__ import annotations

from tools import detect_file_type
from tools.foremost_runner import run_foremost
from tools.pngcheck_runner import run_pngcheck
from tools.pdftotext_runner import pdf_to_text

_ACTIONS = {
    "file_magic": lambda i: detect_file_type(i["path"]),
    "foremost": lambda i: run_foremost(i["path"]),
    "pngcheck": lambda i: run_pngcheck(i["path"]),
    "pdf_text": lambda i: pdf_to_text(i["path"]),
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

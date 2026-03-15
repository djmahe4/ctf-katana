"""Analysis skill – inspect challenge artifacts."""

from __future__ import annotations

import re
from pathlib import Path

from tools import detect_file_type, hex_dump, read_text_safe


def analyze_file(path: str) -> dict:
    """Analyze a file and return a structured summary."""
    p = Path(path)
    if not p.exists():
        return {"error": f"File not found: {path}"}

    info: dict = {
        "path": str(p),
        "file_type": detect_file_type(path),
        "size_bytes": p.stat().st_size,
    }

    text = read_text_safe(path)
    if text is not None:
        info["is_text"] = True
        info["preview"] = text[:2000]
        info["encodings"] = identify_encoding(text[:500])
    else:
        info["is_text"] = False
        info["hex_dump"] = hex_dump(path, length=256)

    return info


def identify_encoding(data: str) -> list[str]:
    """Guess possible encodings present in *data*."""
    guesses: list[str] = []
    if re.fullmatch(r"[A-Za-z0-9+/=\s]+", data):
        guesses.append("base64")
    if re.fullmatch(r"[0-9a-fA-F\s]+", data):
        guesses.append("hex")
    if re.search(r"\\x[0-9a-fA-F]{2}", data):
        guesses.append("escaped_hex")
    if re.search(r"&#?\w+;", data):
        guesses.append("html_entities")
    if re.fullmatch(r"[01\s]+", data):
        guesses.append("binary")
    if re.search(r"%[0-9a-fA-F]{2}", data):
        guesses.append("url_encoded")
    return guesses


def run(inputs: dict) -> dict:
    """Skill entry-point called by the registry."""
    path = inputs.get("path", "")
    data = inputs.get("data", "")

    if path:
        return analyze_file(path)
    if data:
        return {"encodings": identify_encoding(data)}
    return {"error": "Provide 'path' or 'data' in inputs."}

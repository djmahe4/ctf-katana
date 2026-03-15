"""Artifact analysis skill – identify file types, detect encodings, etc."""

from __future__ import annotations

import base64
import binascii
import re
from pathlib import Path
from typing import Optional

from katana.utils import detect_file_type, hex_dump, read_text_safe


def analyze_file(path: str) -> dict:
    """Return a dict describing the file at *path*."""
    p = Path(path)
    if not p.exists():
        return {"error": f"File not found: {path}"}

    info: dict = {
        "path": str(p.resolve()),
        "size_bytes": p.stat().st_size,
        "file_type": detect_file_type(p),
        "hex_head": hex_dump(p, length=128),
    }

    text = read_text_safe(p, max_bytes=500_000)
    if text is not None:
        info["is_text"] = True
        info["line_count"] = text.count("\n")
        info["preview"] = text[:1000]
        info["detected_encodings"] = _detect_encodings(text)
    else:
        info["is_text"] = False

    return info


def identify_encoding(data: str) -> list[str]:
    """Guess which encodings *data* might be using."""
    return _detect_encodings(data)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_BASE64_RE = re.compile(r"^[A-Za-z0-9+/\n]{20,}={0,2}$", re.MULTILINE)
_HEX_RE = re.compile(r"^[0-9a-fA-F\s]{20,}$", re.MULTILINE)
_BINARY_RE = re.compile(r"^[01\s]{16,}$", re.MULTILINE)


def _detect_encodings(text: str) -> list[str]:
    encodings: list[str] = []

    # Base64
    if _BASE64_RE.search(text):
        try:
            base64.b64decode(text.strip(), validate=True)
            encodings.append("base64")
        except Exception:
            pass

    # Hex
    cleaned = text.strip().replace(" ", "").replace("\n", "")
    if _HEX_RE.match(cleaned):
        try:
            binascii.unhexlify(cleaned)
            encodings.append("hex")
        except Exception:
            pass

    # Binary string
    if _BINARY_RE.search(text):
        encodings.append("binary")

    # URL encoding
    if "%" in text and re.search(r"%[0-9a-fA-F]{2}", text):
        encodings.append("url_encoding")

    # ROT13 hint (all alpha, roughly English letter distribution)
    if text.isalpha() and len(text) > 10:
        encodings.append("possible_rot13")

    return encodings

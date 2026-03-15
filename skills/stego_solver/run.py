"""Stego-solver skill – steganographic extraction from media files."""

from __future__ import annotations

from tools.strings_runner import run_strings
from tools.exiftool_runner import run_exiftool
from tools.binwalk_scan import binwalk_scan
from tools.steghide_runner import steghide_extract
from tools.zsteg_runner import run_zsteg

_ACTIONS = {
    "strings": lambda i: run_strings(i["path"], min_length=int(i.get("min_length", 6))),
    "exiftool": lambda i: run_exiftool(i["path"]),
    "binwalk": lambda i: binwalk_scan(i["path"]),
    "steghide": lambda i: steghide_extract(i["path"], i.get("passphrase", "")),
    "zsteg": lambda i: run_zsteg(i["path"]),
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

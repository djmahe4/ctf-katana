"""Exiftool wrapper for metadata extraction."""

from tools import safe_run


def run_exiftool(path: str) -> str:
    """Run ``exiftool`` to extract file metadata."""
    return safe_run(["exiftool", path])

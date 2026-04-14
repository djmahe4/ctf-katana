"""Binwalk wrapper for embedded file/signature scanning."""

from tools import safe_run


def binwalk_scan(path: str) -> str:
    """Run ``binwalk`` to search for embedded files and signatures."""
    return safe_run(["binwalk", path])

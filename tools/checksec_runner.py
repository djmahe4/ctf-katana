"""Checksec / ROPgadget wrappers for binary exploitation analysis."""

from tools import safe_run


def checksec(path: str) -> str:
    """Run ``checksec`` on a binary to list protections."""
    result = safe_run(["checksec", "--file=" + path])
    if "Command not found" in result:
        result = safe_run(["pwn", "checksec", path])
    return result


def find_rop_gadgets(path: str) -> str:
    """Search for ROP gadgets with ``ROPgadget``."""
    return safe_run(["ROPgadget", "--binary", path], timeout=60)

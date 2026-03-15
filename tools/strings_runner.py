"""Strings wrapper for extracting printable strings from files."""

from tools import safe_run


def run_strings(path: str, *, min_length: int = 6) -> str:
    """Run ``strings`` on a file and return the output."""
    return safe_run(["strings", "-n", str(min_length), path])

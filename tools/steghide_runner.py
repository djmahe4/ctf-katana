"""Steghide wrapper for steganographic extraction."""

from tools import safe_run


def steghide_extract(path: str, passphrase: str = "") -> str:
    """Attempt ``steghide extract`` with the given *passphrase*."""
    cmd = ["steghide", "extract", "-sf", path, "-p", passphrase, "-f"]
    return safe_run(cmd)

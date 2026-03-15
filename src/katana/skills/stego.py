"""Steganography skill – helpers for detecting and extracting hidden data."""

from __future__ import annotations

from katana.utils import safe_run


def run_strings(path: str, *, min_length: int = 6) -> str:
    """Run ``strings`` on a file and return the output."""
    return safe_run(["strings", "-n", str(min_length), path])


def run_exiftool(path: str) -> str:
    """Run ``exiftool`` to extract metadata."""
    return safe_run(["exiftool", path])


def run_binwalk(path: str) -> str:
    """Run ``binwalk`` to search for embedded files/signatures."""
    return safe_run(["binwalk", path])


def run_steghide_extract(path: str, passphrase: str = "") -> str:
    """Attempt ``steghide extract`` with the given *passphrase*."""
    cmd = ["steghide", "extract", "-sf", path, "-p", passphrase, "-f"]
    return safe_run(cmd)


def run_zsteg(path: str) -> str:
    """Run ``zsteg`` (Ruby tool for PNG/BMP steganography)."""
    return safe_run(["zsteg", path])


def run_stegsolve_info(path: str) -> str:
    """Return basic image information useful for steganalysis."""
    return safe_run(["identify", "-verbose", path], timeout=15)

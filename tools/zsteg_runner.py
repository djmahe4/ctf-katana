"""zsteg wrapper for PNG/BMP steganography."""

from tools import safe_run


def run_zsteg(path: str) -> str:
    """Run ``zsteg`` on a PNG/BMP file."""
    return safe_run(["zsteg", path])


def stegsolve_info(path: str) -> str:
    """Return basic image information useful for steganalysis."""
    return safe_run(["identify", "-verbose", path], timeout=15)

"""pngcheck wrapper for PNG validation."""

from tools import safe_run


def run_pngcheck(path: str) -> str:
    """Validate a PNG file with ``pngcheck``."""
    return safe_run(["pngcheck", "-v", path])

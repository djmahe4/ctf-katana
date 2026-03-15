"""Forensics skill – file carving, metadata extraction, etc."""

from __future__ import annotations

from katana.utils import safe_run


def run_foremost(path: str, output_dir: str = "/tmp/foremost_out") -> str:
    """Run ``foremost`` to carve files from *path*."""
    return safe_run(["foremost", "-i", path, "-o", output_dir])


def run_volatility(memory_dump: str, profile: str, plugin: str) -> str:
    """Run a Volatility plugin against a memory dump."""
    return safe_run([
        "volatility", "-f", memory_dump,
        "--profile", profile,
        plugin,
    ], timeout=120)


def check_file_magic(path: str) -> str:
    """Return the file magic (``file`` command output) for *path*."""
    return safe_run(["file", "--brief", path])


def extract_zip(path: str, output_dir: str = "/tmp/zip_out") -> str:
    """Extract a ZIP archive."""
    return safe_run(["unzip", "-o", path, "-d", output_dir])


def pdf_to_text(path: str) -> str:
    """Extract text from a PDF using ``pdftotext``."""
    return safe_run(["pdftotext", path, "-"])


def run_pngcheck(path: str) -> str:
    """Validate a PNG file with ``pngcheck``."""
    return safe_run(["pngcheck", "-v", path])

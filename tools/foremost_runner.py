"""Foremost / unzip wrappers for file carving and extraction."""

from tools import safe_run


def run_foremost(path: str, output_dir: str = "/tmp/foremost_out") -> str:
    """Run ``foremost`` to carve files from *path*."""
    return safe_run(["foremost", "-i", path, "-o", output_dir])


def extract_zip(path: str, output_dir: str = "/tmp/zip_out") -> str:
    """Extract a ZIP archive."""
    return safe_run(["unzip", "-o", path, "-d", output_dir])

"""pdftotext wrapper for PDF text extraction."""

from tools import safe_run


def pdf_to_text(path: str) -> str:
    """Extract text from a PDF using ``pdftotext``."""
    return safe_run(["pdftotext", path, "-"])

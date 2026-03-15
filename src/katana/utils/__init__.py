"""Utility helpers used across the Katana package."""

from __future__ import annotations

import mimetypes
import os
import subprocess
from pathlib import Path
from typing import Optional


def detect_file_type(path: str | Path) -> str:
    """Return a human-readable file-type description for *path*."""
    path = Path(path)
    if not path.exists():
        return "file not found"

    # Try the ``file`` command first (most reliable on Linux/macOS)
    try:
        result = subprocess.run(
            ["file", "--brief", str(path)],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except FileNotFoundError:
        pass

    # Fall back to mimetypes
    mime, _ = mimetypes.guess_type(str(path))
    return mime or "unknown"


def read_text_safe(path: str | Path, max_bytes: int = 1_000_000) -> Optional[str]:
    """Read text from *path*, returning ``None`` if binary or too large."""
    path = Path(path)
    if not path.exists() or path.stat().st_size > max_bytes:
        return None
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None


def hex_dump(path: str | Path, length: int = 256) -> str:
    """Return a hex dump of the first *length* bytes of *path*."""
    path = Path(path)
    data = path.read_bytes()[:length]
    lines: list[str] = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:08x}  {hex_part:<48s}  {ascii_part}")
    return "\n".join(lines)


def safe_run(cmd: list[str], *, timeout: int = 30, cwd: Optional[str] = None) -> str:
    """Run *cmd* in a subprocess and return combined stdout+stderr.

    Returns an error string rather than raising on failure.
    """
    try:
        env = os.environ.copy()
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            env=env,
        )
        output = (result.stdout + "\n" + result.stderr).strip()
        return output or "(no output)"
    except subprocess.TimeoutExpired:
        return f"Command timed out after {timeout}s"
    except FileNotFoundError:
        return f"Command not found: {cmd[0]}"
    except Exception as exc:
        return f"Error running command: {exc}"

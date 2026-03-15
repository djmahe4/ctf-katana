"""Reverse-engineering skill – disassembly and decompilation helpers."""

from __future__ import annotations

from katana.utils import safe_run


def disassemble(path: str) -> str:
    """Disassemble a binary with ``objdump``."""
    return safe_run(["objdump", "-d", path], timeout=30)


def show_symbols(path: str) -> str:
    """List symbols in a binary via ``nm``."""
    return safe_run(["nm", path])


def show_sections(path: str) -> str:
    """Show ELF sections with ``readelf``."""
    return safe_run(["readelf", "-S", path])


def decompile_python(path: str) -> str:
    """Attempt to decompile a ``.pyc`` file with ``uncompyle6`` / ``decompyle3``."""
    result = safe_run(["uncompyle6", path])
    if "Command not found" in result:
        result = safe_run(["decompyle3", path])
    return result


def show_elf_info(path: str) -> str:
    """Return ELF header info via ``readelf -h``."""
    return safe_run(["readelf", "-h", path])


def run_ltrace(path: str) -> str:
    """Trace library calls with ``ltrace``."""
    return safe_run(["ltrace", path], timeout=10)


def run_strace(path: str) -> str:
    """Trace system calls with ``strace``."""
    return safe_run(["strace", "-f", path], timeout=10)

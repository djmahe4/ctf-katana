"""Objdump / readelf / nm wrappers for binary analysis."""

from tools import safe_run


def disassemble(path: str) -> str:
    """Disassemble a binary with ``objdump``."""
    return safe_run(["objdump", "-d", path], timeout=30)


def show_symbols(path: str) -> str:
    """List symbols in a binary via ``nm``."""
    return safe_run(["nm", path])


def show_sections(path: str) -> str:
    """Show ELF sections with ``readelf``."""
    return safe_run(["readelf", "-S", path])


def show_elf_info(path: str) -> str:
    """Return ELF header info via ``readelf -h``."""
    return safe_run(["readelf", "-h", path])


def show_got(path: str) -> str:
    """Display the GOT (Global Offset Table) entries of an ELF binary."""
    return safe_run(["objdump", "-R", path])


def show_plt(path: str) -> str:
    """Display the PLT (Procedure Linkage Table) entries."""
    return safe_run(["objdump", "-d", "-j", ".plt", path])

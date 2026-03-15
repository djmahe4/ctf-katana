"""Binary-exploitation / pwn skill – checksec, ROP helpers, etc."""

from __future__ import annotations

from katana.utils import safe_run


def checksec(path: str) -> str:
    """Run ``checksec`` on a binary to list protections."""
    result = safe_run(["checksec", "--file=" + path])
    if "Command not found" in result:
        result = safe_run(["pwn", "checksec", path])
    return result


def find_rop_gadgets(path: str) -> str:
    """Search for ROP gadgets with ``ROPgadget``."""
    return safe_run(["ROPgadget", "--binary", path], timeout=60)


def pattern_create(length: int) -> str:
    """Generate a cyclic pattern for buffer-overflow offset detection."""
    try:
        from string import ascii_uppercase, ascii_lowercase, digits
    except ImportError:
        pass

    # Simple De Bruijn-like cyclic pattern
    pattern: list[str] = []
    for a in ascii_uppercase:
        for b in ascii_lowercase:
            for c in digits:
                pattern.append(f"{a}{b}{c}")
                if len("".join(pattern)) >= length:
                    return "".join(pattern)[:length]
    return "".join(pattern)[:length]


def pattern_offset(pattern: str, value: str) -> int:
    """Find the offset of *value* within a cyclic *pattern*."""
    idx = pattern.find(value)
    return idx if idx != -1 else -1


def show_got(path: str) -> str:
    """Display the GOT (Global Offset Table) entries of an ELF binary."""
    return safe_run(["objdump", "-R", path])


def show_plt(path: str) -> str:
    """Display the PLT (Procedure Linkage Table) entries of an ELF binary."""
    return safe_run(["objdump", "-d", "-j", ".plt", path])

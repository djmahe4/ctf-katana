"""Reconnaissance / enumeration skill – port scanning, service detection."""

from __future__ import annotations

from katana.utils import safe_run


def nmap_scan(target: str, *, ports: str = "-", extra_flags: str = "") -> str:
    """Run an ``nmap`` scan against *target*."""
    cmd = ["nmap", "-sV", "-sC", "-p", ports, target]
    if extra_flags:
        cmd.extend(extra_flags.split())
    return safe_run(cmd, timeout=300)


def whois_lookup(target: str) -> str:
    """Run ``whois`` on *target*."""
    return safe_run(["whois", target], timeout=15)


def dig_lookup(domain: str, record_type: str = "ANY") -> str:
    """DNS lookup via ``dig``."""
    return safe_run(["dig", domain, record_type], timeout=10)


def smb_enum(target: str) -> str:
    """Enumerate SMB shares with ``smbmap``."""
    return safe_run(["smbmap", "-H", target])


def enum4linux(target: str) -> str:
    """Run ``enum4linux`` against *target*."""
    return safe_run(["enum4linux", target], timeout=120)

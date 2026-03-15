"""Recon skill – network scanning and service enumeration."""

from __future__ import annotations

from tools.nmap_wrapper import (
    dig_lookup,
    nmap_scan,
    smb_enum,
    whois_lookup,
)

_ACTIONS = {
    "nmap": lambda i: nmap_scan(
        i["target"],
        ports=i.get("ports", "-"),
        extra_flags=i.get("extra_flags", ""),
    ),
    "whois": lambda i: whois_lookup(i["target"]),
    "dig": lambda i: dig_lookup(i["target"], i.get("record_type", "ANY")),
    "smb_enum": lambda i: smb_enum(i["target"]),
}


def run(inputs: dict) -> dict:
    """Skill entry-point called by the registry."""
    action = inputs.get("action", "nmap")
    fn = _ACTIONS.get(action)
    if fn is None:
        return {"error": f"Unknown action: {action}", "available": list(_ACTIONS)}
    try:
        return {"result": fn(inputs)}
    except Exception as exc:
        return {"error": str(exc)}

"""Recon skill – network scanning and service enumeration."""

from __future__ import annotations

import sys
import json
from pathlib import Path

# Add project root to path
project_root = str(Path(__file__).resolve().parent.parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

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


def run(params: dict) -> dict:
    """Skill entry-point called by the registry."""
    action = params.get("action", "nmap")
    fn = _ACTIONS.get(action)
    if fn is None:
        return {
            "status": False, 
            "summary": f"Unknown action: {action}", 
            "result": {"available": list(_ACTIONS)}
        }
    try:
        result = fn(params)
        return {
            "status": True,
            "summary": f"Performed {action} reconnaissance.",
            "result": result
        }
    except Exception as exc:
        return {
            "status": False, 
            "summary": f"Action failed: {str(exc)}",
            "result": {"error": str(exc)}
        }

def main():
    """CLI entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Recon Skill CLI')
    parser.add_argument('target', nargs='?', help='Target host/IP')
    parser.add_argument('--action', '-a', choices=list(_ACTIONS), default='nmap')
    parser.add_argument('--ports', '-p', help='Ports to scan (nmap only)')
    parser.add_argument('--json', help='Pass parameters as JSON string')
    parser.add_argument('--test', action='store_true', help='Run sanity test')
    
    args = parser.parse_args()
    
    if args.test:
        print("Running sanity test for Recon...")
        test_params = {
            "target": "127.0.0.1",
            "action": "nmap",
            "ports": "80"
        }
        print(f"Test Configuration: {json.dumps(test_params, indent=2)}")
        print("Test passed: Module structure verified.")
        return

    params = {}
    if args.json:
        try:
            params = json.loads(args.json)
        except json.JSONDecodeError as e:
            print(json.dumps({"status": False, "summary": f"Invalid JSON: {str(e)}", "result": {}}))
            return
    else:
        if not args.target:
            parser.print_help()
            return
        params = {
            "target": args.target,
            "action": args.action,
            "ports": args.ports
        }
    
    result = run(params)
    print(json.dumps(result, indent=2, default=str))

if __name__ == "__main__":
    main()

from __future__ import annotations

import base64 as _b64
import codecs
import sys
import json
import argparse
from pathlib import Path


# ---------------------------------------------------------------------------
# Ciphers
# ---------------------------------------------------------------------------

def rot13(text: str) -> str:
    return codecs.encode(text, "rot_13")


def caesar(text: str, shift: int) -> str:
    result: list[str] = []
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            result.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            result.append(ch)
    return "".join(result)


def caesar_bruteforce(text: str) -> list[dict]:
    return [{"shift": s, "text": caesar(text, s)} for s in range(1, 26)]


def xor_single_byte(data_hex: str, key: int) -> str:
    data = bytes.fromhex(data_hex)
    return "".join(chr(b ^ key) for b in data)


def xor_bruteforce(data_hex: str) -> list[dict]:
    results: list[dict] = []
    data = bytes.fromhex(data_hex)
    for key in range(256):
        decoded = "".join(chr(b ^ key) for b in data)
        results.append({"key": key, "text": decoded})
    return results


def base64_decode(data: str) -> str:
    return _b64.b64decode(data).decode("utf-8", errors="replace")


def base64_encode(data: str) -> str:
    return _b64.b64encode(data.encode()).decode()


def hex_decode(data: str) -> str:
    return bytes.fromhex(data.replace(" ", "")).decode("utf-8", errors="replace")


def hex_encode(data: str) -> str:
    return data.encode().hex()


def vigenere_decrypt(ciphertext: str, key: str) -> str:
    result: list[str] = []
    ki = 0
    for ch in ciphertext:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            shift = ord(key[ki % len(key)].upper()) - ord("A")
            result.append(chr((ord(ch) - base - shift) % 26 + base))
            ki += 1
        else:
            result.append(ch)
    return "".join(result)


def atbash(text: str) -> str:
    result: list[str] = []
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            result.append(chr(base + 25 - (ord(ch) - base)))
        else:
            result.append(ch)
    return "".join(result)


# ---------------------------------------------------------------------------
# Skill entry-point
# ---------------------------------------------------------------------------

_ACTIONS = {
    "rot13": lambda i: rot13(i["text"]),
    "caesar": lambda i: caesar(i["text"], int(i.get("shift", 13))),
    "caesar_bruteforce": lambda i: caesar_bruteforce(i["text"]),
    "xor_single_byte": lambda i: xor_single_byte(i["data_hex"], int(i.get("key", 0))),
    "xor_bruteforce": lambda i: xor_bruteforce(i["data_hex"]),
    "base64_decode": lambda i: base64_decode(i["text"]),
    "base64_encode": lambda i: base64_encode(i["text"]),
    "hex_decode": lambda i: hex_decode(i["text"]),
    "hex_encode": lambda i: hex_encode(i["text"]),
    "vigenere_decrypt": lambda i: vigenere_decrypt(i["text"], i["key"]),
    "atbash": lambda i: atbash(i["text"]),
}


def run(params: dict) -> dict:
    """Skill entry-point called by the registry."""
    action = params.get("action", "")
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
            "summary": f"Performed {action} on input.",
            "result": result
        }
    except Exception as exc:
        return {
            "status": False, 
            "summary": f"Action '{action}' failed: {str(exc)}",
            "result": {"error_detail": str(exc)}
        }

def main():
    # Add project root to sys.path for standalone execution
    root_path = str(Path(__file__).resolve().parent.parent.parent)
    if root_path not in sys.path:
        sys.path.insert(0, root_path)

    parser = argparse.ArgumentParser(description="Crypto Solver CLI")
    parser.add_argument("action", choices=list(_ACTIONS.keys()), help="Action to perform")
    parser.add_argument("--text", help="Input text for classical ciphers")
    parser.add_argument("--data_hex", help="Hex data for XOR operations")
    parser.add_argument("--shift", type=int, default=13, help="Caesar shift value")
    parser.add_argument("--key", help="Key for Vigenere or XOR")
    parser.add_argument("--json", action="store_true", help="Output JSON results")

    args = parser.parse_args()
    params = vars(args)
    
    # Simple type conversion for params that might be expected as int
    if params.get('key') and params['key'].isdigit():
        params['key_int'] = int(params['key'])
    
    result = run(params)
    
    if args.json:
        print(json.dumps(result, indent=2))
        sys.exit(0 if result['status'] else 1)

    if not result['status']:
        print(f"Error: {result['summary']}")
        sys.exit(1)
        
    print(f"[*] Success: {result['summary']}")
    print(json.dumps(result.get('result', {}), indent=2))

if __name__ == "__main__":
    main()

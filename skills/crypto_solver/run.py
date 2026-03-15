"""Crypto-solver skill – classical ciphers and encoding helpers."""

from __future__ import annotations

import base64 as _b64
import codecs


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


def run(inputs: dict) -> dict:
    """Skill entry-point called by the registry."""
    action = inputs.get("action", "")
    fn = _ACTIONS.get(action)
    if fn is None:
        return {"error": f"Unknown action: {action}", "available": list(_ACTIONS)}
    try:
        return {"result": fn(inputs)}
    except Exception as exc:
        return {"error": str(exc)}

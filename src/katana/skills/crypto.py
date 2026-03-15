"""Cryptography skill – common CTF crypto operations."""

from __future__ import annotations

import base64
import binascii
import string


def rot13(text: str) -> str:
    """Apply ROT-13 to *text*."""
    return text.translate(str.maketrans(
        string.ascii_lowercase + string.ascii_uppercase,
        string.ascii_lowercase[13:] + string.ascii_lowercase[:13]
        + string.ascii_uppercase[13:] + string.ascii_uppercase[:13],
    ))


def caesar(text: str, shift: int) -> str:
    """Apply a Caesar cipher with the given *shift*."""
    result: list[str] = []
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            result.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            result.append(ch)
    return "".join(result)


def caesar_bruteforce(text: str) -> list[dict[str, object]]:
    """Return all 25 Caesar shifts of *text*."""
    return [{"shift": s, "text": caesar(text, s)} for s in range(1, 26)]


def xor_single_byte(data_hex: str, key: int) -> str:
    """XOR hex-encoded *data_hex* with a single-byte *key*."""
    raw = binascii.unhexlify(data_hex)
    return bytes(b ^ key for b in raw).decode("latin-1")


def xor_bruteforce(data_hex: str) -> list[dict[str, object]]:
    """Try all 256 single-byte XOR keys against hex *data_hex*."""
    results: list[dict[str, object]] = []
    raw = binascii.unhexlify(data_hex)
    for key in range(256):
        decoded = bytes(b ^ key for b in raw)
        try:
            text = decoded.decode("ascii")
            if all(32 <= ord(c) < 127 or c in "\n\r\t" for c in text):
                results.append({"key": key, "text": text})
        except UnicodeDecodeError:
            continue
    return results


def base64_decode(data: str) -> str:
    """Decode a Base-64 string."""
    return base64.b64decode(data).decode("utf-8", errors="replace")


def base64_encode(data: str) -> str:
    """Encode a string to Base-64."""
    return base64.b64encode(data.encode()).decode()


def hex_decode(data: str) -> str:
    """Decode a hex-encoded string."""
    cleaned = data.strip().replace(" ", "").replace("\n", "")
    return binascii.unhexlify(cleaned).decode("utf-8", errors="replace")


def hex_encode(data: str) -> str:
    """Hex-encode a string."""
    return binascii.hexlify(data.encode()).decode()


def vigenere_decrypt(ciphertext: str, key: str) -> str:
    """Decrypt *ciphertext* with a Vigenère *key*."""
    result: list[str] = []
    ki = 0
    for ch in ciphertext:
        if ch.isalpha():
            shift = ord(key[ki % len(key)].lower()) - ord("a")
            base = ord("A") if ch.isupper() else ord("a")
            result.append(chr((ord(ch) - base - shift) % 26 + base))
            ki += 1
        else:
            result.append(ch)
    return "".join(result)


def atbash(text: str) -> str:
    """Apply the Atbash cipher to *text*."""
    result: list[str] = []
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            result.append(chr(base + 25 - (ord(ch) - base)))
        else:
            result.append(ch)
    return "".join(result)

"""Tests for the crypto_solver skill."""

import pytest

from skills.crypto_solver.run import (
    atbash,
    base64_decode,
    base64_encode,
    caesar,
    caesar_bruteforce,
    hex_decode,
    hex_encode,
    rot13,
    run,
    vigenere_decrypt,
    xor_bruteforce,
    xor_single_byte,
)


class TestRot13:
    def test_basic(self):
        assert rot13("Hello") == "Uryyb"

    def test_roundtrip(self):
        assert rot13(rot13("Test")) == "Test"

    def test_non_alpha_unchanged(self):
        assert rot13("123!") == "123!"


class TestCaesar:
    def test_shift_3(self):
        assert caesar("abc", 3) == "def"

    def test_wraparound(self):
        assert caesar("xyz", 3) == "abc"

    def test_preserves_case(self):
        assert caesar("AbC", 1) == "BcD"

    def test_bruteforce_length(self):
        assert len(caesar_bruteforce("test")) == 25


class TestXor:
    def test_single_byte(self):
        result = xor_single_byte("48656c6c6f", 0)
        assert result == "Hello"

    def test_bruteforce_returns_list(self):
        results = xor_bruteforce("41")
        assert len(results) == 256


class TestBase64:
    def test_decode(self):
        assert base64_decode("SGVsbG8=") == "Hello"

    def test_encode(self):
        assert base64_encode("Hello") == "SGVsbG8="

    def test_roundtrip(self):
        assert base64_decode(base64_encode("test")) == "test"


class TestHex:
    def test_decode(self):
        assert hex_decode("48656c6c6f") == "Hello"

    def test_encode(self):
        assert hex_encode("Hello") == "48656c6c6f"

    def test_roundtrip(self):
        assert hex_decode(hex_encode("test")) == "test"


class TestVigenere:
    def test_decrypt(self):
        assert vigenere_decrypt("Mvwzxm", "key") == "Crypto"

    def test_preserves_non_alpha(self):
        assert vigenere_decrypt("M!v", "key") == "C!r"


class TestAtbash:
    def test_basic(self):
        assert atbash("a") == "z"

    def test_roundtrip(self):
        assert atbash(atbash("Hello")) == "Hello"

    def test_non_alpha_unchanged(self):
        assert atbash("123!") == "123!"


class TestRunEntryPoint:
    def test_rot13_via_run(self):
        result = run({"action": "rot13", "text": "Hello"})
        assert result["status"] is True
        assert result["result"] == "Uryyb"
        assert "summary" in result

    def test_unknown_action(self):
        result = run({"action": "nonexistent"})
        assert result["status"] is False
        assert "summary" in result

    def test_caesar_via_run(self):
        result = run({"action": "caesar", "text": "abc", "shift": "3"})
        assert result["status"] is True
        assert result["result"] == "def"
        assert "summary" in result

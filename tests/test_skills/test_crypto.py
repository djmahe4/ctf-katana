"""Tests for crypto skills."""

from katana.skills.crypto import (
    atbash,
    base64_decode,
    base64_encode,
    caesar,
    caesar_bruteforce,
    hex_decode,
    hex_encode,
    rot13,
    vigenere_decrypt,
    xor_bruteforce,
    xor_single_byte,
)


class TestRot13:
    def test_basic(self):
        assert rot13("Hello") == "Uryyb"

    def test_roundtrip(self):
        assert rot13(rot13("Secret")) == "Secret"

    def test_non_alpha_unchanged(self):
        assert rot13("Hello, World!") == "Uryyb, Jbeyq!"


class TestCaesar:
    def test_shift_3(self):
        assert caesar("ABC", 3) == "DEF"

    def test_wraparound(self):
        assert caesar("XYZ", 3) == "ABC"

    def test_preserves_case(self):
        assert caesar("Hello", 1) == "Ifmmp"

    def test_bruteforce_length(self):
        results = caesar_bruteforce("test")
        assert len(results) == 25
        assert all("shift" in r and "text" in r for r in results)


class TestXor:
    def test_single_byte(self):
        # 'A' ^ 0x20 == 'a'
        assert xor_single_byte("41", 0x20) == "a"

    def test_bruteforce_returns_list(self):
        # "48656c6c6f" == "Hello"
        results = xor_bruteforce("48656c6c6f")
        assert isinstance(results, list)
        # Key 0 should produce the original "Hello"
        key_zero = [r for r in results if r["key"] == 0]
        assert len(key_zero) == 1
        assert key_zero[0]["text"] == "Hello"


class TestBase64:
    def test_decode(self):
        assert base64_decode("SGVsbG8=") == "Hello"

    def test_encode(self):
        assert base64_encode("Hello") == "SGVsbG8="

    def test_roundtrip(self):
        assert base64_decode(base64_encode("CTF{flag}")) == "CTF{flag}"


class TestHex:
    def test_decode(self):
        assert hex_decode("48656c6c6f") == "Hello"

    def test_encode(self):
        assert hex_encode("Hello") == "48656c6c6f"

    def test_roundtrip(self):
        assert hex_decode(hex_encode("flag{test}")) == "flag{test}"


class TestVigenere:
    def test_decrypt(self):
        # Encrypting "HELLO" with key "KEY":
        # H+K=R, E+E=I, L+Y=J, L+K=V, O+E=S -> "RIJVS"
        assert vigenere_decrypt("RIJVS", "KEY") == "HELLO"

    def test_preserves_non_alpha(self):
        result = vigenere_decrypt("R I J", "KEY")
        assert " " in result


class TestAtbash:
    def test_basic(self):
        assert atbash("A") == "Z"
        assert atbash("Z") == "A"

    def test_roundtrip(self):
        assert atbash(atbash("Hello")) == "Hello"

    def test_non_alpha_unchanged(self):
        assert atbash("A1B2") == "Z1Y2"

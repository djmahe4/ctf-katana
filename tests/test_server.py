"""Tests for the MCP server tool registrations."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

# We test the underlying functions directly (they're the MCP tool handlers)
from katana.server import (
    search_knowledge,
    get_knowledge_section,
    list_knowledge_categories,
    analyze_artifact,
    identify_encoding,
    crypto_rot13,
    crypto_caesar,
    crypto_base64_decode,
    crypto_hex_decode,
    kb_summary,
    kb_sections,
    kb_categories,
)


README = Path(__file__).resolve().parent.parent / "README.md"


class TestKnowledgeBaseTools:
    def test_search_knowledge(self):
        result = search_knowledge("steghide")
        parsed = json.loads(result)
        assert isinstance(parsed, list)

    def test_search_knowledge_no_results(self):
        result = search_knowledge("zzzznonexistent")
        assert "No matching" in result

    def test_get_knowledge_section(self):
        result = get_knowledge_section("Cryptography")
        assert len(result) > 0
        assert "not found" not in result.lower()

    def test_get_knowledge_section_missing(self):
        result = get_knowledge_section("Nonexistent")
        assert "not found" in result.lower()

    def test_list_knowledge_categories(self):
        result = list_knowledge_categories()
        parsed = json.loads(result)
        assert "crypto" in parsed
        assert isinstance(parsed["crypto"], list)


class TestResourceEndpoints:
    def test_kb_summary(self):
        result = kb_summary()
        assert "CTF-Katana Knowledge Base" in result

    def test_kb_sections(self):
        result = kb_sections()
        parsed = json.loads(result)
        assert isinstance(parsed, list)
        assert len(parsed) > 0

    def test_kb_categories(self):
        result = kb_categories()
        parsed = json.loads(result)
        assert isinstance(parsed, list)
        assert "crypto" in parsed


class TestAnalysisTools:
    def test_analyze_artifact_missing_file(self):
        result = analyze_artifact("/tmp/nonexistent_file_12345")
        parsed = json.loads(result)
        assert "error" in parsed

    def test_analyze_artifact_real_file(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("Hello, CTF World!")
        result = analyze_artifact(str(f))
        parsed = json.loads(result)
        assert parsed.get("is_text") is True
        assert "Hello" in parsed.get("preview", "")

    def test_identify_encoding_base64(self):
        result = identify_encoding("SGVsbG8gV29ybGQhIFRoaXMgaXMgYmFzZTY0")
        parsed = json.loads(result)
        assert isinstance(parsed, list)

    def test_identify_encoding_hex(self):
        result = identify_encoding("48656c6c6f")
        parsed = json.loads(result)
        assert isinstance(parsed, list)


class TestCryptoTools:
    def test_rot13(self):
        assert crypto_rot13("Hello") == "Uryyb"

    def test_caesar(self):
        assert crypto_caesar("ABC", 3) == "DEF"

    def test_base64_decode(self):
        assert crypto_base64_decode("SGVsbG8=") == "Hello"

    def test_hex_decode(self):
        assert crypto_hex_decode("48656c6c6f") == "Hello"

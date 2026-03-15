"""Tests for the MCP server (server/mcp_server.py).

These tests exercise tool functions directly without running the full
MCP transport layer.
"""

import json
import tempfile
from pathlib import Path

import pytest

# Import the tool functions directly from the server module
from server.mcp_server import (
    analyze_artifact,
    crypto_base64_decode,
    crypto_caesar,
    crypto_hex_decode,
    crypto_rot13,
    get_knowledge_section,
    identify_encoding,
    kb_categories,
    kb_sections,
    kb_summary,
    list_knowledge_categories,
    list_skills,
    run_skill,
    search_knowledge,
)


# -------------------------------------------------------------------
# Knowledge-base tools
# -------------------------------------------------------------------

class TestKnowledgeBaseTools:

    def test_search_knowledge(self):
        result = search_knowledge("nmap")
        assert "nmap" in result.lower() or "No results" not in result

    def test_search_knowledge_no_results(self):
        result = search_knowledge("zzzznonexistent12345")
        assert "No results" in result

    def test_get_knowledge_section(self):
        result = get_knowledge_section("Cryptography")
        assert len(result) > 0
        assert "not found" not in result.lower()

    def test_get_knowledge_section_missing(self):
        result = get_knowledge_section("nonexistent")
        assert "not found" in result.lower()

    def test_list_knowledge_categories(self):
        result = list_knowledge_categories()
        assert "crypto" in result.lower()


# -------------------------------------------------------------------
# Resource endpoints
# -------------------------------------------------------------------

class TestResourceEndpoints:

    def test_kb_summary(self):
        result = kb_summary()
        assert "Knowledge Base" in result

    def test_kb_sections(self):
        result = json.loads(kb_sections())
        assert isinstance(result, list)
        assert len(result) > 0

    def test_kb_categories(self):
        result = json.loads(kb_categories())
        assert "crypto" in result


# -------------------------------------------------------------------
# Analysis tools
# -------------------------------------------------------------------

class TestAnalysisTools:

    def test_analyze_artifact_missing_file(self):
        result = json.loads(analyze_artifact("/tmp/nonexistent_xyz"))
        assert "error" in result

    def test_analyze_artifact_real_file(self):
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="w") as f:
            f.write("Hello World")
            f.flush()
            result = json.loads(analyze_artifact(f.name))
        assert "path" in result or "error" not in result

    def test_identify_encoding_base64(self):
        result = json.loads(identify_encoding("SGVsbG8gV29ybGQ="))
        assert "base64" in str(result)

    def test_identify_encoding_hex(self):
        result = json.loads(identify_encoding("48656c6c6f"))
        assert "hex" in str(result)


# -------------------------------------------------------------------
# Crypto tools
# -------------------------------------------------------------------

class TestCryptoTools:

    def test_rot13(self):
        result = json.loads(crypto_rot13("Hello"))
        assert result["result"] == "Uryyb"

    def test_caesar(self):
        result = json.loads(crypto_caesar("abc", 3))
        assert result["result"] == "def"

    def test_base64_decode(self):
        result = json.loads(crypto_base64_decode("SGVsbG8="))
        assert result["result"] == "Hello"

    def test_hex_decode(self):
        result = json.loads(crypto_hex_decode("48656c6c6f"))
        assert result["result"] == "Hello"


# -------------------------------------------------------------------
# Skill meta-tools
# -------------------------------------------------------------------

class TestSkillMetaTools:

    def test_list_skills(self):
        result = list_skills()
        assert "analysis" in result
        assert "crypto_solver" in result

    def test_run_skill(self):
        result = json.loads(run_skill("crypto_solver", json.dumps({
            "action": "rot13",
            "text": "Hello",
        })))
        assert result.get("result") == "Uryyb"

    def test_run_skill_missing(self):
        result = json.loads(run_skill("nonexistent_skill"))
        assert "error" in result

"""Tests for the knowledge base (context/knowledge_base.py)."""

from pathlib import Path

import pytest

from context.knowledge_base import KnowledgeBase, category_for

ROOT = Path(__file__).resolve().parent.parent
KB = KnowledgeBase.from_readme(ROOT / "KNOWLEDGE_BASE.md")


# -------------------------------------------------------------------
# Parsing
# -------------------------------------------------------------------

class TestKnowledgeBaseParsing:

    def test_sections_not_empty(self):
        assert len(KB.sections) > 0

    def test_known_sections_present(self):
        titles = {s.title.lower() for s in KB.sections}
        for expected in ("cryptography", "steganography", "forensics", "web"):
            assert expected in titles, f"Missing section: {expected}"

    def test_entries_parsed(self):
        """At least some sections should contain entries."""
        total = sum(len(s.entries) for s in KB.sections)
        assert total > 0

    def test_summary_output(self):
        summary = KB.summary()
        assert "Knowledge Base" in summary


# -------------------------------------------------------------------
# Category mapping
# -------------------------------------------------------------------

class TestCategoryMapping:

    @pytest.mark.parametrize("title,expected", [
        ("Cryptography", "crypto"),
        ("Steganography", "stego"),
        ("Forensics", "forensics"),
        ("Web", "web"),
        ("Binary Exploitation/pwn", "pwn"),
    ])
    def test_known_categories(self, title, expected):
        assert category_for(title) == expected

    def test_unknown_defaults_to_misc(self):
        assert category_for("Something Unknown") == "misc"


# -------------------------------------------------------------------
# Search
# -------------------------------------------------------------------

class TestKnowledgeBaseSearch:

    def test_search_finds_results(self):
        results = KB.search("base64")
        assert len(results) > 0

    def test_search_limit(self):
        results = KB.search("the", limit=3)
        assert len(results) <= 3

    def test_search_no_results(self):
        results = KB.search("a_very_long_and_extremely_random_string_that_should_not_exist_in_any_kb_1234567890")
        assert len(results) == 0


# -------------------------------------------------------------------
# Section access
# -------------------------------------------------------------------

class TestKnowledgeBaseSections:

    def test_list_sections(self):
        sections = KB.list_sections()
        assert isinstance(sections, list)
        assert len(sections) > 0

    def test_get_section(self):
        sec = KB.get_section("Cryptography")
        assert sec is not None
        assert sec.title == "Cryptography"

    def test_get_section_case_insensitive(self):
        sec = KB.get_section("cryptography")
        assert sec is not None

    def test_get_section_missing(self):
        assert KB.get_section("nonexistent") is None

    def test_categories(self):
        cats = KB.categories
        assert "crypto" in cats
        assert "stego" in cats

    def test_sections_for_category(self):
        secs = KB.sections_for_category("crypto")
        assert len(secs) > 0

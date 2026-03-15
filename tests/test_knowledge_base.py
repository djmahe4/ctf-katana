"""Tests for the knowledge-base parser."""

import json
from pathlib import Path

import pytest

from katana.knowledge_base import KnowledgeBase, category_for

README = Path(__file__).resolve().parent.parent / "README.md"


@pytest.fixture(scope="module")
def kb() -> KnowledgeBase:
    return KnowledgeBase.from_readme(README)


class TestKnowledgeBaseParsing:
    def test_sections_not_empty(self, kb: KnowledgeBase):
        assert len(kb.sections) > 0

    def test_known_sections_present(self, kb: KnowledgeBase):
        titles = [s.title.lower() for s in kb.sections]
        for expected in ["cryptography", "steganography", "forensics", "web"]:
            assert expected in titles, f"Missing section: {expected}"

    def test_entries_parsed(self, kb: KnowledgeBase):
        """At least some sections should have parsed entries."""
        total_entries = sum(len(s.entries) for s in kb.sections)
        assert total_entries > 10, f"Only {total_entries} entries parsed"

    def test_summary_output(self, kb: KnowledgeBase):
        summary = kb.summary()
        assert "CTF-Katana Knowledge Base" in summary
        assert "sections" in summary


class TestCategoryMapping:
    def test_crypto_category(self):
        assert category_for("Cryptography") == "crypto"

    def test_stego_category(self):
        assert category_for("Steganography") == "stego"

    def test_forensics_category(self):
        assert category_for("Forensics") == "forensics"

    def test_web_category(self):
        assert category_for("Web") == "web"

    def test_pwn_category(self):
        assert category_for("Binary Exploitation/pwn") == "pwn"

    def test_unknown_defaults_to_misc(self):
        assert category_for("Something Unknown") == "misc"


class TestKnowledgeBaseSearch:
    def test_search_finds_results(self, kb: KnowledgeBase):
        results = kb.search("xor")
        assert len(results) > 0

    def test_search_limit(self, kb: KnowledgeBase):
        results = kb.search("the", limit=3)
        assert len(results) <= 3

    def test_search_no_results(self, kb: KnowledgeBase):
        results = kb.search("zzzznonexistenttoolzzzz")
        assert len(results) == 0


class TestKnowledgeBaseSections:
    def test_list_sections(self, kb: KnowledgeBase):
        titles = kb.list_sections()
        assert isinstance(titles, list)
        assert len(titles) > 0

    def test_get_section(self, kb: KnowledgeBase):
        section = kb.get_section("Cryptography")
        assert section is not None
        assert section.title == "Cryptography"
        assert len(section.raw_text) > 0

    def test_get_section_case_insensitive(self, kb: KnowledgeBase):
        section = kb.get_section("cryptography")
        assert section is not None

    def test_get_section_missing(self, kb: KnowledgeBase):
        section = kb.get_section("Nonexistent Section")
        assert section is None

    def test_categories(self, kb: KnowledgeBase):
        cats = kb.categories
        assert "crypto" in cats
        assert "stego" in cats

    def test_sections_for_category(self, kb: KnowledgeBase):
        sections = kb.sections_for_category("crypto")
        assert len(sections) > 0
        assert any("Cryptography" in s.title for s in sections)

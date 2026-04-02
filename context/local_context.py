"""Tier 1 (Lite) Knowledge Base built from the CTF-Katana KNOWLEDGE_BASE.md.

Parses the repository's ``KNOWLEDGE_BASE.md`` into structured, searchable sections so
that agents can look up tools, techniques and commands for any CTF category.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class KnowledgeEntry:
    """A single tool / technique bullet from the knowledge base."""
    name: str
    description: str
    commands: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)


@dataclass
class KnowledgeSection:
    """A top-level section (e.g. *Cryptography*, *Steganography*)."""
    title: str
    entries: List[KnowledgeEntry] = field(default_factory=list)
    raw_text: str = ""


# ---------------------------------------------------------------------------
# Category mapping – maps section titles to canonical categories
# ---------------------------------------------------------------------------

_CATEGORY_MAP: dict[str, str] = {
    "post-exploitation": "exploitation",
    "port enumeration": "recon",
    "445 (smb/samba)": "recon",
    "1433 (microsoft sql server)": "recon",
    "snmp": "recon",
    "microsoft office macros": "forensics",
    "retrieving network service hashes": "exploitation",
    "windows reverse shells": "exploitation",
    "known exploits": "exploitation",
    "excess": "misc",
    "esoteric languages": "misc",
    "steganography": "stego",
    "cryptography": "crypto",
    "networking": "networking",
    "php": "web",
    "pdf files": "forensics",
    "forensics": "forensics",
    "png file forensics": "forensics",
    "apk forensics": "forensics",
    "web": "web",
    "reverse engineering": "reversing",
    "powershell": "reversing",
    "windows executables": "reversing",
    "python reversing": "reversing",
    "binary exploitation/pwn": "pwn",
    "visualbasicscript reversing": "reversing",
    "miscellaneous": "misc",
    "jail breaks": "misc",
    "trivia": "misc",
}


def category_for(title: str) -> str:
    """Return the canonical category for a section *title*.

    Returns ``'misc'`` for titles not in the known mapping.
    """
    return _CATEGORY_MAP.get(title.strip().lower(), "misc")


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

_URL_RE = re.compile(r"https?://\S+")
_CODE_BLOCK_RE = re.compile(r"```[^\n]*\n(.*?)```", re.DOTALL)
_INLINE_CODE_RE = re.compile(r"`([^`]+)`")
_SETEXT_UNDERLINE = re.compile(r"^[=\-]{3,}", re.MULTILINE)

# Setext-style headers (===== or -----)
_SETEXT_H1 = re.compile(r"^(.+)\n={3,}\s*$", re.MULTILINE)
_SETEXT_H2 = re.compile(r"^(.+)\n-{3,}\s*$", re.MULTILINE)
# ATX-style headers
_ATX_HEADER = re.compile(r"^(#{1,6})\s+(.+)$", re.MULTILINE)


def _split_sections(text: str) -> List[tuple[str, str]]:
    """Split markdown *text* into ``(title, body)`` pairs."""

    # Build a list of (position, title) for every header we find
    headers: list[tuple[int, str]] = []

    for m in _SETEXT_H1.finditer(text):
        headers.append((m.start(), m.group(1).strip()))
    for m in _SETEXT_H2.finditer(text):
        headers.append((m.start(), m.group(1).strip()))
    for m in _ATX_HEADER.finditer(text):
        headers.append((m.start(), m.group(2).strip()))

    # Sort by position
    headers.sort(key=lambda h: h[0])

    sections: list[tuple[str, str]] = []
    for i, (pos, title) in enumerate(headers):
        # Body runs from after the header line to the start of the next header
        # Find the end of the header line
        header_end = text.index("\n", pos) + 1
        # Skip underline for setext headers
        if header_end < len(text) and _SETEXT_UNDERLINE.match(text[header_end:]):
            next_nl = text.find("\n", header_end)
            if next_nl != -1:
                header_end = next_nl + 1

        next_pos = headers[i + 1][0] if i + 1 < len(headers) else len(text)
        body = text[header_end:next_pos].strip()
        sections.append((title, body))

    return sections


def _parse_entries(body: str) -> List[KnowledgeEntry]:
    """Extract tool/technique entries from a section body."""
    entries: list[KnowledgeEntry] = []

    # Split on top-level bullet points (lines starting with "* ")
    parts = re.split(r"(?m)^\*\s+", body)
    for part in parts:
        part = part.strip()
        if not part:
            continue

        lines = part.split("\n", 1)
        name_line = lines[0].strip()
        rest = lines[1] if len(lines) > 1 else ""

        # Strip markdown link syntax from name
        name_match = re.match(r"\[([^\]]*)\]", name_line)
        name = name_match.group(1) if name_match else name_line.rstrip(":")
        # Clean backticks from name
        name = name.strip("`").strip()
        if not name:
            continue

        # Gather description (non-code, non-url text)
        desc_lines: list[str] = []
        for line in rest.split("\n"):
            stripped = line.strip()
            if stripped and not stripped.startswith("```") and not _URL_RE.match(stripped):
                desc_lines.append(stripped)
        description = " ".join(desc_lines)[:500]

        # Extract code blocks
        commands = [m.group(1).strip() for m in _CODE_BLOCK_RE.finditer(rest)]
        # Also grab inline code as potential commands if no code blocks found
        if not commands:
            commands = _INLINE_CODE_RE.findall(rest)

        urls = _URL_RE.findall(part)

        entries.append(KnowledgeEntry(
            name=name,
            description=description,
            commands=commands,
            urls=urls,
        ))

    return entries


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class LocalKnowledge:
    """Tier 1 (Lite) Searchable knowledge base built from KNOWLEDGE_BASE.md."""

    def __init__(self, sections: Optional[List[KnowledgeSection]] = None):
        self.sections: List[KnowledgeSection] = sections or []

    # -- construction -------------------------------------------------------

    @classmethod
    def from_file(cls, path: Optional[str | Path] = None) -> "LocalKnowledge":
        """Parse the knowledge base at *path* (defaults to ``KNOWLEDGE_BASE.md`` in repo root)."""
        if path is None:
            path = Path(__file__).resolve().parent.parent / "KNOWLEDGE_BASE.md"
        else:
            path = Path(path)

        text = path.read_text(encoding="utf-8")
        raw_sections = _split_sections(text)

        sections: list[KnowledgeSection] = []
        for title, body in raw_sections:
            # Skip meta-sections
            if title.lower() in {
                "ctf-katana", "table of contents",
                "quick start", "usage", "prerequisites",
                "installation", "running the mcp server",
                "end-to-end solving workflow", "skill tools (35)",
                "agent tools (4, ollama-backed)", "example session",
                "running tests", "project layout", "environment variables",
                "claude desktop example",
            }:
                continue
            entries = _parse_entries(body)
            sections.append(KnowledgeSection(
                title=title,
                entries=entries,
                raw_text=body,
            ))

        return cls(sections)

    # -- querying -----------------------------------------------------------

    @property
    def categories(self) -> list[str]:
        """Return a sorted list of unique canonical categories."""
        return sorted({category_for(s.title) for s in self.sections})

    def sections_for_category(self, category: str) -> list[KnowledgeSection]:
        """Return all sections matching *category*."""
        cat = category.lower()
        return [s for s in self.sections if category_for(s.title) == cat]

    def search(self, query: str, *, limit: int = 20) -> list[KnowledgeEntry]:
        """Search entries by keyword across all sections."""
        q = query.lower()
        results: list[KnowledgeEntry] = []
        for section in self.sections:
            for entry in section.entries:
                if (
                    q in entry.name.lower()
                    or q in entry.description.lower()
                    or any(q in c.lower() for c in entry.commands)
                ):
                    results.append(entry)
                    if len(results) >= limit:
                        return results
        return results

    def get_section(self, title: str) -> Optional[KnowledgeSection]:
        """Get a section by exact or case-insensitive title match."""
        t = title.lower()
        for section in self.sections:
            if section.title.lower() == t:
                return section
        return None

    def list_sections(self) -> list[str]:
        """Return all section titles."""
        return [s.title for s in self.sections]

    def summary(self) -> str:
        """Return a human-readable summary of the knowledge base."""
        lines = [f"Purple Engine Local Knowledge Base – {len(self.sections)} sections\n"]
        for section in self.sections:
            cat = category_for(section.title)
            lines.append(f"  [{cat}] {section.title} ({len(section.entries)} entries)")
        return "\n".join(lines)

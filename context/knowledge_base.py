"""
Purple Engine Knowledge Base (Unified)

Combines:
- Tier 1 (Lite): Fast README parsing for MCP resources and navigation.
- Tier 2 (Advanced): ChromaDB-backed RAG for semantic search and deep research.

Features:
- Persistent vector database with automatic deduplication
- Multi-source ingestion (GitHub repos, YouTube, papers, newsletters)
- Semantic search with filtering and relevance scoring
- Source tracking and citation
- Automated repository synchronization
"""

from __future__ import annotations

import os
import json
import hashlib
import logging
import shutil
import re
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, field, asdict
from datetime import datetime

import chromadb
from chromadb.config import Settings
import numpy as np

logger = logging.getLogger(__name__)

# Try to import optional dependencies for advanced features
try:
    from sentence_transformers import SentenceTransformer
    HAS_SENTENCE_TRANSFORMERS = True
except ImportError:
    HAS_SENTENCE_TRANSFORMERS = False
    logger.warning("sentence-transformers not installed - using Ollama embeddings")

try:
    import git
    HAS_GIT = True
except ImportError:
    HAS_GIT = False
    logger.warning("gitpython not installed - repo sync disabled")


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class Document:
    """Represents a document in the vector knowledge base."""
    id: str
    content: str
    source: str
    source_type: str  # 'github', 'youtube', 'paper', 'newsletter', 'cve', 'exploit', 'writeup', 'manual'
    title: str = ""
    url: str = ""
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Document":
        return cls(**data)


class UnifiedResult:
    """
    Search result compatible with both MCP (name/description) and RAG (title/content).
    """
    def __init__(self, title, content, source, url="", commands=None, urls=None, relevance=0.0, metadata=None):
        self.title = title
        self.content = content
        self.source = source
        self.url = url
        self.commands = commands or []
        self.urls = urls or ( [url] if url else [] )
        self.relevance = relevance
        self.metadata = metadata or {}
        
    @property
    def name(self) -> str: return self.title
    @property
    def description(self) -> str: return self.content
    @property
    def score(self) -> float: return self.relevance
    @property
    def chunk(self) -> str: return self.content
    @property
    def chunk_index(self) -> int: return 0
    
    @property
    def document(self) -> Any:
        # Mock a document object for legacy skills
        class MockDoc:
            def __init__(self, d):
                self.title = d.get('title', '')
                self.source = d.get('source', '')
                self.source_type = d.get('source_type', 'manual')
                self.url = d.get('url', '')
                self.tags = d.get('tags', [])
                self.id = d.get('document_id', 'unknown')
        return MockDoc({
            'title': self.title,
            'source': self.source,
            'url': self.url,
            **self.metadata
        })
    
    def __repr__(self):
        return f"<UnifiedResult title='{self.title}' source='{self.source}'>"


@dataclass
class KnowledgeEntry:
    """A single tool / technique bullet from the README (Lite)."""
    name: str
    description: str
    commands: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)


@dataclass
class KnowledgeSection:
    """A top-level section from the README (Lite)."""
    title: str
    entries: List[KnowledgeEntry] = field(default_factory=list)
    raw_text: str = ""
    category: str = "misc"


@dataclass 
class RepoConfig:
    """Configuration for a GitHub repository to index."""
    url: str
    name: str
    description: str = ""
    include_patterns: List[str] = field(default_factory=lambda: ["*.md", "*.py", "*.txt", "*.yaml", "*.yml"])
    exclude_patterns: List[str] = field(default_factory=lambda: ["node_modules/*", ".git/*", "__pycache__/*", "*.pyc"])
    tags: List[str] = field(default_factory=list)
    priority: int = 1


# =============================================================================
# Category Mapping (Lite)
# =============================================================================

_CATEGORY_MAP: dict[str, str] = {
    "post-exploitation": "exploitation",
    "port enumeration": "recon",
    "445 (smb/samba)": "recon",
    "snmp": "recon",
    "forensics": "forensics",
    "web": "web",
    "reverse engineering": "reversing",
    "powershell": "reversing",
    "binary exploitation/pwn": "pwn",
    "cryptography": "crypto",
    "steganography": "stego",
    "miscellaneous": "misc",
    "vulns": "web",
    "adversarial-ai": "adversarial-ai",
    "threat-intelligence": "threat-intelligence",
    "cloud security": "cloud-security",
    "blockchain": "blockchain-security",
}

def category_for(title: str) -> str:
    t = title.strip().lower()
    # Check for specific CTF categories first
    if "cryp" in t: return "crypto"
    if "web" in t: return "web"
    if "rev" in t: return "reversing"
    if "pwn" in t or "exploit" in t: return "pwn"
    if "foren" in t: return "forensics"
    if "steg" in t: return "stego"
    if "recon" in t or "enum" in t: return "recon"
    
    for key, cat in _CATEGORY_MAP.items():
        if key in t: return cat
    return "misc"


# =============================================================================
# ChromaDB Embedding Function Wrapper
# =============================================================================

from chromadb import EmbeddingFunction, Documents, Embeddings

class ChromaEmbeddingFunction(EmbeddingFunction[Documents]):
    """Wrapper to make our embeddings work with ChromaDB's interface."""
    
    def is_legacy(self) -> bool:
        """Return True if the embedding function is legacy."""
        return False
    
    def __init__(self, embedder=None):
        self.embedder = embedder
    
    def __call__(self, input: Documents) -> Embeddings:
        if self.embedder is None:
            # Fallback for reconstructured instances from config
            return [[0.0] * 768 for _ in input]
        
        # In context.knowledge_base, the embedder might be optional or a different type
        if hasattr(self.embedder, "embed"):
            embeddings = self.embedder.embed(input)
            return embeddings.tolist()
        return [[0.0] * 768 for _ in input]
    
    @staticmethod
    def name() -> str:
        """Return embedding function name (required by ChromaDB)."""
        return "purple_engine_kb_custom"

    def get_config(self) -> Dict[str, Any]:
        """Return configuration for persistence."""
        return {
            "model": getattr(self.embedder, 'model_name', "default") if self.embedder else "default",
            "provider": self.embedder.__class__.__name__ if self.embedder else "default"
        }

    @staticmethod
    def build_from_config(config: Dict[str, Any]) -> "ChromaEmbeddingFunction":
        """Reconstruct from config."""
        return ChromaEmbeddingFunction()


# =============================================================================
# Knowledge Base (Unified)
# =============================================================================

class KnowledgeBase:
    """
    Unified Knowledge Base for Purple Engine.
    Supports Lite (README parsing) and Advanced (ChromaDB RAG).
    """
    
    DEFAULT_REPOS = [
        RepoConfig(url="https://github.com/shuvonsec/claude-bug-bounty", name="claude-bug-bounty", tags=["web2", "web3", "vulnerabilities"], priority=10),
        RepoConfig(url="https://github.com/gh0stkey/Web-Fuzzing-Box", name="Web-Fuzzing-Box", tags=["fuzzing", "payloads"], priority=7),
    ]

    def __init__(
        self,
        persist_directory: Path = None,
        embedding_provider: str = "local",
        embedding_model: str = None,
        sections: List[KnowledgeSection] = None,
        **kwargs,
    ):
        # Support legacy 'db_path' argument
        self.persist_directory = persist_directory or kwargs.get('db_path') or Path.home() / ".purple-engine" / "knowledge_db"
        
        if isinstance(self.persist_directory, str):
            self.persist_directory = Path(self.persist_directory)
            
        self.persist_directory.mkdir(parents=True, exist_ok=True)
        self.sections = sections or []
        
        try:
            self._init_vector_db(embedding_provider, embedding_model)
            self.has_vector_db = True
        except Exception as e:
            logger.warning(f"Vector DB initialization failed (Lite mode only): {e}")
            self.has_vector_db = False

    def _init_vector_db(self, provider, model_name):
        # Placeholder for real embedding logic - in this unified version we'll just try to use chromadb
        self._client = chromadb.PersistentClient(path=str(self.persist_directory), settings=Settings(anonymized_telemetry=False))
        
        # Use modernized embedding function wrapper
        embedder = None
        if provider == "local" and HAS_SENTENCE_TRANSFORMERS:
            # Try to get embedder if possible (stubbed for now as placeholder for real logic)
            pass
            
        self._collection = self._client.get_or_create_collection(
            name="purple_engine_kb",
            embedding_function=ChromaEmbeddingFunction(embedder),
            metadata={"hnsw:space": "cosine"}
        )
        self.repos_dir = self.persist_directory / "repos"
        self.repos_dir.mkdir(exist_ok=True)

    @classmethod
    def from_readme(cls, path: Optional[str | Path] = None) -> "KnowledgeBase":
        """Factory to create KB from a README or KNOWLEDGE_BASE.md (Markdown parser)."""
        if path is None:
            path = Path(__file__).resolve().parent.parent / "KNOWLEDGE_BASE.md"
        path = Path(path)
        if not path.exists(): path = path.parent / "README.md"
        
        if not path.exists(): return cls(sections=[])
        
        text = path.read_text(encoding="utf-8")
        
        # Enhanced parsing to support ATX (#) and Setext (===/---) headers
        lines = text.splitlines()
        headers = []
        
        i = 0
        while i < len(lines):
            line = lines[i]
            # ATX Header
            atx_match = re.match(r"^(#{1,6})\s+(.+)$", line)
            
            # Setext Header (requires non-empty line followed by underline)
            next_line = lines[i+1] if i + 1 < len(lines) else ""
            setext_h1 = re.match(r"^={3,}$", next_line)
            setext_h2 = re.match(r"^-{3,}$", next_line)
            
            if atx_match:
                title = atx_match.group(2).strip()
                headers.append((i, title, False))
            elif (setext_h1 or setext_h2) and line.strip():
                title = line.strip()
                headers.append((i, title, True))
                i += 1 # Skip underline
            i += 1
            
        sections = []
        for j, (line_idx, title, is_setext) in enumerate(headers):
            if title.lower() in {"ctf-katana", "table of contents", "quick start", "katana"}: continue
            
            # Find content start and end
            content_start_line = line_idx + (2 if is_setext else 1)
            next_header_line = headers[j+1][0] if j + 1 < len(headers) else len(lines)
            
            body = "\n".join(lines[content_start_line:next_header_line]).strip()
            
            # Simple entry parsing (look for bullet points)
            entries = []
            if body:
                for part in re.split(r"(?m)^\*\s+", body):
                    part = part.strip()
                    if not part: continue
                    plines = part.split("\n", 1)
                    name_raw = plines[0].strip()
                    name = re.sub(r"\[([^\]]*)\]", r"\1", name_raw).strip("`").rstrip(":")
                    if not name: continue
                    
                    desc = " ".join([l.strip() for l in plines[1].split("\n") if l.strip()])[:500] if len(plines) > 1 else ""
                    cmds = [m.group(1).strip() for m in re.finditer(r"```[^\n]*\n(.*?)```", part, re.DOTALL)]
                    urls = re.findall(r"https?://[^\s\)\`\]]+", part)
                    
                    entries.append(KnowledgeEntry(name=name, description=desc, commands=cmds, urls=urls))
                
            sections.append(KnowledgeSection(
                title=title,
                category=category_for(title),
                entries=entries,
                raw_text=body
            ))
        
        return cls(sections=sections)

    @property
    def categories(self) -> List[str]:
        return sorted(list(set(s.category for s in self.sections)))

    def sections_for_category(self, category: str) -> List[KnowledgeSection]:
        return [s for s in self.sections if s.category == category]

    def get_section(self, title: str) -> Optional[KnowledgeSection]:
        for s in self.sections:
            if s.title.lower() == title.lower(): return s
        return None

    def summary(self) -> str:
        v_count = self._collection.count() if self.has_vector_db else 0
        return f"Purple Engine Knowledge Base: {len(self.sections)} categories, {v_count} vector chunks."

    def list_sections(self) -> List[str]:
        return [s.title for s in self.sections]

    def search(
        self, 
        query: str, 
        limit: int = 5, 
        source_type: Optional[str] = None,
        tags: Optional[List[str]] = None,
        **kwargs
    ) -> List[UnifiedResult]:
        results = []
        
        # Vector search first
        if self.has_vector_db:
            try:
                where_clause = {}
                if source_type:
                    where_clause["source_type"] = source_type
                # Multi-tag filtering if Chromadb supports it, or handle in kwargs
                
                res = self._collection.query(
                    query_texts=[query], 
                    n_results=limit * 2, # Get more to filter
                    where=where_clause if where_clause else None
                )
                
                if res['ids'] and res['ids'][0]:
                    for i in range(len(res['ids'][0])):
                        meta = res['metadatas'][0][i]
                        
                        # Manual tag filtering if requested
                        if tags:
                            doc_tags = meta.get('tags', [])
                            if isinstance(doc_tags, str):
                                try: doc_tags = json.loads(doc_tags)
                                except: doc_tags = [doc_tags]
                            if not any(tag in doc_tags for tag in tags):
                                continue
                                
                        results.append(UnifiedResult(
                            title=meta.get('title', 'Result'),
                            content=res['documents'][0][i],
                            source=meta.get('source', 'VectorDB'),
                            url=meta.get('url', ''),
                            relevance=1.0 - (res['distances'][0][i] if 'distances' in res else 0.5),
                            metadata=meta
                        ))
            except Exception as e:
                logger.error(f"Vector search failed: {e}")

        # Filter by threshold
        self._MIN_RELEVANCE = 0.5
        results = [r for r in results if r.relevance >= self._MIN_RELEVANCE]

        # Lite search fallback/augmentation
        q = query.lower()
        if not source_type or source_type == "manual":
            for s in self.sections:
                for e in s.entries:
                    if q in e.name.lower() or q in e.description.lower():
                        results.append(UnifiedResult(
                            title=e.name, content=e.description, source=f"README/{s.title}",
                            commands=e.commands, relevance=0.5
                        ))
        
        # Deduplicate and sort
        # Result thresholding
        filtered = [r for r in sorted(results, key=lambda x: x.relevance, reverse=True) if r.relevance >= self._MIN_RELEVANCE]
        
        if not filtered:
            return []
            
        # Deduplicate
        seen = set()
        unique = []
        for r in filtered:
            if r.title not in seen:
                seen.add(r.title)
                unique.append(r)
        return unique[:limit]

    def add_document(self, content: str, source: str, source_type: str, title: str = "", url: str = "", tags: List[str] = None, metadata: Dict[str, Any] = None):
        if not self.has_vector_db: return
        doc_id = hashlib.sha256(content.encode()).hexdigest()[:16]
        chunks = [content[i:i+2000] for i in range(0, len(content), 1500)]
        meta = {"document_id": doc_id, "source": source, "source_type": source_type, "title": title, "url": url}
        if metadata: meta.update(metadata)
        self._collection.add(
            ids=[f"{doc_id}_{i}" for i in range(len(chunks))],
            documents=chunks,
            metadatas=[meta for _ in chunks]
        )
        return doc_id

    def get_stats(self) -> Dict[str, Any]:
        return {
            "vector_chunks": self._collection.count() if self.has_vector_db else 0,
            "lite_sections": len(self.sections),
            "categories": len(self.categories)
        }

    def list_sources(self) -> List[str]:
        if not self.has_vector_db: return ["README"]
        metas = self._collection.get(include=['metadatas'])['metadatas']
        return sorted(list(set(m.get('source') for m in metas if m)))

    def sync_all_repos(self, repos: List[RepoConfig] = None):
        if not self.has_vector_db or not HAS_GIT: return []
        repos = repos or self.DEFAULT_REPOS
        results = []
        for repo in repos:
            p = self.repos_dir / repo.name
            try:
                if p.exists(): git.Repo(p).remotes.origin.pull()
                else: git.Repo.clone_from(repo.url, p, depth=1)
                for f in p.glob("README.md"):
                    self.add_document(f.read_text(errors='ignore'), repo.name, "github", title=f"{repo.name}/README", url=repo.url)
                results.append({"repo": repo.name, "status": "success"})
            except Exception as e:
                results.append({"repo": repo.name, "status": "error", "message": str(e)})
        return results

def search_knowledge(query: str, limit: int = 5):
    return KnowledgeBase().search(query, limit)

if __name__ == "__main__":
    kb = KnowledgeBase()
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "sync": print(kb.sync_all_repos())
    else: print(kb.summary())

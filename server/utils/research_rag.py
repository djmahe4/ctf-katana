"""Tier 2 (Pro) Semantic Research RAG system for Purple Engine.

Production-grade RAG (Retrieval-Augmented Generation) system using:
- ChromaDB for vector storage and semantic search
- Sentence-Transformers for local embeddings (no API keys needed)
- GitPython for repository syncing
- Ollama integration for optional LLM-based embeddings

Features:
- Persistent vector database with automatic deduplication
- Multi-source ingestion (GitHub repos, YouTube, papers, newsletters)
- Semantic search with filtering and relevance scoring
- Automatic repo syncing via cron-compatible commands
- Source tracking and citation
"""

import os
import json
import hashlib
import logging
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, field, asdict
from datetime import datetime
import re

import chromadb
from chromadb.config import Settings
import numpy as np

logger = logging.getLogger(__name__)

# Try to import sentence-transformers for local embeddings
try:
    from sentence_transformers import SentenceTransformer
    HAS_SENTENCE_TRANSFORMERS = True
except ImportError:
    HAS_SENTENCE_TRANSFORMERS = False
    logger.warning("sentence-transformers not installed - using Ollama embeddings")

# Try to import git for repo operations
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
    """Represents a document in the research RAG."""
    id: str
    content: str
    source: str
    source_type: str  # 'github', 'youtube', 'paper', 'newsletter', 'cve', 'exploit', 'writeup', 'manual', 'seed'
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


@dataclass
class SearchResult:
    """Represents a search result from the RAG."""
    document_id: str
    content: str
    source: str
    source_type: str
    title: str
    url: str
    tags: List[str]
    metadata: Dict[str, Any]
    score: float  # Distance (lower = more similar for ChromaDB)
    relevance: float  # Converted to 0-1 relevance score


@dataclass 
class RepoConfig:
    """Configuration for a GitHub repository to index."""
    url: str
    name: str
    description: str = ""
    include_patterns: List[str] = field(default_factory=lambda: ["*.md", "*.py", "*.txt", "*.yaml", "*.yml"])
    exclude_patterns: List[str] = field(default_factory=lambda: ["node_modules/*", ".git/*", "__pycache__/*", "*.pyc"])
    tags: List[str] = field(default_factory=list)
    priority: int = 1  # Higher = more important


# =============================================================================
# Embedding Providers
# =============================================================================

class LocalEmbeddings:
    """
    Generate embeddings using local Sentence-Transformers models.
    
    No API keys required - everything runs locally.
    Default model: all-MiniLM-L6-v2 (fast, 384 dimensions)
    """
    
    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        if not HAS_SENTENCE_TRANSFORMERS:
            raise ImportError("sentence-transformers required for local embeddings")
        
        self.model_name = model_name
        self._model = None
        self._dimension = None
    
    @property
    def model(self):
        if self._model is None:
            logger.info(f"Loading embedding model: {self.model_name}")
            self._model = SentenceTransformer(self.model_name)
            self._dimension = self._model.get_sentence_embedding_dimension()
        return self._model
    
    def embed(self, texts: Union[str, List[str]]) -> np.ndarray:
        """Generate embeddings for text(s)."""
        if isinstance(texts, str):
            texts = [texts]
        return self.model.encode(texts, convert_to_numpy=True)
    
    @property
    def dimension(self) -> int:
        if self._dimension is None:
            _ = self.model  # Force load
        return self._dimension


class OllamaEmbeddings:
    """
    Generate embeddings using Ollama's local models.
    
    Supports: nomic-embed-text, mxbai-embed-large, all-minilm
    """
    
    def __init__(
        self,
        model: str = "nomic-embed-text",
        host: str = None,
    ):
        self.model = model
        self.host = host or os.environ.get("KATANA_OLLAMA_HOST", "http://localhost:11434")
        self._dimension = None
    
    def embed(self, texts: Union[str, List[str]]) -> np.ndarray:
        """Generate embeddings for text(s)."""
        import requests
        
        if isinstance(texts, str):
            texts = [texts]
        
        embeddings = []
        for text in texts:
            try:
                response = requests.post(
                    f"{self.host}/api/embeddings",
                    json={"model": self.model, "prompt": text},
                    timeout=30
                )
                response.raise_for_status()
                embedding = response.json().get("embedding", [])
                embeddings.append(embedding)
                
                if not self._dimension:
                    self._dimension = len(embedding)
                    
            except Exception as e:
                logger.error(f"Ollama embedding error: {e}")
                embeddings.append([0.0] * (self._dimension or 768))
        
        return np.array(embeddings)
    
    @property
    def dimension(self) -> int:
        return self._dimension or 768


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
        embeddings = self.embedder.embed(input)
        return embeddings.tolist()
    
    def embed_documents(self, input: List[str]) -> List[List[float]]:
        """Embed documents (for adding to collection)."""
        return self.__call__(input)
    
    def embed_query(self, input: List[str]) -> List[List[float]]:
        """Embed query (for searching)."""
        return self.__call__(input)
    
    @staticmethod
    def name() -> str:
        """Return embedding function name (required by ChromaDB)."""
        return "purple_engine_custom"

    def get_config(self) -> Dict[str, Any]:
        """Return configuration for persistence."""
        return {
            "model": getattr(self.embedder, 'model_name', getattr(self.embedder, 'model', 'unknown')) if self.embedder else "unknown",
            "provider": self.embedder.__class__.__name__ if self.embedder else "unknown"
        }

    @staticmethod
    def build_from_config(config: Dict[str, Any]) -> "ChromaEmbeddingFunction":
        """Reconstruct from config."""
        return ChromaEmbeddingFunction()


# =============================================================================
# Research RAG
# =============================================================================

class ResearchRAG:
    """
    Tier 2 (Pro) Semantic Research RAG system for Purple Engine.
    
    Uses ChromaDB for vector storage and semantic search.
    Supports multiple embedding providers (local or Ollama).
    """
    
    # Default repositories to index
    DEFAULT_REPOS: List[RepoConfig] = [
        RepoConfig(
            url="https://github.com/shuvonsec/claude-bug-bounty",
            name="claude-bug-bounty",
            description="Web2 + Web3 vulnerability classes with hunting patterns",
            tags=["web2", "web3", "vulnerabilities", "bug-bounty"],
            priority=10,
        ),
        RepoConfig(
            url="https://github.com/crytic/slither",
            name="slither",
            description="Static analysis framework for smart contracts",
            tags=["web3", "security", "static-analysis"],
            priority=9,
        ),
        RepoConfig(
            url="https://github.com/RhinoSecurityLabs/pacu",
            name="pacu",
            description="AWS exploitation framework",
            tags=["cloud", "aws", "exploitation"],
            priority=9,
        ),
        RepoConfig(
            url="https://github.com/prowler-cloud/prowler",
            name="prowler",
            description="Cloud security posture management (AWS, Azure, GCP)",
            tags=["cloud", "compliance", "security"],
            priority=8,
        ),
        RepoConfig(
            url="https://github.com/xcellerator/linux-kernel-exploitation",
            name="linux-kernel-exploitation",
            description="Linux kernel vulnerability research",
            tags=["pwn", "kernel", "linux"],
            priority=8,
        ),
        RepoConfig(
            url="https://github.com/LucidAkshay/kavach",
            name="kavach",
            description="AI firewall/EDR security patterns",
            tags=["firewall", "edr", "security"],
            priority=8,
        ),
        RepoConfig(
            url="https://github.com/SunWeb3Sec/llm-sast-scanner",
            name="llm-sast-scanner",
            description="LLM-based SAST vulnerability analysis",
            tags=["llm", "sast", "analysis"],
            priority=6,
        ),
        RepoConfig(
            url="https://github.com/microsoft/RustTraining",
            name="RustTraining",
            description="Rust secure coding patterns",
            tags=["rust", "secure-coding", "training"],
            priority=4,
        ),
        RepoConfig(
            url="https://github.com/OpenZeppelin/openzeppelin-contracts",
            name="OpenZeppelin",
            description="Golden standard for secure smart contracts",
            tags=["web3", "solidity", "security-patterns"],
            priority=10,
        ),
        RepoConfig(
            url="https://github.com/Gallopsled/pwntools",
            name="pwntools",
            description="CTF framework and exploit development library",
            tags=["pwn", "exploitation", "binary"],
            priority=9,
        ),
        RepoConfig(
            url="https://github.com/unitedbyai/droidclaw",
            name="droidclaw",
            description="AI Android security",
            tags=["android", "mobile", "security"],
            priority=5,
        ),
        RepoConfig(
            url="https://github.com/gh0stkey/Web-Fuzzing-Box",
            name="Web-Fuzzing-Box",
            description="Payloads and fuzzing wordlists",
            tags=["fuzzing", "payloads", "wordlists"],
            priority=7,
        ),
        RepoConfig(
            url="https://github.com/IamAlch3mist/Awesome-Embedded-Systems-Vulnerability-Research",
            name="Awesome-Embedded-Systems",
            description="IoT/embedded security research",
            tags=["iot", "embedded", "hardware"],
            priority=6,
        ),
        RepoConfig(
            url="https://github.com/0xor0ne/awesome-list",
            name="awesome-cybersecurity-papers",
            description="Curated cybersecurity research papers",
            tags=["papers", "research", "academic"],
            priority=5,
        ),
    ]
    
    def __init__(
        self,
        persist_directory: Path = None,
        collection_name: str = "purple_engine_kb",
        embedding_provider: str = "ollama",  # 'local' or 'ollama'
        embedding_model: str = None,
        chunk_size: int = 1000,
        chunk_overlap: int = 200,
    ):
        self.persist_directory = Path(persist_directory) if persist_directory else Path.home() / ".purple-engine" / "knowledge_db"
        self.persist_directory.mkdir(parents=True, exist_ok=True)
        
        self.collection_name = collection_name
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap
        
        # Initialize embedding provider
        if embedding_provider == "local" and HAS_SENTENCE_TRANSFORMERS:
            model = embedding_model or "all-MiniLM-L6-v2"
            self._embedder = LocalEmbeddings(model_name=model)
        else:
            model = embedding_model or "nomic-embed-text"
            self._embedder = OllamaEmbeddings(model=model)
        
        # Initialize ChromaDB
        self._client = chromadb.PersistentClient(
            path=str(self.persist_directory),
            settings=Settings(anonymized_telemetry=False),
        )
        
        # Get or create collection
        self._collection = self._client.get_or_create_collection(
            name=collection_name,
            embedding_function=ChromaEmbeddingFunction(self._embedder),
            metadata={"hnsw:space": "cosine"}  # Use cosine similarity
        )
        
        # Repos directory for cloned repos
        self.repos_dir = self.persist_directory / "repos"
        self.repos_dir.mkdir(exist_ok=True)
        
        logger.info(f"ResearchRAG initialized: {self.persist_directory}")
        logger.info(f"Collection: {collection_name}, Documents: {self._collection.count()}")
    
    def _chunk_text(self, text: str) -> List[str]:
        """Split text into overlapping chunks."""
        # Clean text
        text = re.sub(r'\s+', ' ', text).strip()
        
        if len(text) <= self.chunk_size:
            return [text] if text else []
        
        chunks = []
        start = 0
        
        while start < len(text):
            end = start + self.chunk_size
            
            # Try to break at sentence boundary
            if end < len(text):
                # Look for sentence end near chunk boundary
                for sep in ['. ', '.\n', '! ', '? ', '\n\n']:
                    last_sep = text.rfind(sep, start + self.chunk_size // 2, end)
                    if last_sep != -1:
                        end = last_sep + len(sep)
                        break
            
            chunk = text[start:end].strip()
            if chunk:
                chunks.append(chunk)
            
            # Move start with overlap
            start = end - self.chunk_overlap
            if start >= len(text) - self.chunk_overlap:
                break
        
        return chunks
    
    def add_document(
        self,
        content: str,
        source: str,
        source_type: str,
        title: str = "",
        url: str = "",
        tags: List[str] = None,
        metadata: Dict[str, Any] = None,
    ) -> str:
        """
        Add a document to the research RAG.
        
        Automatically chunks content and generates embeddings.
        Returns: document ID
        """
        # Generate document ID
        doc_id = hashlib.sha256(content.encode()).hexdigest()[:16]
        
        # Check for existing chunks from this document
        existing = self._collection.get(
            where={"document_id": doc_id},
            limit=1
        )
        if existing['ids']:
            logger.debug(f"Document {doc_id} already exists, skipping")
            return doc_id
        
        # Chunk content
        chunks = self._chunk_text(content)
        if not chunks:
            logger.warning(f"No content to index for {source}")
            return doc_id
        
        # Prepare data for ChromaDB
        ids = [f"{doc_id}_{i}" for i in range(len(chunks))]
        metadatas = [
            {
                "document_id": doc_id,
                "chunk_index": i,
                "source": source,
                "source_type": source_type,
                "title": title,
                "url": url,
                "tags": json.dumps(tags or []),
                "created_at": datetime.utcnow().isoformat(),
                **(metadata or {}),
            }
            for i in range(len(chunks))
        ]
        
        # Add to collection
        self._collection.add(
            ids=ids,
            documents=chunks,
            metadatas=metadatas,
        )
        
        logger.info(f"Added document {doc_id}: {len(chunks)} chunks from {source}")
        return doc_id
    
    def search(
        self,
        query: str,
        limit: int = 10,
        source_type: Optional[str] = None,
        tags: Optional[List[str]] = None,
        min_relevance: float = 0.0,
        preferred_source_type: Optional[str] = None,
        where: Optional[Dict[str, Any]] = None,
    ) -> List[SearchResult]:
        """
        Semantic search over the research RAG.
        
        Returns: List of SearchResults sorted by relevance
        """
        # Build where filter
        final_where = where or {}
        if source_type:
            final_where["source_type"] = source_type
        
        # Query ChromaDB
        results = self._collection.query(
            query_texts=[query],
            n_results=limit * 3,  # Get more, then filter and boost
            where=final_where if final_where else None,
            include=["documents", "metadatas", "distances"],
        )
        
        # Process results
        search_results = []
        
        if results['ids'] and results['ids'][0]:
            for i, doc_id in enumerate(results['ids'][0]):
                distance = results['distances'][0][i]
                # Convert cosine distance to relevance (1 - distance for cosine)
                relevance = 1 - distance
                
                metadata = results['metadatas'][0][i]
                doc_type = metadata.get('source_type', '')
                
                # Apply boost for preferred source type
                if preferred_source_type and doc_type == preferred_source_type:
                    relevance += 0.2  # 20% boost
                
                if relevance < min_relevance:
                    continue
                
                doc_tags = json.loads(metadata.get('tags', '[]'))
                
                # Filter by tags if specified
                if tags and not any(t in doc_tags for t in tags):
                    continue
                
                search_results.append(SearchResult(
                    document_id=metadata.get('document_id', ''),
                    content=results['documents'][0][i],
                    source=metadata.get('source', ''),
                    source_type=doc_type,
                    title=metadata.get('title', ''),
                    url=metadata.get('url', ''),
                    tags=doc_tags,
                    metadata=metadata,
                    score=distance,
                    relevance=round(min(relevance, 1.0), 4),
                ))
        
        # Sort by relevance and limit
        search_results.sort(key=lambda r: r.relevance, reverse=True)
        return search_results[:limit]
    
    def sync_repo(self, repo: RepoConfig, force: bool = False) -> Dict[str, Any]:
        """
        Clone/pull a repository and index its contents.
        
        This is cron-friendly - can be called periodically to keep RAG updated.
        """
        if not HAS_GIT:
            return {"status": "error", "message": "gitpython not installed"}
        
        repo_path = self.repos_dir / repo.name
        
        try:
            if repo_path.exists():
                # Pull latest changes
                logger.info(f"Pulling updates for {repo.name}")
                g = git.Repo(repo_path)
                origin = g.remotes.origin
                origin.pull()
                action = "updated"
            else:
                # Clone repository
                logger.info(f"Cloning {repo.name} from {repo.url}")
                git.Repo.clone_from(repo.url, repo_path, depth=1)
                action = "cloned"
            
            # Index repository contents
            indexed_count = self._index_repo_contents(repo_path, repo)
            
            return {
                "status": "success",
                "action": action,
                "repo": repo.name,
                "indexed_files": indexed_count,
            }
            
        except Exception as e:
            logger.error(f"Repo sync error for {repo.name}: {e}")
            return {
                "status": "error",
                "repo": repo.name,
                "message": str(e),
            }
    
    def _index_repo_contents(self, repo_path: Path, repo: RepoConfig) -> int:
        """Index files from a cloned repository."""
        import fnmatch
        
        indexed_count = 0
        
        for file_path in repo_path.rglob("*"):
            if not file_path.is_file():
                continue
            
            rel_path = file_path.relative_to(repo_path)
            rel_str = str(rel_path)
            
            # Check exclude patterns
            if any(fnmatch.fnmatch(rel_str, p) for p in repo.exclude_patterns):
                continue
            
            # Check include patterns
            if not any(fnmatch.fnmatch(rel_str, p) for p in repo.include_patterns):
                continue
            
            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore')
                if len(content) < 50:  # Skip very small files
                    continue
                
                self.add_document(
                    content=content,
                    source=repo.name,
                    source_type="github",
                    title=f"{repo.name}/{rel_str}",
                    url=f"{repo.url}/blob/main/{rel_str}",
                    tags=repo.tags + [file_path.suffix.lstrip('.')],
                    metadata={"file_path": rel_str, "priority": repo.priority},
                )
                indexed_count += 1
                
            except Exception as e:
                logger.debug(f"Could not index {file_path}: {e}")
        
        return indexed_count
    
    def sync_all_repos(self, repos: List[RepoConfig] = None) -> Dict[str, Any]:
        """
        Sync all configured repositories.
        
        Designed for cron usage:
        ```
        python -c "from server.utils.research_rag import ResearchRAG; ResearchRAG().sync_all_repos()"
        ```
        """
        repos = repos or self.DEFAULT_REPOS
        results = []
        
        for repo in repos:
            result = self.sync_repo(repo)
            results.append(result)
        
        successful = sum(1 for r in results if r.get('status') == 'success')
        
        return {
            "status": "success" if successful > 0 else "error",
            "total_repos": len(repos),
            "successful": successful,
            "results": results,
        }
    
    def get_stats(self) -> Dict[str, Any]:
        """Get research RAG statistics (safe for large collections)."""
        count = self._collection.count()
        
        return {
            "total_chunks": count,
            "persist_directory": str(self.persist_directory),
            "embedding_model": getattr(self._embedder, 'model', 'all-MiniLM-L6-v2'),
        }
    
    def clear(self):
        """Clear all documents from research RAG."""
        self._client.delete_collection(self.collection_name)
        self._collection = self._client.create_collection(
            name=self.collection_name,
            embedding_function=ChromaEmbeddingFunction(self._embedder),
            metadata={"hnsw:space": "cosine"}
        )
        logger.info("Research RAG cleared")


# =============================================================================
# Convenience Functions
# =============================================================================

def search_research(query: str, limit: int = 5, **kwargs) -> List[Dict[str, Any]]:
    """
    Quick search function for use in research agent prompts.
    
    Returns simplified results for LLM consumption.
    """
    rag = ResearchRAG()
    results = rag.search(query, limit=limit, **kwargs)
    
    return [
        {
            'title': r.title or r.source,
            'source': r.source,
            'source_type': r.source_type,
            'url': r.url,
            'relevance': r.relevance,
            'excerpt': r.content[:500] + "..." if len(r.content) > 500 else r.content,
            'tags': r.tags,
        }
        for r in results
    ]


def sync_repos():
    """CLI-friendly function for cron jobs."""
    rag = ResearchRAG()
    result = rag.sync_all_repos()
    print(json.dumps(result, indent=2))
    return result


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        
        if cmd == "sync":
            sync_repos()
        elif cmd == "stats":
            rag = ResearchRAG()
            print(json.dumps(rag.get_stats(), indent=2))
        elif cmd == "search":
            query = " ".join(sys.argv[2:])
            results = search_research(query)
            print(json.dumps(results, indent=2))
        elif cmd == "clear":
            rag = ResearchRAG()
            rag.clear()
            print("Research RAG cleared")
        else:
            print(f"Unknown command: {cmd}")
            print("Usage: python research_rag.py [sync|stats|search <query>|clear]")
    else:
        print("Purple Engine Research RAG")
        print("Usage: python research_rag.py [sync|stats|search <query>|clear]")


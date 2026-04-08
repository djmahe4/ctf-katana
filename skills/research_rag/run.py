"""
RAG (Retrieval-Augmented Generation) Skill for Purple Engine

Provides semantic search over the local security knowledge base.
Supports searching, adding documents, and ingesting from various sources.
"""

import os
import sys
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime

# Add project root to path
project_root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(project_root))

from context.knowledge_base import KnowledgeBase, Document, search_knowledge

logger = logging.getLogger(__name__)


class RAGSkill:
    """
    RAG Skill Implementation.
    
    Provides knowledge base search and management for Purple Engine agents.
    """
    
    def __init__(
        self,
        db_path: Optional[Path] = None,
        embedding_model: str = None,
    ):
        # Get embedding model from environment or use default
        self.embedding_model = embedding_model or os.environ.get(
            "KATANA_EMBEDDING_MODEL", "nomic-embed-text"
        )
        
        # Initialize knowledge base
        self.kb = KnowledgeBase(
            db_path=db_path,
            embedding_model=self.embedding_model,
        )
        
        logger.info(f"RAGSkill initialized with model: {self.embedding_model}")
    
    def search(
        self,
        query: str,
        limit: int = 5,
        source_type: Optional[str] = None,
        tags: Optional[List[str]] = None,
        min_score: float = 0.0,
    ) -> Dict[str, Any]:
        """
        Search the knowledge base.
        
        Args:
            query: Search query
            limit: Maximum results
            source_type: Filter by source type
            tags: Filter by tags
            min_score: Minimum relevance score
        
        Returns:
            Search results with relevance scores
        """
        try:
            results = self.kb.search(
                query=query,
                limit=limit,
                source_type=source_type,
                tags=tags,
                min_score=min_score,
            )
            
            # Format results for output
            formatted_results = []
            for r in results:
                formatted_results.append({
                    'title': r.document.title or r.document.source,
                    'source': r.document.source,
                    'source_type': r.document.source_type,
                    'url': r.document.url,
                    'relevance': round(r.score, 4),
                    'excerpt': r.chunk[:500] + "..." if len(r.chunk) > 500 else r.chunk,
                    'chunk_index': r.chunk_index,
                    'tags': r.document.tags,
                    'document_id': r.document.id,
                })
            
            return {
                'status': 'success',
                'query': query,
                'results': formatted_results,
                'total_found': len(formatted_results),
                'filters_applied': {
                    'source_type': source_type,
                    'tags': tags,
                    'min_score': min_score,
                },
            }
            
        except Exception as e:
            logger.error(f"Search error: {e}")
            return {
                'status': 'error',
                'message': str(e),
                'query': query,
            }
    
    def add_document(
        self,
        content: str,
        source: str,
        source_type: str,
        title: str = "",
        url: str = "",
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Add a document to the knowledge base.
        
        Args:
            content: Document text content
            source: Source identifier (e.g., repo name, website)
            source_type: Type of source
            title: Document title
            url: Source URL
            tags: Document tags
            metadata: Additional metadata
        
        Returns:
            Document ID and status
        """
        try:
            doc_id = self.kb.add_document(
                content=content,
                source=source,
                source_type=source_type,
                title=title,
                url=url,
                tags=tags,
                metadata=metadata,
            )
            
            return {
                'status': 'success',
                'message': f'Document added successfully',
                'document_id': doc_id,
                'title': title or source,
            }
            
        except Exception as e:
            logger.error(f"Add document error: {e}")
            return {
                'status': 'error',
                'message': str(e),
            }
    
    def ingest_github_repo(
        self,
        repo_url: str,
        include_patterns: List[str] = None,
        exclude_patterns: List[str] = None,
    ) -> Dict[str, Any]:
        """
        Ingest a GitHub repository into the knowledge base.
        
        Clones/downloads repo and indexes relevant files.
        """
        # Extract repo info from URL
        parts = repo_url.rstrip('/').split('/')
        repo_name = parts[-1]
        owner = parts[-2] if len(parts) >= 2 else "unknown"
        
        try:
            import requests
            b="main"
            # Get repo README first
            readme_url = f"https://raw.githubusercontent.com/{owner}/{repo_name}/{b}/README.md"
            response = requests.get(readme_url, timeout=30)
            
            if response.status_code == 404:
                # Try master branch
                b="master"
                readme_url = f"https://raw.githubusercontent.com/{owner}/{repo_name}/{b}/README.md"
                response = requests.get(readme_url, timeout=30)
            
            if response.status_code == 200:
                self.add_document(
                    content=response.text,
                    source=repo_name,
                    source_type="github",
                    title=f"{repo_name} README",
                    url=repo_url,
                    tags=["readme", "documentation"],
                    metadata={"owner": owner, "branch": b},
                )
            
            # Get repo info via API
            api_url = f"https://api.github.com/repos/{owner}/{repo_name}"
            response = requests.get(api_url, timeout=30)
            
            if response.status_code == 200:
                repo_info = response.json()
                description = repo_info.get('description', '')
                topics = repo_info.get('topics', [])
                
                return {
                    'status': 'success',
                    'message': f'Ingested {repo_name}',
                    'repo': repo_name,
                    'description': description,
                    'topics': topics,
                    'documents_added': 1,  # README for now
                }
            else:
                return {
                    'status': 'partial',
                    'message': f'Ingested README only (API rate limited)',
                    'repo': repo_name,
                }
                
        except Exception as e:
            logger.error(f"Ingest error: {e}")
            return {
                'status': 'error',
                'message': str(e),
                'repo_url': repo_url,
            }
    
    def ingest_youtube_ocr(
        self,
        url: str,
        results: List[Dict[str, Any]],
        title: str = "",
        tags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Ingest OCR results from AdvancedYTScraper into the knowledge base.
        """
        try:
            # Extract video ID from URL
            video_id = url.split("v=")[-1].split("&")[0] if "v=" in url else url
            source = f"youtube_{video_id}"
            
            docs_added = 0
            for item in results:
                timestamp = item.get("timestamp", 0)
                ocr_text = item.get("ocr_text", "")
                frame_path = item.get("frame_path", "")
                is_terminal = item.get("is_terminal", False)
                
                if not ocr_text.strip():
                    continue
                
                # Add each frame as a semantic chunk with precise metadata
                self.add_document(
                    content=ocr_text,
                    source=source,
                    source_type="youtube",
                    title=title or f"YouTube Walkthrough: {video_id}",
                    url=url,
                    tags=(tags or []) + ["ocr", "walkthrough"] + (["terminal"] if is_terminal else ["gui"]),
                    metadata={
                        "timestamp": timestamp,
                        "frame_path": frame_path,
                        "video_id": video_id,
                        "is_terminal": is_terminal
                    }
                )
                docs_added += 1
            
            return {
                'status': 'success',
                'message': f'Ingested {docs_added} frames from YouTube OCR',
                'video_id': video_id,
                'frames_indexed': docs_added
            }
        except Exception as e:
            logger.error(f"YouTube ingestion error: {e}")
            return {
                'status': 'error',
                'message': str(e),
                'url': url
            }
    
    def get_stats(self) -> Dict[str, Any]:
        """Get knowledge base statistics."""
        try:
            stats = self.kb.get_stats()
            sources = self.kb.list_sources()
            
            return {
                'status': 'success',
                'stats': stats,
                'sources': sources,
            }
            
        except Exception as e:
            logger.error(f"Stats error: {e}")
            return {
                'status': 'error',
                'message': str(e),
            }
    
    def list_sources(self) -> Dict[str, Any]:
        """List all indexed sources."""
        try:
            sources = self.kb.list_sources()
            
            return {
                'status': 'success',
                'sources': sources,
                'total_source_types': len(sources),
            }
            
        except Exception as e:
            logger.error(f"List sources error: {e}")
            return {
                'status': 'error',
                'message': str(e),
            }


def run(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main entry point for RAG Skill.
    
    Args:
        params: {
            'action': str,       # search, add, ingest, stats, list_sources
            'query': str,        # Search query (for action=search)
            'limit': int,        # Max results (default: 5)
            'source_type': str,  # Filter by source type
            'tags': list,        # Filter by tags
            'content': str,      # Document content (for action=add)
            'source': str,       # Source name (for action=add)
            'title': str,        # Document title (for action=add)
            'url': str,          # Source URL
            'repo_url': str,     # GitHub URL (for action=ingest)
        }
    
    Returns:
        {
            'status': 'success' | 'error',
            'results': [...],    # Search results
            'stats': {...},      # Knowledge base stats
        }
    """
    action = params.get('action', 'search')
    
    try:
        skill = RAGSkill()
        
        if action == 'search':
            query = params.get('query')
            if not query:
                return {
                    'status': 'error',
                    'message': 'query parameter required for search action',
                }
            
            return skill.search(
                query=query,
                limit=params.get('limit', 5),
                source_type=params.get('source_type'),
                tags=params.get('tags'),
                min_score=params.get('min_score', 0.0),
            )
        
        elif action == 'add':
            content = params.get('content')
            source = params.get('source')
            source_type = params.get('source_type', 'manual')
            
            if not content or not source:
                return {
                    'status': 'error',
                    'message': 'content and source parameters required for add action',
                }
            
            return skill.add_document(
                content=content,
                source=source,
                source_type=source_type,
                title=params.get('title', ''),
                url=params.get('url', ''),
                tags=params.get('tags'),
                metadata=params.get('metadata'),
            )
        
        elif action == 'ingest':
            repo_url = params.get('repo_url')
            if not repo_url:
                return {
                    'status': 'error',
                    'message': 'repo_url parameter required for ingest action',
                }
            
            return skill.ingest_github_repo(
                repo_url=repo_url,
                include_patterns=params.get('include_patterns'),
                exclude_patterns=params.get('exclude_patterns'),
            )
        
        elif action == 'ingest_youtube':
            url = params.get('url')
            results = params.get('results')
            if not url or not results:
                return {
                    'status': 'error',
                    'message': 'url and results parameters required for ingest_youtube action',
                }
            
            return skill.ingest_youtube_ocr(
                url=url,
                results=results,
                title=params.get('title', ''),
                tags=params.get('tags'),
            )
        
        elif action == 'stats':
            return skill.get_stats()
        
        elif action == 'list_sources':
            return skill.list_sources()
        
        else:
            return {
                'status': 'error',
                'message': f'Unknown action: {action}',
                'available_actions': ['search', 'add', 'ingest', 'stats', 'list_sources'],
            }
            
    except Exception as e:
        logger.error(f"RAG skill error: {e}")
        return {
            'status': 'error',
            'message': str(e),
            'error_type': type(e).__name__,
        }


def main():
    """CLI entry point for testing."""
    import argparse
    
    parser = argparse.ArgumentParser(description='RAG Skill CLI')
    parser.add_argument('action', choices=['search', 'add', 'ingest', 'stats', 'list_sources'])
    parser.add_argument('--query', '-q', help='Search query')
    parser.add_argument('--limit', '-l', type=int, default=5, help='Max results')
    parser.add_argument('--source-type', '-t', help='Filter by source type')
    parser.add_argument('--repo-url', '-r', help='GitHub repo URL for ingest')
    
    args = parser.parse_args()
    
    params = {
        'action': args.action,
        'query': args.query,
        'limit': args.limit,
        'source_type': args.source_type,
        'repo_url': args.repo_url,
    }
    
    result = run(params)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()

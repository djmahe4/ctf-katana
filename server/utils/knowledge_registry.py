import os
import re
import logging
from typing import Dict, List, Optional, Any
from pathlib import Path

# Tier 1 (Lite)
from context.local_context import LocalKnowledge
# Tier 2 (Pro)
from server.utils.research_rag import ResearchRAG

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("KnowledgeRegistry")

class KnowledgeRegistry:
    """
    The orchestrator for the Purple Engine's tiered knowledge architecture.
    Handles intent-based routing between LocalKnowledge, ResearchRAG, 
    and LLM-guided scraping results.
    """

    def __init__(self, workspace_root: Optional[Path] = None):
        self.workspace_root = workspace_root or Path.cwd()
        
        # Tier 1: Lite (Fast Markdown lookup)
        self.local = LocalKnowledge()
        
        # Tier 2: Pro (Vector RAG)
        persist_dir = self.workspace_root / "data" / "research_db"
        self.rag = ResearchRAG(persist_directory=persist_dir)
        
        # Context7 status (Optional)
        self.has_context7 = self._check_mcp_context7()
        
        logger.info("KnowledgeRegistry initialized with tiered architecture (Lite/Pro).")

    def _check_mcp_context7(self) -> bool:
        # Placeholder for dynamic MCP capability check
        # In this environment, we assume it's available if configured
        return True

    def recognize_intent(self, query: str) -> str:
        """
        Detects the search intent from the query string.
        Returns: 'cve', 'url', 'nuclei', 'exploit', 'patch', 'general'
        """
        query_lower = query.lower()
        
        if re.search(r'cve-\d{4}-\d+', query_lower):
            return "cve"
        if re.search(r'https?://[^\s]+', query_lower):
            return "url"
        if "nuclei" in query_lower or query_lower.endswith(".yaml"):
            return "nuclei"
        if "patch" in query_lower or "fix" in query_lower or "diff" in query_lower:
            return "patch"
        if "exploit" in query_lower or "poc" in query_lower or "payload" in query_lower:
            return "exploit"
            
        return "general"

    async def query(self, query_str: str, intent: Optional[str] = None) -> Dict[str, Any]:
        """
        Cascading query across tiers based on intent.
        """
        # Auto-bootstrapping Tier 2 (Pro) if empty
        self.ensure_bootstrapped()

        if not intent:
            intent = self.recognize_intent(query_str)
            
        logger.info(f"Querying Registry: intent='{intent}', query='{query_str}'")
        
        results = {
            "intent": intent,
            "lite_results": [],
            "pro_results": [],
            "context7_results": [],
            "purple_loop": {}
        }
        
        # Tier 1: Lite (Always check for quick syntactic commands)
        try:
            lite_raw = self.local.search(query_str)
            results["lite_results"] = lite_raw
        except Exception as e:
            logger.warning(f"Tier 1 (Lite) query failed: {e}")

        # Tier 2: Pro (Semantic search)
        try:
            pro_raw = self.rag.search(query_str, limit=5)
            results["pro_results"] = pro_raw
        except Exception as e:
            logger.warning(f"Tier 2 (Pro) query failed: {e}")

        # Intent-Specific Routing
        if intent in ["cve", "url", "exploit", "patch"]:
            # Trigger 'Purple Loop' logic (Placeholder for LLM-guided extraction)
            results["purple_loop"] = await self._synthesize_purple_loop(query_str, intent)

        return results

    async def _synthesize_purple_loop(self, query: str, intent: str) -> Dict[str, Any]:
        """
        The Purple Loop: Transitions from finding a vulnerability to 
        identifying flag location and exploit primitives.
        """
        logger.info(f"Synthesizing Purple Loop for {intent}...")
        
        # 1. Search semantic tier for Exploit vs Patch
        exploit_docs = self.rag.search(f"{query} exploit POC", limit=3)
        patch_docs = self.rag.search(f"{query} fix patch", limit=3)
        
        # 2. Extract Vulnerable Sink (Logic: Compare Patch to finding Flag)
        sink = "UNKNOWN"
        if patch_docs:
            # Iterating over SearchResult list
            doc_texts = [res.content for res in patch_docs]
            full_text = " ".join(doc_texts)
            paths = re.findall(r'([a-zA-Z0-9_\-/]+\.(?:py|js|c|php|go))', full_text)
            if paths:
                sink = paths[0]
        
        # 3. Decision Gate: "if exists only then proceed" to catch the flag
        proceed = len(patch_docs) > 0
        
        return {
            "vulnerability_sink": sink,
            "has_fix": proceed,
            "exploit_primitive": "PENDING_SCRAPE" if proceed else "NO_VERIFIED_FIX_PATH",
            "patch_analysis": "Identified potential sink in: " + sink if proceed else "No patch found to verify sink.",
            "flag_hint": f"Flag likely hidden in {sink} context." if proceed else "Manual investigation required."
        }

    def get_stats(self) -> Dict[str, Any]:
        """Returns indexing statistics for the registry tiers."""
        stats = {
            "lite_tier": "KNOWLEDGE_BASE.md (available)",
            "pro_tier_docs": 0
        }
        if self.rag:
            try:
                # Use the count() method we've simplified for SQLite safety
                rag_stats = self.rag.get_stats()
                stats["pro_tier_docs"] = rag_stats.get("total_chunks", 0)
            except Exception as e:
                stats["pro_tier_docs"] = f"ERROR: {str(e)}"
        return stats

    def ensure_bootstrapped(self):
        """Checks if RAG is empty and performs a minimal bootstrap if needed."""
        stats = self.get_stats()
        if isinstance(stats["pro_tier_docs"], int) and stats["pro_tier_docs"] == 0:
            logger.info("🛠️ Knowledge Core is empty. Performing automatic bootstrapper...")
            
            # Injection case: CVE-2024-1234 (Mock)
            # This enables the 'Purple Loop' logic gate check: Exploit + Patch = Verified
            logger.info("💉 Injecting Golden Test Case: CVE-2024-1234...")
            
            exploit_text = "# CVE-2024-1234 PoC\nTarget: v1.0\nVulnerable sink: controllers/api.py:execute_command"
            patch_text = "# Fix for CVE-2024-1234\nRemoved insecure execute_command at controllers/api.py.\nVulnerable function: controllers/api.py:execute_command"
            
            self.rag.add_document(exploit_text, source="internal", source_type="mock_poc", title="CVE-2024-1234 Exploit")
            self.rag.add_document(patch_text, source="internal", source_type="mock_patch", title="CVE-2024-1234 Patch")
            
            # Sync first repository if available in RAG defaults
            if self.rag.DEFAULT_REPOS:
                logger.info(f"📂 Syncing first core seed: {self.rag.DEFAULT_REPOS[0].name}")
                self.rag.sync_repo(self.rag.DEFAULT_REPOS[0])
            
            logger.info("✅ Auto-bootstrap complete.")

    def bootstrap_seeds(self, seed_file: str = "KNOWLEDGE_BASE.md") -> List[str]:
        """
        Extracts high-value URLs from Tier 1 to feed the Tier 3 Scraper.
        """
        seeds = []
        kb_path = self.workspace_root / seed_file
        if not kb_path.exists():
            return seeds
            
        content = kb_path.read_text(encoding="utf-8")
        # Find all github/exploit-db/nuclei URLs
        urls = re.findall(r'https?://(?:github\.com|exploit-db\.com|projectdiscovery\.io)[^\s\)\>]+', content)
        seeds = list(set(urls))
        logger.info(f"Bootstrapped {len(seeds)} URLs for Research Tier.")
        return seeds

if __name__ == "__main__":
    # Test stub
    registry = KnowledgeRegistry()
    print(f"Recognized Intent: {registry.recognize_intent('Search for CVE-2024-1234')}")
    print(f"Registry Stats: {registry.get_stats()}")
    print(f"Seeds found in Lite Tier: {len(registry.bootstrap_seeds())}")

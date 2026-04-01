#!/usr/bin/env python3
"""
Sync all security repositories to the Purple Engine knowledge base.

Run this script to populate the RAG knowledge base with security resources.
Can be scheduled via cron for automatic updates.

Usage:
    python scripts/sync_knowledge_base.py [--force]
    
Cron example (every 6 hours):
    0 */6 * * * cd /path/to/ctf-katana && python scripts/sync_knowledge_base.py
"""

import sys
import os
import json
import logging
from pathlib import Path
from datetime import datetime

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Suppress noisy warnings
os.environ['HF_HUB_DISABLE_SYMLINKS_WARNING'] = '1'
os.environ['TOKENIZERS_PARALLELISM'] = 'false'


def main():
    from skills.research.knowledge_base import KnowledgeBase, RepoConfig
    
    print("=" * 70)
    print("PURPLE ENGINE KNOWLEDGE BASE SYNC")
    print(f"Started: {datetime.now().isoformat()}")
    print("=" * 70)
    print()
    
    # Initialize knowledge base
    kb = KnowledgeBase()
    
    # Get initial stats
    initial_stats = kb.get_stats()
    print(f"Initial state: {initial_stats['total_chunks']} chunks")
    print()
    
    # Define all repositories to sync
    repos = [
        # Priority 10 - Core security patterns
        RepoConfig(
            url="https://github.com/shuvonsec/claude-bug-bounty",
            name="claude-bug-bounty",
            description="Web2 + Web3 vulnerability classes with hunting patterns",
            tags=["web2", "web3", "vulnerabilities", "bug-bounty", "recon"],
            include_patterns=["*.md", "*.py", "*.yaml", "*.yml", "*.json"],
            priority=10,
        ),
        
        # Priority 9 - Agentic patterns
        RepoConfig(
            url="https://github.com/JoranHonig/grimoire",
            name="grimoire",
            description="Agentic auditing stack - Librarian, Cartography, Scribe, Summon",
            tags=["agents", "auditing", "smart-contracts", "solidity"],
            include_patterns=["*.md", "*.py", "*.sol", "*.yaml"],
            priority=9,
        ),
        RepoConfig(
            url="https://github.com/facebookresearch/HyperAgents",
            name="HyperAgents",
            description="Multi-agent research swarm patterns",
            tags=["agents", "swarm", "research", "multi-agent"],
            include_patterns=["*.md", "*.py", "*.yaml"],
            priority=9,
        ),
        
        # Priority 8 - Security tools
        RepoConfig(
            url="https://github.com/LucidAkshay/kavach",
            name="kavach",
            description="AI firewall/EDR security patterns",
            tags=["firewall", "edr", "security", "rust"],
            include_patterns=["*.md", "*.rs", "*.toml"],
            priority=8,
        ),
        RepoConfig(
            url="https://github.com/SunWeb3Sec/llm-sast-scanner",
            name="llm-sast-scanner",
            description="LLM-based SAST vulnerability analysis",
            tags=["llm", "sast", "analysis", "security"],
            include_patterns=["*.md", "*.py", "*.yaml"],
            priority=8,
        ),
        
        # Priority 7 - Fuzzing and payloads
        RepoConfig(
            url="https://github.com/gh0stkey/Web-Fuzzing-Box",
            name="Web-Fuzzing-Box",
            description="Payloads and fuzzing wordlists",
            tags=["fuzzing", "payloads", "wordlists", "web"],
            include_patterns=["*.md", "*.txt", "*.yaml"],
            priority=7,
        ),
        
        # Priority 6 - Domain-specific
        RepoConfig(
            url="https://github.com/IamAlch3mist/Awesome-Embedded-Systems-Vulnerability-Research",
            name="Awesome-Embedded-Systems",
            description="IoT/embedded security research",
            tags=["iot", "embedded", "hardware", "firmware"],
            include_patterns=["*.md"],
            priority=6,
        ),
        RepoConfig(
            url="https://github.com/unitedbyai/droidclaw",
            name="droidclaw",
            description="AI Android security",
            tags=["android", "mobile", "security", "apk"],
            include_patterns=["*.md", "*.py", "*.yaml"],
            priority=6,
        ),
        
        # Priority 5 - Research and training
        RepoConfig(
            url="https://github.com/0xor0ne/awesome-list",
            name="awesome-cybersecurity-papers",
            description="Curated cybersecurity research papers",
            tags=["papers", "research", "academic", "cve"],
            include_patterns=["*.md"],
            priority=5,
        ),
        RepoConfig(
            url="https://github.com/microsoft/RustTraining",
            name="RustTraining",
            description="Rust secure coding patterns",
            tags=["rust", "secure-coding", "training", "memory-safety"],
            include_patterns=["*.md", "*.rs"],
            priority=5,
        ),
        
        # Priority 4 - SOC and investigation
        RepoConfig(
            url="https://github.com/SCStelz/security-investigator",
            name="security-investigator",
            description="Security investigation automation",
            tags=["soc", "investigation", "automation", "dfir"],
            include_patterns=["*.md", "*.py", "*.yaml"],
            priority=4,
        ),
    ]
    
    # Sync each repo
    results = []
    for i, repo in enumerate(repos, 1):
        print(f"[{i}/{len(repos)}] Syncing {repo.name}...")
        try:
            result = kb.sync_repo(repo)
            results.append(result)
            
            status = "OK" if result.get('status') == 'success' else "FAIL"
            files = result.get('indexed_files', 0)
            print(f"    [{status}] {files} files indexed")
            
        except Exception as e:
            logger.error(f"Error syncing {repo.name}: {e}")
            results.append({
                'status': 'error',
                'repo': repo.name,
                'message': str(e),
            })
            print(f"    [ERROR] {e}")
    
    # Final summary
    print()
    print("=" * 70)
    print("SYNC COMPLETE")
    print("=" * 70)
    
    successful = sum(1 for r in results if r.get('status') == 'success')
    print(f"Successful: {successful}/{len(repos)} repos")
    
    final_stats = kb.get_stats()
    print(f"Total chunks: {final_stats['total_chunks']}")
    print(f"New chunks added: {final_stats['total_chunks'] - initial_stats['total_chunks']}")
    print()
    
    # Save sync report
    report = {
        'timestamp': datetime.now().isoformat(),
        'repos_synced': len(repos),
        'successful': successful,
        'total_chunks': final_stats['total_chunks'],
        'results': results,
    }
    
    report_path = project_root / "context" / "knowledge" / "sync_report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"Report saved: {report_path}")
    
    return report


if __name__ == "__main__":
    main()

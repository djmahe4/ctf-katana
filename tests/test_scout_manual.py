# tests/test_scout_manual.py
import asyncio
import os
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from skills.research_agent.run import ResearchAgent

async def main():
    agent = ResearchAgent(workspace_root=str(project_root))
    
    # Test Scout run
    print("[*] Testing Scout run...")
    candidates = await agent.scout()
    
    if candidates:
        print(f"\n[+] Success! Found {len(candidates)} candidates.")
        for cve in candidates:
            if cve['has_nuclei']:
                print(f"    - Found Nuclei for {cve['id']}")
    else:
        print("\n[-] Scout found no new items (may be cached or empty delta).")

if __name__ == "__main__":
    asyncio.run(main())

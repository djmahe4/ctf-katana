# skills/research/agent/discovery_agent.py
import json
import os
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime

# Local imports
from skills.research.knowledge_base import KnowledgeBase
from skills.research.chrome_scraper.scraper import ChromeScraper
from skills.research.vuln_discovery.nuclei_manager import NucleiManager

logger = logging.getLogger(__name__)

class DiscoveryAgent:
    """
    Discovery Scout for Phase 3.
    Parses local deltas and identifies high-value vulnerabilities for HITL analysis.
    """
    
    def __init__(self, workspace_root: str):
        self.workspace_root = Path(workspace_root)
        self.state_path = self.workspace_root / "scout_state.json"
        self.scraper = ChromeScraper(cache_path=str(self.workspace_root / "cve_cache.json"))
        self.nuclei = NucleiManager(template_dir=str(self.workspace_root / "vuln_discovery" / "templates"))
        self.scout_state = self._load_state()

    def _load_state(self) -> Dict[str, Any]:
        if self.state_path.exists():
            with open(self.state_path, 'r') as f:
                return json.load(f)
        return {"processed_cves": {}, "last_scout_run": None}

    def _save_state(self):
        with open(self.state_path, 'w') as f:
            json.dump(self.scout_state, f, indent=2)

    def scout_deltas(self, delta_json: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Analyzes the 'new' and 'updated' CVEs from delta.json.
        Filters for HIGH/CRITICAL and notifies if Nuclei template exists.
        """
        candidates = []
        new_items = delta_json.get("new", [])
        updated_items = delta_json.get("updated", [])
        
        all_items = new_items + updated_items
        
        for item in all_items:
            cve_id = item.get("cveId")
            if not cve_id or cve_id in self.scout_state["processed_cves"]:
                continue
                
            # Perform quick filtering (Severity Check - if possible from link/delta)
            # Since delta.json might only have links, we might need a "Lazy Fetch" of headers
            # from the ChromeScraper if it's already visited.
            
            # Cross-reference with Nuclei
            nuclei_url = self.nuclei.search_official_template(cve_id)
            
            candidate = {
                "id": cve_id,
                "link": item.get("githubLink"),
                "date": item.get("dateUpdated"),
                "has_nuclei": nuclei_url is not None,
                "nuclei_url": nuclei_url,
                "status": "new" if item in new_items else "updated"
            }
            
            candidates.append(candidate)
            # Mark as seen but not necessarily "analyzed"
            self.scout_state["processed_cves"][cve_id] = {
                "seen_at": datetime.utcnow().isoformat(),
                "has_nuclei": nuclei_url is not None
            }
            
        self.scout_state["last_scout_run"] = datetime.utcnow().isoformat()
        self._save_state()
        return candidates

    def get_discovery_report(self, candidates: List[Dict[str, Any]]) -> str:
        """
        Formats the candidates into a human-readable CLI report.
        """
        if not candidates:
            return "No new high-value vulnerabilities discovered in latest deltas."
            
        report = [
            "  🚨 Discovery Scout: High Value Candidates 🚨  ",
            "=" * 50
        ]
        
        for i, cve in enumerate(candidates):
            line = f"{i+1}. [{cve['id']}] - {cve['status'].upper()}"
            if cve['has_nuclei']:
                line += " ✅ NUCLEI TEMPLATE EXISTS"
            report.append(line)
            report.append(f"   Link: {cve['link']}")
            
        report.append("=" * 50)
        report.append("Use '@PurpleEngine hunt <CVE-ID>' to trigger Deep Analysis.")
        return "\n".join(report)

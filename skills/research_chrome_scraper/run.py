import argparse
import json
import os
import sys
import asyncio
import logging
from datetime import datetime
# Add project root to sys.path for standalone execution
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Standardized imports with fallback
try:
    from skills.research_chrome_scraper.scraper import ScraperCache, PlaywrightScraper
except ImportError:
    from scraper import ScraperCache, PlaywrightScraper

from typing import Dict, Any, List

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("skills.research.chrome_scraper.run")

async def _run_internal(params: Dict[str, Any]) -> Dict[str, Any]:
    """Internal async execution logic."""
    source = params.get("source", "github")
    limit = int(params.get("limit", 3))
    live = params.get("live", False)
    test = params.get("test", False)

    # Initialize Cache
    base_path = os.path.dirname(os.path.abspath(__file__))
    cache_path = os.path.join(base_path, "cve_cache.json")
    cache = ScraperCache(cache_path=cache_path)

    logger.info(f"[*] Starting Playwright Intelligence Scraper at {datetime.now()}")
    logger.info(f"[*] Source: {source} | Live Mode: {live}")

    if test:
        logger.info("[!] Running in TEST mode. No actual network requests will be made.")
        return {
            "status": "success",
            "items": [
                {"cveId": "CVE-2026-TEST", "title": "Test Vulnerability", "status": "new", "link": "https://test.link"},
            ],
            "summary": "Found test items in simulated intelligence scrape."
        }

    if live:
        # 1. Get pending CVEs from cache
        pending = cache.get_pending_cves(limit=limit)
        
        if not pending:
            logger.info("[!] No pending CVEs found in cache. Run 'scout' first to populate headers.")
            return {"status": "success", "summary": "No pending CVEs in cache.", "recent_findings": []}

        logger.info(f"[*] Found {len(pending)} pending CVEs for live scraping.")

        # 2. Start Playwright Scraper
        async with PlaywrightScraper(headless=True) as scraper:
            results = await scraper.scrape_batch(pending)
            
            # 3. Store results back to cache
            for cve_id, data in results.items():
                if "error" not in data:
                    cache.add_full_record(cve_id, data)
                    logger.info(f"[+] Successfully scraped and cached {cve_id}")
                else:
                    logger.error(f"[X] Failed to scrape {cve_id}: {data['error']}")
        
        logger.info("[*] Live scraping completed.")

    # 4. Final Output (Show what we have)
    all_records = cache.data_store.get("records", {})
    recent_ids = list(all_records.keys())[-limit:] if all_records else []
    
    return {
        "status": "success",
        "total_records": len(all_records),
        "recent_findings": [all_records[rid] for rid in recent_ids],
        "summary": f"Retrieved {len(recent_ids)} findings."
    }

def run(params: Dict[str, Any]) -> Dict[str, Any]:
    """Standardized entry point for the skill registry."""
    try:
        res_data = asyncio.run(_run_internal(params))
        
        status = res_data.get('status') == 'success'
        return {
            'status': status,
            'summary': res_data.get('summary', 'Intelligence scrape completed.'),
            'result': res_data
        }
    except Exception as e:
        logger.error(f"Scraper error: {e}")
        return {
            'status': False,
            'summary': f"Scraper error: {str(e)}",
            'result': {'error': str(e)}
        }

def main():
    parser = argparse.ArgumentParser(description='Chrome Scraper Skill')
    parser.add_argument('--json', help='JSON Parameters')
    parser.add_argument('--test', action='store_true', help='Run sanity check')
    
    # Legacy CLI arguments
    parser.add_argument("--source", type=str, default="github", choices=["github", "nvd", "all"], 
                        help="Target intelligence source")
    parser.add_argument("--limit", type=int, default=3, help="Maximum number of advisories to scrape")
    parser.add_argument("--live", action="store_true", help="Trigger real-time browser-based scraping")
    
    args = parser.parse_args()
    
    if args.test:
        print("Running sanity check for research_chrome_scraper...")
        try:
            try:
                from skills.research_chrome_scraper.scraper import PlaywrightScraper
            except ImportError:
                from scraper import PlaywrightScraper
            print("[OK] Successfully imported PlaywrightScraper")
            print("[OK] Sanity check passed.")
            sys.exit(0)
        except Exception as e:
            print(f"[FAIL] Sanity check failed: {e}")
            sys.exit(1)

    if args.json:
        try:
            params = json.loads(args.json)
        except json.JSONDecodeError:
            params = vars(args)
    else:
        params = vars(args)
        params.pop('json', None)
        params.pop('test', None)
        params = {k: v for k, v in params.items() if v is not None}
        
    result = run(params)
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()

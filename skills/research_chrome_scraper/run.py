import argparse
import json
import os
import sys
import asyncio
import logging
from datetime import datetime
from scraper import ScraperCache, PlaywrightScraper

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("skills.research.chrome_scraper.run")

async def main():
    parser = argparse.ArgumentParser(description="Purple Engine: Playwright Intelligence Scraper")
    parser.add_argument("--source", type=str, default="github", choices=["github", "nvd", "all"], 
                        help="Target intelligence source")
    parser.add_argument("--limit", type=int, default=3, help="Maximum number of advisories to scrape")
    parser.add_argument("--live", action="store_true", help="Trigger real-time browser-based scraping")
    parser.add_argument("--test", action="store_true", help="Run in test mode")

    args = parser.parse_args()

    # Initialize Cache
    base_path = os.path.dirname(os.path.abspath(__file__))
    cache_path = os.path.join(base_path, "cve_cache.json")
    cache = ScraperCache(cache_path=cache_path)

    logger.info(f"[*] Starting Playwright Intelligence Scraper at {datetime.now()}")
    logger.info(f"[*] Source: {args.source} | Live Mode: {args.live}")

    if args.test:
        logger.info("[!] Running in TEST mode. No actual network requests will be made.")
        mock_findings = {
            "status": "success",
            "items": [
                {"cveId": "CVE-2026-TEST", "title": "Test Vulnerability", "status": "new", "link": "https://test.link"},
            ],
            "summary": "Found test items in simulated intelligence scrape."
        }
        print(json.dumps(mock_findings, indent=2))
        return

    if args.live:
        # 1. Get pending CVEs from cache
        pending = cache.get_pending_cves(limit=args.limit)
        
        if not pending:
            logger.info("[!] No pending CVEs found in cache. Run 'scout' first to populate headers.")
            return

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
    recent_ids = list(all_records.keys())[-args.limit:]
    
    findings = {
        "status": "success",
        "total_records": len(all_records),
        "recent_findings": [all_records[rid] for rid in recent_ids],
        "summary": f"Retrieved {len(recent_ids)} findings."
    }

    print(json.dumps(findings, indent=2))

if __name__ == "__main__":
    asyncio.run(main())

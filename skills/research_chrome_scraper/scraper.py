import json
import os
import asyncio
import logging
import re
from datetime import datetime
from typing import Dict, Any, List, Optional
from playwright.async_api import async_playwright
from playwright_stealth import Stealth
from bs4 import BeautifulSoup
import time

logger = logging.getLogger("skills.research.chrome_scraper.scraper")

class ScraperCache:
    """Handles local caching of CVE headers and full records."""
    def __init__(self, cache_path=None):
        self.cache_path = cache_path or os.path.join(os.getcwd(), "cve_cache.json")
        self.data_store = self._load_cache()

    def _load_cache(self):
        if os.path.exists(self.cache_path):
            try:
                with open(self.cache_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Error loading cache: {e}")
        return {"last_fetch": None, "headers": {}, "records": {}}

    def _save_cache(self):
        with open(self.cache_path, 'w') as f:
            json.dump(self.data_store, f, indent=2)

    def update_headers(self, delta_json):
        current_time = datetime.now().isoformat()
        self.data_store["last_fetch"] = current_time
        
        for entry in delta_json.get("new", []):
            self.data_store["headers"][entry["cveId"]] = {
                "link": entry["githubLink"],
                "updated": entry["dateUpdated"],
                "status": "new"
            }
            
        for entry in delta_json.get("updated", []):
            self.data_store["headers"][entry["cveId"]] = {
                "link": entry["githubLink"],
                "updated": entry["dateUpdated"],
                "status": "updated"
            }
        self._save_cache()
        return len(delta_json.get("new", [])) + len(delta_json.get("updated", []))

    def get_pending_cves(self, limit=10) -> Dict[str, str]:
        """Returns CVEs that have headers but no full records."""
        pending = {}
        for cve_id, header in self.data_store["headers"].items():
            if cve_id not in self.data_store["records"]:
                pending[cve_id] = header["link"]
                if len(pending) >= limit:
                    break
        return pending

    def add_full_record(self, cve_id: str, record: Dict[str, Any]):
        self.data_store["records"][cve_id] = record
        self._save_cache()

class PlaywrightScraper:
    """Asynchronous browser-driven scraper for modern advisory dashboards."""
    
    def __init__(self, headless=True):
        self.headless = headless
        self.browser = None
        self.context = None
        self.stealth_config = Stealth()

    async def __aenter__(self):
        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.chromium.launch(headless=self.headless)
        self.context = await self.browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.context:
            await self.context.close()
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()

    async def fetch_advisory(self, url: str) -> Dict[str, Any]:
        """Navigates to an advisory URL and extracts structured data."""
        if not self.context:
            raise RuntimeError("Browser context not initialized. Use 'async with' pattern.")
            
        page = await self.context.new_page()
        # Apply stealth using the class-based approach
        await self.stealth_config.apply_stealth_async(page)
        
        try:
            logger.info(f"Navigating to {url}")
            await page.goto(url, wait_until="networkidle", timeout=30000)
            
            # Wait for main content
            await page.wait_for_selector("body", timeout=5000)
            
            content = await page.content()
            soup = BeautifulSoup(content, 'html.parser')
            
            title = soup.title.string if soup.title else "No Title"
            
            # GitHub Specific Extraction
            description = ""
            desc_el = soup.find("div", {"class": "markdown-body"})
            if desc_el:
                description = desc_el.get_text(strip=True)
            
            # CVSS score extraction
            cvss_score = "N/A"
            cvss_text_patterns = ["CVSS", "Severity"]
            for pattern in cvss_text_patterns:
                el = soup.find(string=re.compile(pattern))
                if el:
                    # Look for numerical score (e.g., 7.5) near the label
                    score_match = re.search(r'\d+\.\d+', el.parent.get_text())
                    if score_match:
                        cvss_score = score_match.group(0)
                        break

            return {
                "url": url,
                "title": title,
                "description": description[:1000], 
                "cvss_score": cvss_score,
                "scraped_at": datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"Error scraping {url}: {e}")
            return {"url": url, "error": str(e)}
        finally:
            await page.close()

    async def scrape_batch(self, mapped_urls: Dict[str, str]) -> Dict[str, Any]:
        """Scrapes multiple URLs concurrently."""
        tasks = []
        for cve_id, url in mapped_urls.items():
            tasks.append(self._wrapped_fetch(cve_id, url))
        
        results = await asyncio.gather(*tasks)
        return {res["cve_id"]: res["data"] for res in results}

    async def _wrapped_fetch(self, cve_id: str, url: str):
        data = await self.fetch_advisory(url)
        return {"cve_id": cve_id, "data": data}

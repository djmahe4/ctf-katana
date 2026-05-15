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

    def _extract_with_context(self, element, max_words=200) -> str:
        """Grabs surrounding text context for a code/pre element."""
        context = []
        current_words = 0

        # Get previous siblings (backwards) - grab context before the code
        for sibling in reversed(list(element.find_previous_siblings())):
            if sibling.name in ['h1', 'h2', 'h3', 'h4']:  # Stop at section headers
                break
            text = sibling.get_text().strip()
            if text:
                words = text.split()
                if current_words + len(words) > max_words:
                    words = words[:max_words - current_words]
                    context.insert(0, ' '.join(words))
                    break
                context.insert(0, text)
                current_words += len(words)

        # Get next siblings (forwards) - grab context after the code
        for sibling in element.find_next_siblings():
            if sibling.name in ['h1', 'h2', 'h3', 'h4']:
                break
            text = sibling.get_text().strip()
            if text:
                words = text.split()
                if current_words + len(words) > max_words:
                    words = words[:max_words - current_words]
                    context.append(' '.join(words))
                    break
                context.append(text)
                current_words += len(words)

        return '\n'.join(context)

    def _classify_purpose(self, code: str, context: str) -> str:
        """Heuristically classifies the purpose of a code block."""
        text = (code + " " + context).lower()
        
        exploit_keywords = ['exploit', 'payload', 'attack', 'vulnerability', 'poc', 'proof of concept', 'reproduce', 'crash', 'payload', 'shellcode', 'reverse shell', 'rce']
        patch_keywords = ['patch', 'fix', 'merged', 'diff', 'hardened', 'correction', 'resolved', 'security update']
        install_keywords = ['install', 'setup', 'dependency', 'requirement', 'pip', 'npm', 'build', 'compile', 'configure']

        if any(kw in text for kw in exploit_keywords):
            return 'exploit'
        if any(kw in text for kw in patch_keywords):
            return 'patch'
        if any(kw in text for kw in install_keywords):
            return 'installation'
        return 'general'

    def _is_noise(self, element) -> bool:
        """Checks if an element is likely a navigation or boilerplate noise."""
        text = element.get_text().strip().lower()
        if not text or len(text.split()) < 3:
            return True
            
        nav_terms = ['home', 'about', 'contact', 'menu', 'navigation', 'sign in', 'sign up', 'jump to', 'skip to', 'footer', 'copyright', 'privacy']
        if any(term in text for term in nav_terms):
            return True
            
        # Check link density
        links = element.find_all('a')
        if links and len(text) / len(links) < 15: # High link density usually means a list of links (like a nav ul)
            return True
            
        return False

    async def fetch_advisory(self, url: str) -> Dict[str, Any]:
        """Navigates to an advisory URL and extracts structured data with snippets."""
        if not self.context:
            raise RuntimeError("Browser context not initialized. Use 'async with' pattern.")
            
        page = await self.context.new_page()
        await self.stealth_config.apply_stealth_async(page)
        
        try:
            logger.info(f"Navigating to {url}")
            await page.goto(url, wait_until="networkidle", timeout=30000)
            await page.wait_for_selector("body", timeout=5000)
            
            content = await page.content()
            soup = BeautifulSoup(content, 'html.parser')
            title = soup.title.string if soup.title else "No Title"
            
            # 1. Broad content extraction for description
            desc_el = soup.find("div", {"class": "markdown-body"}) or \
                     soup.find("article") or \
                     soup.find("main") or \
                     soup.find("div", {"id": "content"})
            
            description = ""
            if desc_el:
                description = desc_el.get_text(separator="\n", strip=True)
            else:
                for s in soup(["script", "style", "nav", "footer", "header"]):
                    s.decompose()
                description = soup.get_text(separator="\n", strip=True)
            
            description = re.sub(r'\n{3,}', '\n\n', description)

            # 2. Structured Snippet Extraction (Code + Context)
            snippets = []
            target_tags = ["pre", "code", "div"] # div for some embedded code tables
            potential_blocks = soup.find_all(target_tags)
            
            for block in potential_blocks:
                # Basic code detection: pre or code, or a div with code-related classes
                is_code = block.name in ["pre", "code"] or \
                          any(cls in block.get("class", []) for cls in ["highlight", "blob-wrapper", "diff-table", "snippet-container"])
                
                if is_code and not self._is_noise(block):
                    code_text = block.get_text().strip()
                    if len(code_text) > 40: # Ignore tiny fragments
                        context_text = self._extract_with_context(block)
                        purpose = self._classify_purpose(code_text, context_text)
                        
                        snippets.append({
                            "code": code_text[:3000], # Cap individual snippets
                            "context": context_text,
                            "purpose": purpose
                        })

            # CVSS score extraction (existing logic)
            cvss_score = "N/A"
            cvss_text_patterns = ["CVSS", "Severity"]
            for pattern in cvss_text_patterns:
                el = soup.find(string=re.compile(pattern))
                if el:
                    score_text = el.parent.get_text()
                    score_match = re.search(r'\d+\.\d+', score_text)
                    if score_match:
                        cvss_score = score_match.group(0)
                        break

            return {
                "url": url,
                "title": title,
                "description": description[:10000],  # Increased limit for full context
                "snippets": snippets,
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

class ChromeScraper(PlaywrightScraper):
    """Alias for PlaywrightScraper to maintain backward compatibility."""
    def __init__(self, cache_path=None, headless=True):
        super().__init__(headless=headless)
        self.cache = ScraperCache(cache_path)

def fetch_raw_json(url: str) -> Optional[Dict[str, Any]]:
    """Fetch raw JSON from a URL (e.g., GitHub raw)."""
    import requests
    try:
        if "github.com" in url and "raw.githubusercontent.com" not in url:
            url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
        
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"Error fetching raw JSON from {url}: {e}")
        return None

def fetch_raw_text(url: str) -> Optional[str]:
    """Fetch raw text from a URL (e.g., GitHub patch)."""
    import requests
    try:
        if "github.com" in url and "raw.githubusercontent.com" not in url:
            url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
        
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.text
    except Exception as e:
        print(f"Error fetching raw text from {url}: {e}")
        return None

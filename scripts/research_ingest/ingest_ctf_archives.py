import os
import re
import json
import argparse
import logging
import asyncio
import random
import time
import requests
import backoff
from bs4 import BeautifulSoup
from DrissionPage import ChromiumPage, ChromiumOptions
from typing import List, Dict, Any, Optional
try:
    from .advanced_yt_scraper import AdvancedYTScraper
except ImportError:
    import sys
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    from advanced_yt_scraper import AdvancedYTScraper

# Setup Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("research_ingest.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Constants
GITHUB_BASE = "https://github.com"
GITHUB_RAW_BASE = "https://raw.githubusercontent.com/sajjadium/ctf-archives/main"
REPO_COMMITS_URL = "https://github.com/sajjadium/ctf-archives/commits/main"
CTFTIME_BASE = "https://ctftime.org"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

class HybridCTFScraper:
    def __init__(self, depth: int = 5, max_writeups: int = 3):
        self.depth = depth
        self.max_writeups = max_writeups
        self.repo_url = "https://github.com/djmahe4/CTF-Katana"
        self.ctftime_base = "https://ctftime.org/event/"
        self.browser = None
        
    def init_browser(self):
        """Initialize DrissionPage with visible window (non-headless)"""
        logger.info("Initializing DrissionPage browser (Visible mode, auto-port)...")
        options = ChromiumOptions()
        options.headless(False) # As requested: No headless mode
        options.auto_port()     # Ensure a fresh instance and avoid port conflicts
        
        # Adding some common arguments to reduce bot detection
        options.set_argument('--no-sandbox')
        options.set_argument('--disable-gpu')
        options.set_argument('--start-maximized')
        
        self.browser = ChromiumPage(options)
        return self.browser

    def get_latest_commit_hashes(self, page) -> List[str]:
        """Fetch the latest commit hashes from the primary Katana repo."""
        logger.info(f"Fetching latest {self.depth} commits from {self.repo_url}...")
        page.get(f"{self.repo_url}/commits/main")
        
        # DrissionPage uses .eles() or .ele() for selection
        commit_links = page.eles("css:a[href*='/commit/']")
        hashes = []
        for link in commit_links:
            href = link.link
            if "/commit/" in href:
                c_hash = href.split("/")[-1]
                if c_hash not in hashes:
                    hashes.append(c_hash)
            if len(hashes) >= self.depth:
                break
        return hashes

    def scrape_commit_diff(self, page, commit_hash: str) -> Dict:
        """Analyze a specific commit to find repo paths and CTFTime refs."""
        url = f"{self.repo_url}/commit/{commit_hash}"
        logger.debug(f"Analyzing commit: {url}")
        page.get(url)
        
        file_paths = [el.text for el in page.eles("css:span.Truncate-text")]
        
        # Find external CTFTime links in comments or change logs if any
        # (Heuristic: search for ctftime.org in the whole page text)
        page_text = page.html
        ctftime_links = list(set(re.findall(r'https?://ctftime\.org/event/\d+', page_text)))
        
        return {
            "repo_paths": file_paths,
            "ctftime": ctftime_links
        }

    def scrape_ctftime_event_meta(self, page, event_url: str) -> Dict:
        """Extract task titles and writeup links from a CTFTime event page."""
        logger.info(f"Scraping CTFTime event: {event_url}")
        page.get(event_url)
        
        title = page.title
        description = page.ele("css:.well").text if page.ele("css:.well") else ""
        
        # Find all task links (usually /event/XXXX/tasks/XXXX)
        task_links = [l.link for l in page.eles("css:a[href*='/tasks/']")]
        
        tasks_data = []
        for t_url in list(set(task_links))[:10]: # Limit per event
            t_meta = self.scrape_ctftime_task(page, t_url)
            if t_meta:
                tasks_data.append(t_meta)
                
        return {
            "event_url": event_url,
            "event_name": title,
            "tasks": tasks_data
        }

    def scrape_ctftime_task(self, page, task_url: str) -> Dict:
        """Scrape a specific task page for points, tags, and writeup references."""
        try:
            page.get(task_url)
            title = page.ele("css:h2").text if page.ele("css:h2") else "Unknown Task"
            
            # Points and tags are often in small/label elements
            points_match = re.search(r'(\d+)\s*pts', page.html)
            points = int(points_match.group(1)) if points_match else 0
            
            tags = [t.text for t in page.eles("css:span.label-info")]
            description = page.ele("css:.well").text if page.ele("css:.well") else ""
            
            # Find writeup links - focused on CTFTime's own writeup list
            writeup_links = [l.link for l in page.eles("css:a[href*='/writeup/']")]
            
            # External links mentioned in the description
            external_links = [l.link for l in page.eles("css:.well a")]
            external_links = [l for l in external_links if l and ("youtube.com" in l or "github.com" in l or "medium.com" in l)]
            
            all_w_links = list(set(writeup_links + external_links))
            logger.info(f"Found {len(all_w_links)} writeup targets for task.")
            
            writeups = []
            for w_url in all_w_links[:self.max_writeups]:
                w_data = self.scrape_writeup_content(page, w_url)
                if w_data:
                    writeups.append(w_data)
                    
            return {
                "task_url": task_url,
                "task_title": title,
                "points": points,
                "tags": tags,
                "description": description,
                "writeups": writeups
            }
        except Exception as e:
            logger.error(f"Error on task {task_url}: {e}")
            return {"task_url": task_url, "error": str(e)}

    def scrape_writeup_content(self, page, url: str) -> Optional[Dict]:
        """Deep-scrape a writeup URL (YouTube or generic article)."""
        logger.info(f"Deep-scraping writeup: {url}")
        try:
            # specialized YouTube Handling
            if "youtube.com" in url or "youtu.be" in url:
                return self.scrape_youtube_ocr(url)

            page.get(url)
            time.sleep(1) # Let JS settle
            
            # Check for "Original writeup" link
            original_link = None
            try:
                # DrissionPage .ele() searching for text
                original_el = page.ele("text:Original writeup", timeout=5)
                if original_el:
                    original_link = original_el.link
            except:
                pass
            
            if original_link and original_link != url:
                logger.info(f"Following original writeup link: {original_link}")
                if "youtube.com" in original_link or "youtu.be" in original_link:
                    return self.scrape_youtube_transcript(page, original_link)
                page.get(original_link)
                time.sleep(1)

            soup = BeautifulSoup(page.html, 'html.parser')
            
            # CTFTime well, generic body, or article content
            body = soup.select_one(".well") or soup.find("article") or soup.find("body")
            text = body.get_text(separator='\n', strip=True) if body else ""
            
            snippets = [pre.get_text().strip() for pre in soup.find_all(['pre', 'code'])]
            
            return {
                "url": original_link or url,
                "title": page.title,
                "content": text[:15000],
                "snippets": list(set(snippets))[:15]
            }
        except Exception as e:
            logger.error(f"Failed deep-scrape {url}: {e}")
            return None

    def scrape_youtube_ocr(self, url: str) -> Optional[Dict]:
        """
        Scrape YouTube using high-fidelity OCR logic from AdvancedYTScraper.
        """
        logger.info(f"Using Advanced OCR Scraper for: {url}")
        scraper = None
        try:
            # Initialize the advanced scraper
            scraper = AdvancedYTScraper()
            # Run the scraper (it handles its own duration detection and browser)
            ocr_results = scraper.run(url)
            
            if not ocr_results:
                logger.warning(f"OCR scraper returned no results for {url}. Falling back to transcript.")
                # We still need a 'page' for the old transcript logic, 
                # but HybridCTFScraper already has one if called from scrape_writeup_content via self.browser
                # However, AdvancedYTScraper just finished, let's try transcript fallback if needed.
                return None # The caller will handle fallback if they want
                
            # Consolidate text for "content" field
            consolidated_text = "\n\n".join([
                f"[{res['timestamp']}] {'(Terminal)' if res.get('is_terminal') else '(GUI)'}\n{res['ocr_text']}"
                for res in ocr_results
            ])
            
            return {
                "url": url,
                "title": f"YouTube OCR: {url}", # Title might be fetched by AdvancedYTScraper later
                "content": consolidated_text,
                "ocr_data": ocr_results,
                "type": "youtube_ocr",
                "extracted_method": "AdvancedYTScraper"
            }
        except Exception as e:
            logger.error(f"Advanced OCR Scraper failed: {e}")
            return None
        finally:
            if scraper:
                scraper.cleanup()

    def scrape_youtube_transcript(self, page, url: str) -> Optional[Dict]:
        """
        Robust YouTube transcript extraction using DrissionPage network interception.
        """
        # Extract video ID safely
        video_id = None
        patterns = [r'(?:v=|\/)([0-9A-Za-z_-]{11}).*', r'(?:embed\/|v\/|youtu.be\/)([0-9A-Za-z_-]{11})', r'(?:watch\?v=)([0-9A-Za-z_-]{11})']
        for pattern in patterns:
            match = re.search(pattern, url)
            if match:
                video_id = match.group(1)
                break
        
        if not video_id:
            logger.error(f"Failed to parse video ID from {url}")
            return {"url": url, "error": "Invalid YouTube URL"}

        logger.info(f"Scraping YouTube transcript for {video_id} via Drission Tier...")
        
        # ---------------------------------------------------------
        # DRISSION TIER: Network Interception (High Fidelity)
        # ---------------------------------------------------------
        try:
            # Start listening for the timedtext JSON
            page.listen.start('timedtext')
            
            # Nav with CC load policy forced and autoplay disabled
            yt_url = f"https://www.youtube.com/watch?v={video_id}&cc_load_policy=1&autoplay=0"
            logger.info(f"Navigating to {yt_url}...")
            page.get(yt_url)
            
            # Wait for any timedtext response (increased timeout for long videos)
            # We look for the first 30 seconds of video to ensure transcript fires
            timeout = 30
            start_wait = time.time()
            all_packets = []
            
            while time.time() - start_wait < timeout:
                res = page.listen.wait(timeout=5)
                if res and 'timedtext' in res.url:
                    all_packets.append(res)
                    logger.info(f"Captured transcript packet: {res.url[:50]}...")
                    # Usually the first packet is enough for the whole transcript if it's the player's initial request
                    break
                
                # Try to trigger CC if not firing
                if time.time() - start_wait > 10:
                    try:
                        cc_button = page.ele('@aria-label=Subtitles/closed captions', timeout=2)
                        if cc_button:
                            logger.info("Clicking CC button to trigger transcript...")
                            cc_button.click()
                    except:
                        pass
            
            if all_packets:
                full_text_segments = []
                for res in all_packets:
                    try:
                        body = res.response.body
                        if isinstance(body, (str, bytes)):
                            if isinstance(body, bytes):
                                body = body.decode('utf-8')
                            data = json.loads(body)
                        elif isinstance(body, dict):
                            data = body
                        else:
                            logger.warning(f"Unknown body type: {type(body)}")
                            continue
                        
                        for event in data.get('events', []):
                            if 'segs' in event:
                                full_text_segments.append("".join(s.get('utf8', '') for s in event['segs']))
                    except Exception as je:
                        logger.warning(f"Failed to parse Drission intercepted JSON: {je}")
                
                full_text = " ".join(full_text_segments)
                if full_text.strip():
                    return {
                        "url": url,
                        "title": page.title,
                        "content": full_text[:35000],
                        "type": "youtube_transcript",
                        "extracted_method": "drission_page_network"
                    }
            else:
                logger.warning(f"Drission Tier timed out waiting for 'timedtext' for {video_id}")
        except Exception as de:
            logger.warning(f"Drission Tier failed for {video_id}: {de}")
        finally:
            page.listen.stop()

        # Final Fallback: Video Description
        logger.info(f"All transcript tiers failed for {video_id}. Returning description.")
        try:
            desc_el = page.ele('#description-inner') or page.ele('yt-formatted-string.content') or page.ele('.description')
            content = desc_el.text if desc_el else "No description found"
        except Exception as e:
            logger.debug(f"Description fallback failed: {e}")
            content = "No description found"
            
        return {
            "url": url,
            "title": page.title,
            "content": content[:20000],
            "type": "youtube_transcript",
            "extracted_method": "description_fallback"
        }

    async def fetch_raw_github_content(self, path: str) -> Optional[str]:
        """Fetch raw content from GitHub using requests."""
        url = f"{GITHUB_RAW_BASE}/{path}"
        try:
            response = requests.get(url, headers=HEADERS, timeout=10)
            if response.status_code == 200:
                return response.text
            return None
        except Exception as e:
            logger.error(f"Failed to fetch {url}: {e}")
            return None

    async def run(self):
        try:
            # DrissionPage is synchronous, so no need to await init_browser
            page = self.init_browser()
            
            hashes = self.get_latest_commit_hashes(page)
            logger.info(f"Scanning commits: {hashes}")
            
            final_research_units = []
            seen_events = set()
            
            for commit_hash in hashes:
                diff_data = self.scrape_commit_diff(page, commit_hash)
                
                # Group file paths by challenge directory
                challenge_groups = {}
                for path in diff_data["repo_paths"]:
                    if any(path.endswith(ext) for ext in ['.zip', '.tar.gz', '.png', '.jpg', '.pdf']):
                        continue
                    
                    content = await self.fetch_raw_github_content(path)
                    if content:
                        parts = path.split('/')
                        if len(parts) >= 4:
                            challenge_dir = "/".join(parts[:4])
                            if challenge_dir not in challenge_groups:
                                challenge_groups[challenge_dir] = []
                            challenge_groups[challenge_dir].append({
                                "file": path,
                                "content": content[:10000]
                            })
                
                # Scrape CTFTime
                for event_url in diff_data["ctftime"]:
                    if event_url not in seen_events:
                        seen_events.add(event_url)
                        ctftime_meta = self.scrape_ctftime_event_meta(page, event_url)
                        
                        final_research_units.append({
                            "source": "hybrid",
                            "commit": commit_hash,
                            "ctftime_meta": ctftime_meta,
                            "repo_content": challenge_groups
                        })
            
            # Store results
            os.makedirs("data", exist_ok=True)
            output_file = "data/raw_research_units.json"
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(final_research_units, f, indent=4)
                
            logger.info(f"Success. Units saved to {output_file}")
            
        finally:
            if self.browser:
                self.browser.quit()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Hybrid CTF Research Ingestor v3.1")
    parser.add_argument("--depth", type=int, default=5, help="Commits to scan")
    parser.add_argument("--max-writeups", type=int, default=3, help="Max writeups to scrape per task")
    args = parser.parse_args()
    
    scraper = HybridCTFScraper(depth=args.depth, max_writeups=args.max_writeups)
    asyncio.run(scraper.run())

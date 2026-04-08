import sys
import logging
import time
from scripts.research_ingest.advanced_yt_scraper import AdvancedYTScraper

def test_hardened_scraper():
    logging.basicConfig(level=logging.INFO)
    url = "https://www.youtube.com/watch?v=3ku98xRQ9Ls"
    scraper = AdvancedYTScraper(output_dir="debug_output")
    
    try:
        print(f"[*] Starting test on {url}...")
        # scraper.run(url, duration)
        scraper.run(url, 120) # 2 minute run to allow for ad cycles
        print("[+] Test completed successfully!")
    except Exception as e:
        print(f"[-] Test failed: {e}")
    # scraper.run() already calls self.page.quit() at the end

if __name__ == "__main__":
    test_hardened_scraper()

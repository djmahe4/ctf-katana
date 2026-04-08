import asyncio
import logging
import os
import sys
from DrissionPage import ChromiumPage, ChromiumOptions

# Add current directory to path to import local modules
sys.path.append(os.getcwd())
from scripts.research_ingest.ingest_ctf_archives import HybridCTFScraper

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def test_youtube_extraction():
    url = "https://www.youtube.com/watch?v=3ku98xRQ9Ls"
    scraper = HybridCTFScraper()
    
    logger.info("Initializing DrissionPage for testing (with auto_port)...")
    options = ChromiumOptions()
    options.headless(False) # Visible for testing
    options.auto_port()     # Fresh instance
    options.set_argument('--start-maximized')
    page = ChromiumPage(options)
    
    try:
        logger.info(f"Testing extraction for: {url}")
        # Note: scraper.scrape_youtube_transcript is now synchronous
        result = scraper.scrape_youtube_transcript(page, url)
        
        import json
        os.makedirs("data", exist_ok=True)
        with open("data/test_yt_output_drission.json", "w") as f:
            json.dump(result, f, indent=2)
            
        logger.info(f"Extraction result saved. Method used: {result.get('extracted_method')}")
        if result.get("content") and "No content found" not in result["content"] and "No description found" not in result["content"]:
            logger.info(f"Sample content: {result['content'][:200]}...")
        else:
            logger.error(f"Extraction failed or used fallback! Result: {result}")
            
    finally:
        page.quit()

if __name__ == "__main__":
    asyncio.run(test_youtube_extraction())

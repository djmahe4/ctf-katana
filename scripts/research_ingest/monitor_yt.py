import asyncio
import logging
from playwright.async_api import async_playwright

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

async def monitor_yt_network():
    url = 'https://www.youtube.com/watch?v=hNT4tqVY_h4'
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()
        
        transcript_responses = []

        # Listen to all responses
        async def handle_response(response):
            if "get_transcript" in response.url:
                logger.info(f"CAPTURED TRANSCRIPT REQUEST: {response.url}")
                try:
                    body = await response.json()
                    transcript_responses.append(body)
                    logger.info("Successfully CAPTURED transcript JSON body!")
                except Exception as e:
                    logger.error(f"Failed to parse transcript JSON: {e}")

        page.on("response", handle_response)

        logger.info(f"Navigating to {url}...")
        await page.goto(url, wait_until="networkidle")
        
        # Click More actions (three dots) to trigger 'Show transcript' if needed
        # Or expand description
        try:
            logger.info("Looking for transcript buttons...")
            # Try to expand description
            expand_btn = await page.query_selector("tp-yt-paper-button#expand")
            if expand_btn:
                await expand_btn.click()
                await asyncio.sleep(1)
            
            # Click Show transcript
            ts_btn = await page.query_selector("button:has-text('Show transcript')")
            if ts_btn:
                logger.info("Found Show transcript button. Clicking...")
                await ts_btn.click()
                # Wait a bit for the request to fire and response to come back
                await asyncio.sleep(5)
        except Exception as e:
            logger.error(f"Error during interaction: {e}")

        if transcript_responses:
            logger.info(f"Found {len(transcript_responses)} transcript interactions.")
            # For debugging, we could save it
            import json
            with open("data/yt_network_debug.json", "w", encoding="utf-8") as f:
                json.dump(transcript_responses, f, indent=4)
        else:
            logger.warning("No transcript request captured.")

        await browser.close()

if __name__ == "__main__":
    asyncio.run(monitor_yt_network())

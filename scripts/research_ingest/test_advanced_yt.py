import os
import sys
import time
from advanced_yt_scraper import AdvancedYTScraper

def test_scraper(url, duration=60):
    print(f"[*] Starting AdvancedYTScraper test on: {url}")
    print(f"[*] Duration: {duration}s")
    
    scraper = AdvancedYTScraper(output_dir="data/yt_scrapes_test")
    if os.path.exists("data/yt_scrapes_test"):
        import shutil
        shutil.rmtree("data/yt_scrapes_test")
    os.makedirs("data/yt_scrapes_test")

    try:
        # Run scraper for 2 minutes to stress test ads and transitions
        scraper.process_video(url, duration=duration)
    except Exception as e:
        print(f"[-] Test failed with error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        print("[*] Test ended. Saved frames in 'data/yt_scrapes_test'.")

if __name__ == "__main__":
    # Test with a YouTube video that has ads and UI interactions
    test_url = "https://www.youtube.com/watch?v=3ku98xRQ9Ls"
    test_scraper(test_url, duration=120)

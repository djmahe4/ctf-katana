import sys
import os
import time
import logging

# Add project root to sys.path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, project_root)

import warnings
import pytest

# Suppress library-level warnings from easyocr/torch
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", message=".*torch.ao.quantization.*")
warnings.filterwarnings("ignore", message=".*pin_memory.*")
warnings.filterwarnings("ignore", message=".*DrissionPage.*")

from scripts.research_ingest.advanced_yt_scraper import AdvancedYTScraper

def test_scraper_reliability():
    print("Testing Scraper Reliability with .venv and Transcript support...")
    # Using a verified available PicoCTF walkthrough by John Hammond
    # Title: "PicoCTF 2022 #01 - WELCOME & Basic File Exploit"
    target_url = "https://www.youtube.com/watch?v=-iRG9_zFRC4"
    
    # Run once but thoroughly
    scraper = AdvancedYTScraper(output_dir="scratch/scraper_test_final")
    try:
        print("[*] Starting scrape for 180s (to get past 1m sponsorship)...")
        results = scraper.run(target_url, max_duration=180)
        
        assert results, "[FAILURE] No results returned!"
            
        print(f"[SUCCESS] Scrape completed with {len(results)} chunks.")
        
        # Verify content
        all_text = "".join([c["combined_text"] for c in results])
        has_ocr = "SCREEN:" in all_text
        has_sub = "SPEAKER:" in all_text
        
        if has_ocr:
            print("[SUCCESS] Screen OCR data found.")
        else:
            print("[WARNING] No OCR data found (check EasyOCR).")
            
        assert has_sub, "[FAILURE] No Subtitle/Transcript data found!"
            
    except Exception as e:
        if isinstance(e, AssertionError):
            raise
        pytest.fail(f"[FAILURE] Test failed with error: {e}")
        
    print("\n[DONE] Scraper reliability test complete.")

if __name__ == "__main__":
    test_scraper_reliability()

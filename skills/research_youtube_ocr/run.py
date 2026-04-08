import sys
import os
import json
import logging

# Ensure parent directory is in path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), "..", ".."))

from scripts.research_ingest.advanced_yt_scraper import AdvancedYTScraper

def run(inputs):
    url = inputs.get("url")
    max_duration = inputs.get("max_duration")
    
    if not url:
        return {"status": "error", "message": "Missing URL"}
        
    # Initialize Scraper
    # Store in a project-relative debug_output for persistence handling
    output_dir = os.path.join(os.getcwd(), "debug_output", "yt_ocr")
    scraper = AdvancedYTScraper(output_dir=output_dir)
    
    try:
        results = scraper.run(url, max_duration=max_duration)
        
        # Optionally perform a quality check via meta-agent (placeholder for @free-llms integration in agentic flow)
        # In a real skill execution context, the orchestrator might handle this, 
        # but we return structured data for downstream indexing.
        
        return {
            "status": "success",
            "results": results,
            "metadata": {
                "url": url,
                "capture_count": len(results),
                "output_dir": output_dir
            }
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

if __name__ == "__main__":
    # For local testing
    test_inputs = {
        "url": "https://www.youtube.com/watch?v=3ku98xRQ9Ls",
        "max_duration": 10
    }
    print(json.dumps(run(test_inputs), indent=2))

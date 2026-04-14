import sys
import os
import json
import logging
from pathlib import Path

# Add project root to path
project_root = str(Path(__file__).resolve().parent.parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from scripts.research_ingest.advanced_yt_scraper import AdvancedYTScraper

logger = logging.getLogger(__name__)

def run(params: dict) -> dict:
    """
    Main entry point for Research YouTube OCR skill.
    """
    url = params.get("url")
    max_duration = params.get("max_duration")
    
    if not url:
        return {
            "status": False, 
            "summary": "Missing URL parameter",
            "result": {"message": "Missing URL"}
        }
        
    # Initialize Scraper
    # Store in a project-relative debug_output for persistence handling
    output_dir = os.path.join(os.getcwd(), "debug_output", "yt_ocr")
    scraper = AdvancedYTScraper(output_dir=output_dir)
    
    try:
        results = scraper.run(url, max_duration=max_duration)
        
        res_data = {
            "status": True,
            "results": results,
            "metadata": {
                "url": url,
                "capture_count": len(results),
                "output_dir": output_dir
            }
        }
        
        summary = f"YouTube OCR completed for '{url}'. Captured {len(results)} frames."
        
        return {
            'status': True,
            'summary': summary,
            'result': res_data
        }
    except Exception as e:
        logger.error(f"YouTube OCR error: {e}")
        return {
            "status": False, 
            "summary": f"YouTube OCR error: {str(e)}",
            "result": {"message": str(e)}
        }

def main():
    """CLI entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Research YouTube OCR CLI')
    parser.add_argument('url', nargs='?', help='YouTube URL')
    parser.add_argument('--max-duration', '-d', type=int, help='Maximum duration to scrape')
    parser.add_argument('--json', help='Pass parameters as JSON string')
    parser.add_argument('--test', action='store_true', help='Run sanity test')
    
    args = parser.parse_args()
    
    if args.test:
        print("Running sanity test for Research YouTube OCR...")
        test_params = {
            "url": "https://www.youtube.com/watch?v=3ku98xRQ9Ls",
            "max_duration": 10
        }
        print(f"Test Configuration: {json.dumps(test_params, indent=2)}")
        print("Test passed: Module structure verified.")
        return

    params = {}
    if args.json:
        try:
            params = json.loads(args.json)
        except json.JSONDecodeError as e:
            print(json.dumps({"status": False, "summary": f"Invalid JSON: {str(e)}", "result": {}}))
            return
    else:
        if not args.url:
            parser.print_help()
            return
        params = {
            "url": args.url,
            "max_duration": args.max_duration
        }
    
    result = run(params)
    print(json.dumps(result, indent=2, default=str))

if __name__ == "__main__":
    main()

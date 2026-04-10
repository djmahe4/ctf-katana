import sys
import requests
import json
import logging
from pathlib import Path
from typing import Dict, Any, List

# Add project root to path
project_root = Path(__file__).resolve().parents[2]
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

logger = logging.getLogger("ctf_katana.skills.research_ctftime")

class ResearchCTFTime:
    """Wrapper for the official CTFTime API."""
    def __init__(self, api_url="https://ctftime.org/api/v1/"):
        self.api_url = api_url
        self.headers = {
            # CTFTime requires a distinct User-Agent
            "User-Agent": "CTF-Katana-Research-Bot/1.0"
        }

    def get_upcoming_ctfs(self, limit: int = 5) -> List[Dict[str, Any]]:
        """
        Retrieves a list of upcoming CTF events.
        """
        try:
            # We fetch up to `limit` upcoming events
            response = requests.get(
                f"{self.api_url}events/", 
                headers=self.headers,
                params={"limit": limit, "upcoming": "true"}
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"Failed to fetch upcoming CTFs: {e}")
            return []

    def search_past_writeups(self, event_name: str) -> List[Dict[str, Any]]:
        """
        Searches for past writeups of a specific CTF event.
        
        The API v1 doesn't have a dedicated 'search writeups by string' endpoint.
        It returns events by name, and we would usually need the specific event ID to pull writeups.
        For demonstration, we lookup the event ID first.
        """
        try:
            # 1. Search for Event to get ID
            response = requests.get(
                f"{self.api_url}events/", 
                headers=self.headers,
                params={"name": event_name}
            )
            response.raise_for_status()
            events = response.json()
            
            if not events:
                return []
                
            event_id = events[0].get('id')
            
            # 2. To get the specific tasks/writeups of an event requires a different approach
            # Using the event URL as a fallback reference if tasks API is tight.
            # CTFTime API currently focuses on standard metadata.
            
            return [{
                "event_id": event_id,
                "title": events[0].get('title'),
                "url": events[0].get('url'),
                "ctftime_url": events[0].get('ctftime_url'),
                "message": f"To view writeups, visit: {events[0].get('ctftime_url')}#writeups"
            }]

        except requests.RequestException as e:
            logger.error(f"Failed to search for event writeups: {e}")
            return []

def run(params: Dict[str, Any]) -> Dict[str, Any]:
    """Unified entry point for the skill registry."""
    try:
        api = ResearchCTFTime()
        action = params.get("action", "upcoming")
        
        if action == "upcoming":
            limit = int(params.get("limit", 5))
            data = api.get_upcoming_ctfs(limit=limit)
            return {
                "status": True, 
                "summary": f"Fetched {len(data)} upcoming CTFs.",
                "result": {"events": data}
            }
        elif action == "writeups":
            event = params.get("event_name", "")
            results = api.search_past_writeups(event_name=event)
            return {
                "status": True, 
                "summary": f"Found {len(results)} events for writeup research.",
                "result": {"events": results}
            }
        else:
            return {
                "status": False, 
                "summary": f"Unknown action: {action}",
                "result": {"error": f"Unknown action: {action}"}
            }
    except Exception as e:
        logger.error(f"CTFTime error: {e}")
        return {
            "status": False, 
            "summary": f"CTFTime error: {str(e)}",
            "result": {"error": str(e)}
        }

def main():
    import argparse
    parser = argparse.ArgumentParser(description="CTFTime Research CLI")
    parser.add_argument("--action", choices=["upcoming", "writeups"], default="upcoming")
    parser.add_argument("--limit", type=int, default=5)
    parser.add_argument("--event-name", help="Event name for writeup search")
    parser.add_argument("--json", help="Pass parameters as JSON string")
    parser.add_argument("--test", action="store_true", help="Run sanity test")
    
    args = parser.parse_args()

    if args.test:
        print("[*] Testing CTFTime API Upcoming Events...")
        result = run({"action": "upcoming", "limit": 2})
        print(json.dumps(result, indent=2))
        return

    if args.json:
        try:
            params = json.loads(args.json)
        except json.JSONDecodeError:
            print(json.dumps({"status": False, "summary": "Invalid JSON input", "result": {}}))
            return
    else:
        params = {
            "action": args.action,
            "limit": args.limit,
            "event_name": args.event_name
        }

    result = run(params)
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()

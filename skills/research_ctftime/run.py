import requests
import json
import logging
from typing import Dict, Any, List

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

def run(action: str, **kwargs) -> Dict[str, Any]:
    """Unified entry point for the skill registry."""
    api = ResearchCTFTime()
    
    if action == "upcoming":
        limit = kwargs.get("limit", 5)
        return {"status": "success", "data": api.get_upcoming_ctfs(limit=limit)}
    elif action == "writeups":
        event = kwargs.get("event_name", "")
        return {"status": "success", "data": api.search_past_writeups(event_name=event)}
    else:
        return {"status": "error", "message": f"Unknown action: {action}"}

if __name__ == "__main__":
    # Test execution
    print("[*] Testing CTFTime API Upcoming Events...")
    api = ResearchCTFTime()
    results = api.get_upcoming_ctfs(limit=2)
    print(json.dumps(results, indent=2))

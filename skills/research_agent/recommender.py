import json
from datetime import datetime

class VulnerabilityRecommender:
    """
    Expert Recommendation Engine for Vulnerability Research.
    Uses user context to provide 'Next Best' threats to implement.
    """
    
    def __init__(self, agent_context=None):
        self.history = [] # To track recent user selections
        self.agent_context = agent_context

    def add_selection(self, cve_id, metadata):
        """
        Record a user's selection to refine future recommendations.
        """
        self.history.append({
            "cve_id": cve_id,
            "tech_stack": metadata.get("tech_stack", "unknown"),
            "vector": metadata.get("vector", "unknown"),
            "timestamp": datetime.now().isoformat()
        })

    def suggest_similar(self, current_cve, cached_headers):
        """
        AI-driven logic to suggest similar vulnerabilities from the cache.
        This provides the 'WOW' factor by predicting user interest.
        """
        # In the context of the agent, this will call 'free-llm' 
        # to rank the cached_headers based on the 'current_cve' metadata.
        
        # For the base logic, we just return the next 3 if no AI yet.
        # But our ResearchAgent will trigger the 'free-llm' skill for this.
        return list(cached_headers.keys())[:3]

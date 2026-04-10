"""
Research Agent Orchestrator for Purple Engine

Coordinates autonomous vulnerability research using:
- RAG knowledge base for context
- Multi-agent swarms for parallel research
- Vulnerability discovery and validation
- CTF challenge generation from findings
"""

import os
import sys
import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum

# Add project root to path
project_root = Path(__file__).resolve().parents[2]
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from context.knowledge_base import KnowledgeBase, search_knowledge
from skills.research_chrome_scraper.scraper import ChromeScraper
from skills.research_vuln_discovery.nuclei_manager import NucleiManager
from skills.research_agent.recommender import VulnerabilityRecommender

logger = logging.getLogger(__name__)


class ResearchMode(Enum):
    RESEARCH = "research"
    HUNT = "hunt"
    VALIDATE = "validate"
    GENERATE = "generate"
    FULL_CYCLE = "full_cycle"
    INTERACTIVE = "interactive"


class ResearchDepth(Enum):
    QUICK = "quick"
    MEDIUM = "medium"
    DEEP = "deep"


@dataclass
class Finding:
    """Represents a research finding."""
    id: str
    title: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    confidence: float  # 0.0 to 1.0
    vuln_type: str  # CWE ID or category
    description: str
    evidence: List[str] = field(default_factory=list)
    reproduction_steps: List[str] = field(default_factory=list)
    impact: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class ResearchResult:
    """Result of a research operation."""
    status: str  # success, error, partial
    mode: str
    topic: str
    target: Optional[str]
    findings: List[Finding] = field(default_factory=list)
    knowledge_sources: List[Dict[str, Any]] = field(default_factory=list)
    report: str = ""
    challenge: Optional[Dict[str, Any]] = None
    duration_seconds: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


class ResearchAgent:
    """
    Research Agent Orchestrator.
    
    Coordinates vulnerability research using RAG + multi-agent swarms.
    """
    
    # Depth configurations
    DEPTH_CONFIG = {
        ResearchDepth.QUICK: {
            "rag_results": 3,
            "max_iterations": 1,
            "swarm_agents": 2,
            "timeout": 60,
        },
        ResearchDepth.MEDIUM: {
            "rag_results": 10,
            "max_iterations": 3,
            "swarm_agents": 5,
            "timeout": 300,
        },
        ResearchDepth.DEEP: {
            "rag_results": 25,
            "max_iterations": 10,
            "swarm_agents": 10,
            "timeout": 900,
        },
    }
    
    def __init__(
        self,
        ollama_model: str = None,
        ollama_host: str = None,
        workspace_root: str = None,
    ):
        self.ollama_model = ollama_model or os.environ.get("KATANA_OLLAMA_MODEL", "mistral-nemo")
        self.ollama_host = ollama_host or os.environ.get("KATANA_OLLAMA_HOST", "http://localhost:11434")
        self.workspace_root = Path(workspace_root or os.getcwd())
        
        # Initialize knowledge base
        self.kb = KnowledgeBase()
        
        # Track findings
        self.findings: List[Finding] = []
        
        # Initialize specialized tools
        self.scraper = ChromeScraper()
        self.nuclei = NucleiManager()
        self.recommender = VulnerabilityRecommender(agent_context=self)
        
        # Phase 3: Discovery Agent integration
        from skills.research_agent.discovery_agent import DiscoveryAgent
        self.discovery_agent = DiscoveryAgent(str(self.workspace_root))
        
        logger.info(f"ResearchAgent initialized with model: {self.ollama_model}")
    
    async def scout(self, delta_json_url: str = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/delta.json") -> List[Dict[str, Any]]:
        """
        Executes a 'Scout' run to find new vulnerabilities from the latest deltas.
        """
        logger.info(f"Starting Scout run from {delta_json_url}...")
        
        import requests
        try:
            response = requests.get(delta_json_url, timeout=10)
            delta_data = response.json()
        except Exception as e:
            logger.error(f"Failed to fetch delta.json: {e}")
            return []
            
        candidates = self.discovery_agent.scout_deltas(delta_data)
        report = self.discovery_agent.get_discovery_report(candidates)
        print("\n" + report)
        return candidates

    async def hunt(self, cve_id: str):
        """
        Performs a 'Deep Dive' analysis on a specific CVE.
        Delegates to @free-llm-apis for documentation and solver generation.
        """
        print(f"\n[*] Starting Deep Dive: {cve_id}...")
        
        # Check if Nuclei template exists first
        nuclei_url = self.nuclei.search_official_template(cve_id)
        if nuclei_url:
            print(f"[!] Notification: Official Nuclei template found at: {nuclei_url}")
            print(f"    Recommendation: Use this template for verification.")
            confirm = input("    Import this template? (y/n): ").strip().lower()
            if confirm == 'y':
                path = self.nuclei.import_template(cve_id, nuclei_url)
                print(f"[+] Template imported to {path}")
        
        # AI Delegation (Signaled to the parent agent)
        print(f"[*] Task ready for @free-llm-apis to perform deep analysis.")
        print(f"    Target: {cve_id}\n    Docs will populate in 'docs/vulnerability_catalog/{cve_id}.md'")

    def _query_llm(self, prompt: str, system_prompt: str = None) -> str:
        """Query Ollama LLM."""
        try:
            import requests
            
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})
            
            response = requests.post(
                f"{self.ollama_host}/api/chat",
                json={
                    "model": self.ollama_model,
                    "messages": messages,
                    "stream": False,
                },
                timeout=120,
            )
            response.raise_for_status()
            
            return response.json().get("message", {}).get("content", "")
            
        except Exception as e:
            logger.error(f"LLM query error: {e}")
            return f"Error querying LLM: {e}"
    
    def _gather_context(self, topic: str, depth: ResearchDepth) -> List[Dict[str, Any]]:
        """Gather relevant context from RAG knowledge base."""
        config = self.DEPTH_CONFIG[depth]
        
        # Search knowledge base
        results = self.kb.search(
            query=topic,
            limit=config["rag_results"],
        )
        
        return [
            {
                "title": r.title,
                "source": r.source,
                "relevance": r.relevance,
                "content": r.content,
                "url": r.url,
            }
            for r in results
        ]
    
    def _generate_research_prompt(
        self,
        topic: str,
        context: List[Dict[str, Any]],
        mode: ResearchMode,
    ) -> str:
        """Generate research prompt with context."""
        context_text = "\n\n".join([
            f"### {c['title']} (relevance: {c['relevance']})\n{c['content'][:500]}..."
            for c in context[:5]
        ])
        
        if mode == ResearchMode.RESEARCH:
            return f"""Research the following security topic thoroughly:

TOPIC: {topic}

EXISTING KNOWLEDGE:
{context_text}

Based on the above context and your knowledge, provide:
1. A comprehensive overview of the vulnerability/technique
2. Common attack vectors and exploitation methods
3. Real-world examples or CVEs if applicable
4. Detection and prevention strategies
5. Any gaps in the existing knowledge that need further research

Format your response as a structured research report."""

        elif mode == ResearchMode.HUNT:
            return f"""You are hunting for vulnerabilities related to:

TARGET/TOPIC: {topic}

RELEVANT KNOWLEDGE:
{context_text}

Provide a hunting methodology:
1. Reconnaissance steps
2. Specific indicators to look for
3. Testing techniques
4. Potential payload patterns
5. Validation approaches

Be specific and actionable."""

        elif mode == ResearchMode.VALIDATE:
            return f"""Validate the following potential vulnerability:

FINDING: {topic}

CONTEXT:
{context_text}

Provide:
1. Reproduction steps
2. Proof-of-concept approach
3. Impact assessment
4. Confidence level (with justification)
5. False positive indicators to check"""

        else:
            return f"""Analyze the following topic: {topic}\n\nContext:\n{context_text}"""
    
    def research(
        self,
        topic: str,
        depth: ResearchDepth = ResearchDepth.MEDIUM,
        target: str = None,
    ) -> ResearchResult:
        """
        Conduct general vulnerability research on a topic.
        """
        start_time = datetime.utcnow()
        
        logger.info(f"Starting research on: {topic} (depth: {depth.value})")
        
        # Gather context from RAG
        context = self._gather_context(topic, depth)
        logger.info(f"Found {len(context)} relevant knowledge sources")
        
        # Generate research prompt
        prompt = self._generate_research_prompt(topic, context, ResearchMode.RESEARCH)
        
        # Query LLM for research
        system_prompt = """You are an expert security researcher. Provide thorough, accurate, 
and actionable security research. Always cite sources when possible and indicate confidence levels."""
        
        research_response = self._query_llm(prompt, system_prompt)
        
        # Parse findings (simplified - in production would use structured extraction)
        findings = self._extract_findings(research_response, topic)
        
        duration = (datetime.utcnow() - start_time).total_seconds()
        
        return ResearchResult(
            status="success",
            mode=ResearchMode.RESEARCH.value,
            topic=topic,
            target=target,
            findings=findings,
            knowledge_sources=context,
            report=research_response,
            duration_seconds=duration,
            metadata={
                "depth": depth.value,
                "rag_sources": len(context),
                "model": self.ollama_model,
            },
        )
    
    def hunt(
        self,
        target: str,
        topic: str,
        depth: ResearchDepth = ResearchDepth.MEDIUM,
    ) -> ResearchResult:
        """
        Active vulnerability hunting on a target.
        """
        start_time = datetime.utcnow()
        
        logger.info(f"Starting hunt for {topic} on {target}")
        
        # Gather context
        context = self._gather_context(f"{topic} {target}", depth)
        
        # Generate hunt prompt
        prompt = self._generate_research_prompt(f"{topic} on {target}", context, ResearchMode.HUNT)
        
        system_prompt = """You are an expert penetration tester and bug bounty hunter.
Provide specific, actionable hunting methodologies. Focus on practical techniques."""
        
        hunt_response = self._query_llm(prompt, system_prompt)
        
        findings = self._extract_findings(hunt_response, topic)
        
        duration = (datetime.utcnow() - start_time).total_seconds()
        
        return ResearchResult(
            status="success",
            mode=ResearchMode.HUNT.value,
            topic=topic,
            target=target,
            findings=findings,
            knowledge_sources=context,
            report=hunt_response,
            duration_seconds=duration,
        )
    
    def validate(
        self,
        finding: str,
        evidence: List[str] = None,
    ) -> ResearchResult:
        """
        Validate a potential vulnerability finding.
        """
        start_time = datetime.utcnow()
        
        logger.info(f"Validating finding: {finding}")
        
        context = self._gather_context(finding, ResearchDepth.MEDIUM)
        
        prompt = self._generate_research_prompt(finding, context, ResearchMode.VALIDATE)
        
        if evidence:
            prompt += f"\n\nEVIDENCE PROVIDED:\n" + "\n".join(f"- {e}" for e in evidence)
        
        system_prompt = """You are a security validation expert. Analyze findings critically,
identify false positives, and provide clear reproduction steps for real vulnerabilities."""
        
        validation_response = self._query_llm(prompt, system_prompt)
        
        duration = (datetime.utcnow() - start_time).total_seconds()
        
        return ResearchResult(
            status="success",
            mode=ResearchMode.VALIDATE.value,
            topic=finding,
            target=None,
            findings=[],
            knowledge_sources=context,
            report=validation_response,
            duration_seconds=duration,
        )
    
    def generate_challenge(
        self,
        finding: Finding,
        difficulty: str = "medium",
    ) -> Dict[str, Any]:
        """
        Generate a CTF challenge from a validated finding.
        """
        logger.info(f"Generating challenge from: {finding.title}")
        
        prompt = f"""Create a CTF challenge based on this vulnerability:

VULNERABILITY: {finding.title}
TYPE: {finding.vuln_type}
DESCRIPTION: {finding.description}

Generate:
1. Challenge name and description (for CTFd)
2. Difficulty: {difficulty}
3. Points suggestion
4. Challenge setup (Docker/code requirements)
5. Flag format and placement
6. Hints (3 levels)
7. Solution walkthrough
8. AI-hardening techniques to prevent trivial AI solving

Output as structured JSON."""

        system_prompt = """You are a CTF challenge designer. Create educational, 
realistic challenges that teach security concepts without being trivially solvable by AI."""
        
        response = self._query_llm(prompt, system_prompt)
        
        # Try to parse JSON from response
        try:
            # Find JSON in response
            import re
            json_match = re.search(r'\{[\s\S]*\}', response)
            if json_match:
                challenge = json.loads(json_match.group())
            else:
                challenge = {"raw_response": response}
        except json.JSONDecodeError:
            challenge = {"raw_response": response}
        
        challenge["source_finding"] = finding.id
        challenge["generated_at"] = datetime.utcnow().isoformat()
        
        return challenge
    
    def _extract_findings(self, response: str, topic: str) -> List[Finding]:
        """Extract structured findings from LLM response."""
        # Simplified extraction - in production would use structured prompting
        findings = []
        
        # Create a finding from the research
        finding = Finding(
            id=f"FINDING-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            title=f"Research: {topic}",
            severity="INFO",
            confidence=0.7,
            vuln_type="research",
            description=response[:500] if len(response) > 500 else response,
            references=[],
        )
        findings.append(finding)
        
        return findings
    
    def full_cycle(
        self,
        topic: str,
        depth: ResearchDepth = ResearchDepth.MEDIUM,
        target: str = None,
    ) -> ResearchResult:
        """
        Complete research → validate → generate pipeline.
        """
        start_time = datetime.utcnow()
        all_findings = []
        
        # Phase 1: Research
        logger.info("Phase 1: Research")
        research_result = self.research(topic, depth, target)
        all_findings.extend(research_result.findings)
        
        # Phase 2: Hunt (if target provided)
        if target:
            logger.info("Phase 2: Hunt")
            hunt_result = self.hunt(target, topic, depth)
            all_findings.extend(hunt_result.findings)
        
        # Phase 3: Generate challenges from findings
        challenges = []
        for finding in all_findings[:3]:  # Limit to top 3
            logger.info(f"Phase 3: Generate challenge for {finding.id}")
            challenge = self.generate_challenge(finding)
            challenges.append(challenge)
        
        duration = (datetime.utcnow() - start_time).total_seconds()
        
        # Compile full report
        report = f"""# Full Research Cycle: {topic}

## Research Findings
{research_result.report}

## Generated Challenges
{len(challenges)} challenges generated from findings.

## Summary
- Duration: {duration:.1f} seconds
- Findings: {len(all_findings)}
- Challenges: {len(challenges)}
"""
        
        return ResearchResult(
            status="success",
            mode=ResearchMode.FULL_CYCLE.value,
            topic=topic,
            target=target,
            findings=all_findings,
            knowledge_sources=research_result.knowledge_sources,
            report=report,
            challenge=challenges[0] if challenges else None,
            duration_seconds=duration,
            metadata={
                "all_challenges": challenges,
                "depth": depth.value,
            },
        )

    def interactive_loop(self, topic: str = "recent"):
        """
        Iterative, Human-in-the-Loop research flow.
        """
        print(f"\n[+] Entering Interactive Research Mode for: {topic}")
        
        # 1. Lazy Ingestion (Index only)
        print("[*] Observing delta.json via Chrome Scraper...")
        # (This would be triggered by an actual browser call in the CLI environment)
        # For now, we use the cached headers.
        
        headers = self.scraper.get_cached_headers(limit=5)
        
        if not headers:
            print("[!] No cached vulnerabilities found. Please run a fetch first.")
            return {"status": "error", "message": "No cache"}

        print("\n--- Recent Vulnerabilities ---")
        for i, (cve_id, meta) in enumerate(headers.items()):
            print(f"{i+1}. {cve_id} | Updated: {meta['updated']} | Status: {meta['status']}")
        
        print("\n[?] Which CVE would you like to explore? (Enter number or ID)")
        # In a real CLI, we'd take input here.
        # This logic will be driven by the user prompts in this session.
        return {"status": "pending_selection", "candidates": headers}


def run(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main entry point for Research Agent skill.
    
    Args:
        params: {
            'mode': str,        # research, hunt, validate, generate, full_cycle
            'topic': str,       # Research topic
            'target': str,      # Target URL/system (optional)
            'depth': str,       # quick, medium, deep
            'finding': dict,    # Finding to validate/generate from (optional)
        }
    """
    mode = params.get('mode', 'research')
    topic = params.get('topic', '')
    target = params.get('target')
    depth_str = params.get('depth', 'medium')
    
    if not topic and mode != 'validate':
        return {
            'status': False,
            'summary': 'topic parameter required',
        }
    
    try:
        depth = ResearchDepth(depth_str)
    except ValueError:
        depth = ResearchDepth.MEDIUM
    
    try:
        agent = ResearchAgent()
        
        if mode == 'research':
            result = agent.research(topic, depth, target)
        elif mode == 'hunt':
            if not target:
                return {'status': False, 'summary': 'target required for hunt mode'}
            result = agent.hunt(target, topic, depth)
        elif mode == 'validate':
            evidence = params.get('evidence', [])
            result = agent.validate(topic or params.get('finding', ''), evidence)
        elif mode == 'generate':
            finding_data = params.get('finding', {})
            finding = Finding(
                id=finding_data.get('id', 'MANUAL'),
                title=finding_data.get('title', topic),
                severity=finding_data.get('severity', 'MEDIUM'),
                confidence=finding_data.get('confidence', 0.8),
                vuln_type=finding_data.get('vuln_type', 'unknown'),
                description=finding_data.get('description', topic),
            )
            challenge = agent.generate_challenge(finding)
            return {
                'status': True,
                'summary': f"Generated challenge based on research topic: {topic}",
                'result': {
                    'mode': 'generate',
                    'challenge': challenge,
                }
            }
        elif mode == 'full_cycle':
            result = agent.full_cycle(topic, depth, target)
        elif mode == 'interactive':
            result = agent.interactive_loop(topic)
            return {
                'status': True,
                'summary': f"Entered interactive mode for topic: {topic}",
                'result': {
                    'mode': 'interactive',
                    'candidates': result.get('candidates', {}),
                    'summary': 'Entering Interactive Mode. Review candidates below.'
                }
            }
        else:
            return {
                'status': False,
                'summary': f'Unknown mode: {mode}',
                'result': {'valid_modes': ['research', 'hunt', 'validate', 'generate', 'full_cycle']},
            }
        
        summary = f"Completed {result.mode} for topic: {result.topic}."
        if result.findings:
            summary += f" Found {len(result.findings)} items."

        return {
            'status': True,
            'summary': summary,
            'result': {
                'mode': result.mode,
                'topic': result.topic,
                'target': result.target,
                'findings': [asdict(f) for f in result.findings],
                'knowledge_sources': result.knowledge_sources[:5],  # Limit for output
                'report': result.report,
                'challenge': result.challenge,
                'duration_seconds': result.duration_seconds,
                'metadata': result.metadata,
            }
        }
        
    except Exception as e:
        logger.error(f"Research agent error: {e}")
        return {
            "status": False,
            "summary": f"Research agent error: {str(e)}",
            "result": {"error_type": type(e).__name__}
        }


def main():
    """CLI entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Research Agent CLI')
    parser.add_argument('mode', choices=['research', 'hunt', 'validate', 'generate', 'full_cycle', 'interactive'])
    parser.add_argument('--topic', '-t', required=False, default='recent', help='Research topic')
    parser.add_argument('--target', help='Target URL/system')
    parser.add_argument('--depth', choices=['quick', 'medium', 'deep'], default='medium')
    
    args = parser.parse_args()
    
    result = run({
        'mode': args.mode,
        'topic': args.topic,
        'target': args.target,
        'depth': args.depth,
    })
    
    print(json.dumps(result, indent=2, default=str))


if __name__ == '__main__':
    main()

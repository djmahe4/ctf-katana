"""
Purple Engine - CTFd Solve Skill Implementation

Autonomously solves CTFd challenges using the 6-step agent loop:
Analyze → Search KB → Plan → Execute → Interpret → Report

Integrates CTFd API for challenge enumeration, artifact download, and flag submission.
"""

import sys
import os
import json
import logging
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

# Add project root to sys.path for standalone execution
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Import CTFd API client from the bridge
try:
    from skills.api_client import CTFdAPIClient, CTFdChallenge, CTFdSubmission
except ImportError:
    from api_client import CTFdAPIClient, CTFdChallenge, CTFdSubmission

# Import Katana agents (will be available when run in Katana environment)
try:
    from agents.analyzer import AnalyzerAgent
    from agents.planner import PlannerAgent
    from agents.executor import ExecutorAgent
    from agents.reporter import ReporterAgent
except ImportError:
    # Fallback for testing
    AnalyzerAgent = None
    PlannerAgent = None
    ExecutorAgent = None
    ReporterAgent = None

logger = logging.getLogger(__name__)


class CTFdSolver:
    """
    Autonomous CTFd challenge solver using Purple Engine.
    
    Combines CTFd API integration with the Katana 6-step agent loop
    to automatically solve challenges, submit flags, and generate write-ups.
    """
    
    def __init__(self, 
                 ctfd_url: str,
                 username: str = None,
                 password: str = None,
                 api_token: str = None,
                 auto_submit: bool = True,
                 generate_writeup: bool = True,
                 output_dir: str = "./ctfd_output",
                 max_retries: int = 3,
                 ollama_model: str = None,
                 ollama_host: str = None):
        """
        Initialize CTFd Solver.
        
        Args:
            ctfd_url: CTFd instance URL
            username: CTFd username (optional if api_token provided)
            password: CTFd password (optional if api_token provided)
            api_token: CTFd API token
            auto_submit: Auto-submit flags when found
            generate_writeup: Generate write-ups after solving
            output_dir: Directory to save artifacts and write-ups
            max_retries: Maximum retry attempts per challenge
            ollama_model: Ollama model to use (default from env)
            ollama_host: Ollama host URL (default from env)
        """
        # Initialize CTFd client
        self.client = CTFdAPIClient(ctfd_url, username, password, api_token)
        if not self.client.authenticated:
            raise ValueError("Failed to authenticate with CTFd")
        
        self.auto_submit = auto_submit
        self.generate_writeup = generate_writeup
        self.output_dir = Path(output_dir)
        self.max_retries = max_retries
        
        # Create output directory
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize Ollama settings
        self.ollama_model = ollama_model or os.getenv('KATANA_OLLAMA_MODEL', 'mistral')
        self.ollama_host = ollama_host or os.getenv('KATANA_OLLAMA_HOST', 'http://localhost:11434')
        
        # Results tracking
        self.results = []
        self.total_points = 0
    
    def list_challenges(self, category: str = None) -> List[Dict[str, Any]]:
        """
        List available challenges from CTFd.
        
        Args:
            category: Filter by category (optional)
            
        Returns:
            List of challenge metadata dictionaries
        """
        challenges = self.client.list_challenges(category=category)
        
        result = []
        for challenge in challenges:
            result.append({
                'id': challenge.id,
                'name': challenge.name,
                'category': challenge.category,
                'value': challenge.value,
                'description': challenge.description[:200] + '...' if len(challenge.description) > 200 else challenge.description,
                'files': len(challenge.files),
                'tags': challenge.tags
            })
        
        return result
    
    def solve_challenge(self, challenge_id: int = None, challenge_name: str = None) -> Dict[str, Any]:
        """
        Solve a single challenge using the 6-step agent loop.
        
        Args:
            challenge_id: Challenge ID (optional if challenge_name provided)
            challenge_name: Challenge name (optional if challenge_id provided)
            
        Returns:
            Dictionary with solve results
        """
        # Get challenge details
        if challenge_id:
            challenge = self.client.get_challenge(challenge_id)
        elif challenge_name:
            # Find challenge by name
            challenges = self.client.list_challenges(visible_only=False)
            challenge = next((c for c in challenges if c.name.lower() == challenge_name.lower()), None)
        else:
            raise ValueError("Must provide either challenge_id or challenge_name")
        
        if not challenge:
            return {
                'status': 'failed',
                'error': 'Challenge not found',
                'challenge_id': challenge_id,
                'challenge_name': challenge_name
            }
        
        logger.info(f"Attempting to solve: [{challenge.category}] {challenge.name} ({challenge.value}pts)")
        
        # Create challenge-specific output directory
        challenge_dir = self.output_dir / f"{challenge.id}_{challenge.name.replace(' ', '_')}"
        challenge_dir.mkdir(exist_ok=True)
        
        # Download challenge files
        artifacts = self._download_artifacts(challenge, challenge_dir)
        
        # Execute 6-step solving workflow
        try:
            result = self._execute_solve_loop(challenge, artifacts, challenge_dir)
            
            # Auto-submit flag if found and enabled
            if result.get('flag') and self.auto_submit:
                submission = self.client.submit_flag(challenge.id, result['flag'])
                result['submitted'] = submission.correct
                result['submission_message'] = submission.message
                
                if submission.correct:
                    logger.info(f"✓ Correctly solved: {challenge.name}")
                    self.total_points += challenge.value
                else:
                    logger.warning(f"✗ Flag incorrect for {challenge.name}: {submission.message}")
            
            # Generate write-up if enabled
            if self.generate_writeup and result.get('flag'):
                writeup_path = self._generate_writeup(challenge, result, challenge_dir)
                result['writeup_path'] = str(writeup_path)
            
            self.results.append(result)
            return result
            
        except Exception as e:
            logger.error(f"Error solving challenge {challenge.name}: {e}", exc_info=True)
            error_result = {
                'status': 'failed',
                'challenge_id': challenge.id,
                'challenge_name': challenge.name,
                'category': challenge.category,
                'error': str(e)
            }
            self.results.append(error_result)
            return error_result
    
    def _download_artifacts(self, challenge: CTFdChallenge, output_dir: Path) -> List[Path]:
        """Download all challenge files to output directory."""
        artifacts = []
        
        # Save challenge description
        desc_file = output_dir / "description.txt"
        desc_file.write_text(challenge.description, encoding='utf-8')
        artifacts.append(desc_file)
        
        # Download files
        for file_url in challenge.files:
            filename = file_url.split('/')[-1]
            file_path = output_dir / filename
            
            if self.client.download_file(file_url, str(file_path)):
                artifacts.append(file_path)
                logger.info(f"Downloaded: {filename}")
        
        return artifacts
    
    def _execute_solve_loop(self, 
                           challenge: CTFdChallenge, 
                           artifacts: List[Path], 
                           output_dir: Path) -> Dict[str, Any]:
        """
        Execute the 6-step agent solving workflow.
        
        Returns:
            Dictionary with solve results including flag if found
        """
        start_time = datetime.now()
        steps_log = []
        
        # Prepare artifact info for agents
        artifact_info = {
            'challenge_name': challenge.name,
            'category': challenge.category,
            'description': challenge.description,
            'files': [str(f) for f in artifacts],
            'value': challenge.value
        }
        
        # STEP 1: ANALYZE
        logger.info("Step 1: Analyzing challenge...")
        if AnalyzerAgent:
            analyzer = AnalyzerAgent(model=self.ollama_model, ollama_host=self.ollama_host)
            analysis = analyzer.analyze(json.dumps(artifact_info))
            steps_log.append({'step': 1, 'action': 'analyze', 'result': analysis})
        else:
            # Fallback: basic analysis
            analysis = {
                'category': challenge.category,
                'observations': ['Challenge analysis not available (AnalyzerAgent not loaded)'],
                'suggested_tools': []
            }
            steps_log.append({'step': 1, 'action': 'analyze', 'result': analysis})
        
        # STEP 2: SEARCH KNOWLEDGE BASE
        logger.info("Step 2: Searching knowledge base...")
        # This would normally query the KB - for now, use category-based hints
        kb_context = self._get_kb_context(challenge.category)
        steps_log.append({'step': 2, 'action': 'search_kb', 'result': kb_context})
        
        # STEP 3: PLAN
        logger.info("Step 3: Generating solve plan...")
        if PlannerAgent:
            planner = PlannerAgent(model=self.ollama_model, ollama_host=self.ollama_host)
            plan = planner.plan(json.dumps(analysis), kb_context)
            steps_log.append({'step': 3, 'action': 'plan', 'result': plan})
        else:
            # Fallback: basic plan
            plan = {
                'steps': [
                    {'step': 1, 'action': 'Examine artifacts', 'tool': 'manual', 'args': {}}
                ]
            }
            steps_log.append({'step': 3, 'action': 'plan', 'result': plan})
        
        # STEP 4: EXECUTE
        logger.info("Step 4: Executing plan...")
        execution_results = self._execute_plan(plan, artifacts, output_dir)
        steps_log.append({'step': 4, 'action': 'execute', 'result': execution_results})
        
        # STEP 5: INTERPRET
        logger.info("Step 5: Interpreting results...")
        flag = self._extract_flag(execution_results, challenge.category)
        interpretation = {
            'flag_found': flag is not None,
            'flag': flag,
            'confidence': 'high' if flag else 'low'
        }
        steps_log.append({'step': 5, 'action': 'interpret', 'result': interpretation})
        
        # STEP 6: REPORT (handled in write-up generation)
        
        solve_time = (datetime.now() - start_time).total_seconds()
        
        return {
            'status': 'solved' if flag else 'attempted',
            'challenge_id': challenge.id,
            'challenge_name': challenge.name,
            'category': challenge.category,
            'value': challenge.value,
            'flag': flag,
            'solve_time_seconds': solve_time,
            'steps_executed': steps_log,
            'submitted': False
        }
    
    def _get_kb_context(self, category: str) -> str:
        """Get knowledge base context for category (placeholder)."""
        kb_hints = {
            'crypto': 'Common techniques: ROT13, Caesar cipher, XOR, Base64, Vigenère',
            'stego': 'Tools: strings, exiftool, binwalk, steghide, zsteg',
            'forensics': 'Tools: file, foremost, pngcheck, PDF analysis',
            'web': 'Vulnerabilities: SQL injection, XSS, path traversal, JWT',
            'pwn': 'Techniques: buffer overflow, ROP, format strings',
            'reversing': 'Tools: disassembly, decompilation, string analysis',
            'recon': 'Tools: nmap, whois, dig, OSINT'
        }
        return kb_hints.get(category, 'General CTF solving techniques')
    
    def _execute_plan(self, plan: Dict, artifacts: List[Path], output_dir: Path) -> List[Dict]:
        """Execute planned steps (placeholder - would invoke actual tools)."""
        results = []
        
        # For now, basic file examination
        for artifact in artifacts:
            if artifact.suffix == '.txt':
                content = artifact.read_text(errors='ignore')
                results.append({
                    'tool': 'read_file',
                    'file': str(artifact),
                    'output': content[:1000]  # First 1000 chars
                })
        
        return results
    
    def _extract_flag(self, execution_results: List[Dict], category: str) -> Optional[str]:
        """Extract flag from execution results."""
        import re
        
        # Common flag patterns
        patterns = [
            r'flag\{[^}]+\}',
            r'FLAG\{[^}]+\}',
            r'ctf\{[^}]+\}',
            r'CTF\{[^}]+\}',
        ]
        
        # Search all execution outputs
        for result in execution_results:
            output = result.get('output', '')
            if isinstance(output, str):
                for pattern in patterns:
                    match = re.search(pattern, output, re.IGNORECASE)
                    if match:
                        return match.group(0)
        
        return None
    
    def _generate_writeup(self, challenge: CTFdChallenge, result: Dict, output_dir: Path) -> Path:
        """Generate Markdown write-up."""
        writeup_path = output_dir / "writeup.md"
        
        writeup = f"""# {challenge.name}

**Category:** {challenge.category}  
**Points:** {challenge.value}  
**Status:** {result['status']}

## Description

{challenge.description}

## Solution

### Analysis
{json.dumps(result['steps_executed'][0]['result'], indent=2)}

### Solve Steps
"""
        
        for step in result['steps_executed']:
            writeup += f"\n**Step {step['step']}: {step['action']}**\n\n"
            writeup += f"```\n{json.dumps(step['result'], indent=2)}\n```\n"
        
        if result.get('flag'):
            writeup += f"\n## Flag\n\n```\n{result['flag']}\n```\n"
        
        writeup += f"\n## Solve Time\n\n{result['solve_time_seconds']:.1f} seconds\n"
        
        writeup_path.write_text(writeup, encoding='utf-8')
        logger.info(f"Write-up saved: {writeup_path}")
        
        return writeup_path
    
    def get_summary(self) -> Dict[str, Any]:
        """Get comprehensive solving summary."""
        solved = [r for r in self.results if r['status'] == 'solved']
        attempted = [r for r in self.results if r['status'] == 'attempted']
        failed = [r for r in self.results if r['status'] == 'failed']
        
        return {
            'ctfd_instance': self.client.base_url,
            'challenges_attempted': len(self.results),
            'challenges_solved': len(solved),
            'challenges_failed': len(attempted) + len(failed),
            'total_points_earned': self.total_points,
            'results': self.results,
            'success_rate': f"{len(solved) / len(self.results) * 100:.1f}%" if self.results else "0%"
        }


def run(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main entry point for the ctfd_solve skill.
    
    Args:
        params: Dictionary with parameters from skill.yaml
        
    Returns:
        Dictionary with status, summary, and result
    """
    # Extract parameters
    ctfd_url = params.get('ctfd_url')
    username = params.get('username')
    password = params.get('password')
    api_token = params.get('api_token')
    challenge_id = params.get('challenge_id')
    challenge_name = params.get('challenge_name')
    category = params.get('category')
    auto_submit = params.get('auto_submit', True)
    generate_writeup = params.get('generate_writeup', True)
    output_dir = params.get('output_dir', './ctfd_output')
    max_retries = params.get('max_retries', 3)
    
    # Validate inputs
    if not ctfd_url:
        return {'status': False, 'summary': 'ctfd_url is required', 'result': {}}
    
    if not (api_token or (username and password)):
        return {'status': False, 'summary': 'Must provide api_token or username+password', 'result': {}}
    
    try:
        # Initialize solver
        solver = CTFdSolver(
            ctfd_url=ctfd_url,
            username=username,
            password=password,
            api_token=api_token,
            auto_submit=auto_submit,
            generate_writeup=generate_writeup,
            output_dir=output_dir,
            max_retries=max_retries
        )
        
        # LIST MODE: No specific challenge requested
        if not challenge_id and not challenge_name:
            challenges = solver.list_challenges(category=category)
            return {
                'status': True,
                'summary': f"Listed {len(challenges)} challenges",
                'result': {
                    'mode': 'list',
                    'challenges': challenges,
                    'total_challenges': len(challenges)
                }
            }
        
        # SOLVE MODE: Specific challenge
        result = solver.solve_challenge(challenge_id=challenge_id, challenge_name=challenge_name)
        summary_data = solver.get_summary()
        
        # Enforce error status if solve failed
        status = True
        if result.get('status') == 'failed' or 'error' in result:
             status = False
             summary = result.get('error', 'Solve failed')
        else:
             summary = f"Attempted challenge: {challenge_name or challenge_id}"

        return {
            'status': status,
            'summary': summary,
            'result': {
                'mode': 'solve',
                'solve_result': result,
                'overall_summary': summary_data
            }
        }
        
    except Exception as e:
        logger.error(f"CTFd solve skill error: {e}", exc_info=True)
        return {
            'status': False,
            'summary': f"Error during CTFd solve: {str(e)}",
            'result': {}
        }


def main():
    parser = argparse.ArgumentParser(description='CTFd Solve Skill')
    parser.add_argument('--json', help='JSON Parameters')
    parser.add_argument('--test', action='store_true', help='Run sanity check')
    
    # Legacy CLI arguments
    parser.add_argument('--ctfd_url', help='CTFd instance URL')
    parser.add_argument('--api_token', help='CTFd API token')
    parser.add_argument('--username', help='CTFd username')
    parser.add_argument('--password', help='CTFd password')
    parser.add_argument('--challenge_id', type=int, help='Challenge ID to solve')
    parser.add_argument('--challenge_name', help='Challenge name to solve')
    parser.add_argument('--category', help='Filter challenges by category')
    
    args = parser.parse_args()
    
    if args.test:
        print("Running sanity check for ctfd_solve...")
        try:
            # Basic validation: try to import the API client
            try:
                from skills.api_client import CTFdAPIClient
            except ImportError:
                from api_client import CTFdAPIClient
            print("✓ Successfully imported CTFdAPIClient")
            print("✓ Sanity check passed.")
            sys.exit(0)
        except Exception as e:
            print(f"✗ Sanity check failed: {e}")
            sys.exit(1)

    if args.json:
        # If --json is provided as a string, it contains the full params
        try:
            params = json.loads(args.json)
        except json.JSONDecodeError:
            # Fallback for when --json was used as a flag in some versions
            params = vars(args)
    else:
        params = vars(args)
        # Remove internal arg labels
        params.pop('json', None)
        params.pop('test', None)
        # Remove None values
        params = {k: v for k, v in params.items() if v is not None}
        
    # Standardize result output
    result = run(params)
    print(json.dumps(result, indent=2))

if __name__ == '__main__':
    main()

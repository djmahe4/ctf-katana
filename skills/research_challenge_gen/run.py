"""
CTF Challenge Generator

Automatically generates CTF challenges from vulnerability findings,
with AI-hardening to prevent trivial automated solving.
"""

import os
import sys
import json
import logging
import random
import string
import hashlib
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum

# Add project root to path
project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root))

logger = logging.getLogger(__name__)


class Difficulty(Enum):
    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"
    INSANE = "insane"


class Category(Enum):
    WEB = "web"
    PWN = "pwn"
    CRYPTO = "crypto"
    FORENSICS = "forensics"
    REVERSE = "reverse"
    MISC = "misc"
    WEB3 = "web3"
    MOBILE = "mobile"


class AIHardening(Enum):
    NONE = "none"
    STANDARD = "standard"
    AGGRESSIVE = "aggressive"


# Points by difficulty
DIFFICULTY_POINTS = {
    Difficulty.EASY: (100, 200),
    Difficulty.MEDIUM: (200, 400),
    Difficulty.HARD: (400, 700),
    Difficulty.INSANE: (700, 1000),
}

# Challenge templates by category and type
CHALLENGE_TEMPLATES = {
    "sqli": {
        "category": Category.WEB,
        "name_templates": [
            "Login Bypass",
            "Database Dungeon",
            "Query Quest",
            "Injection Junction",
        ],
        "description_templates": [
            "Can you bypass the login page and access the admin panel?",
            "There's a database full of secrets. Can you extract them?",
            "This web application seems vulnerable. Find the flag!",
        ],
        "flag_keywords": ["sql", "inject", "database", "query"],
    },
    "xss": {
        "category": Category.WEB,
        "name_templates": [
            "Script Kiddie",
            "Cookie Monster",
            "XSS Playground",
            "Browser Betrayal",
        ],
        "description_templates": [
            "Execute JavaScript in the context of another user.",
            "Steal the admin's cookies to get the flag.",
            "This comment section looks interesting...",
        ],
        "flag_keywords": ["xss", "script", "cookie", "alert"],
    },
    "reentrancy": {
        "category": Category.WEB3,
        "name_templates": [
            "Bank Heist",
            "Recursive Riches",
            "The DAO Strikes Back",
            "Withdraw Wisely",
        ],
        "description_templates": [
            "This smart contract bank has a vulnerability. Can you drain it?",
            "Find the reentrancy bug and claim the reward.",
            "The withdraw function looks suspicious...",
        ],
        "flag_keywords": ["reentr", "withdraw", "callback", "drain"],
    },
    "buffer_overflow": {
        "category": Category.PWN,
        "name_templates": [
            "Stack Smash",
            "Buffer Bonanza",
            "Memory Mayhem",
            "Overflow Odyssey",
        ],
        "description_templates": [
            "This binary has a buffer overflow. Can you get a shell?",
            "Smash the stack and read the flag file.",
            "The function doesn't check input length...",
        ],
        "flag_keywords": ["overflow", "stack", "smash", "pwn"],
    },
    "crypto_weak": {
        "category": Category.CRYPTO,
        "name_templates": [
            "Weak Cipher",
            "Crypto Catastrophe",
            "Broken Encryption",
            "Key Confusion",
        ],
        "description_templates": [
            "This encryption scheme has a weakness. Can you break it?",
            "Find the flaw in the cryptographic implementation.",
            "The random number generator isn't so random...",
        ],
        "flag_keywords": ["crypto", "cipher", "decrypt", "key"],
    },
}

# AI hardening techniques
AI_HARDENING_TECHNIQUES = {
    AIHardening.NONE: [],
    AIHardening.STANDARD: [
        "context_embedding",
        "red_herrings",
        "multi_step",
    ],
    AIHardening.AGGRESSIVE: [
        "context_embedding",
        "red_herrings",
        "multi_step",
        "visual_elements",
        "timing_based",
        "anti_pattern_injection",
        "domain_knowledge",
    ],
}


@dataclass
class ChallengeHint:
    """A progressive hint for the challenge."""
    cost: int
    text: str


@dataclass
class ChallengeSolution:
    """Solution documentation."""
    walkthrough: str
    tools_required: List[str] = field(default_factory=list)
    time_estimate: str = ""


@dataclass
class ChallengeHardening:
    """AI hardening documentation."""
    techniques_applied: List[str] = field(default_factory=list)
    ai_resistance_score: int = 5
    notes: str = ""


@dataclass
class CTFChallenge:
    """Complete CTF challenge."""
    id: str
    name: str
    category: str
    difficulty: str
    points: int
    description: str
    flag: str
    flag_format: str = "flag{...}"
    files: List[str] = field(default_factory=list)
    hints: List[ChallengeHint] = field(default_factory=list)
    solution: Optional[ChallengeSolution] = None
    hardening: Optional[ChallengeHardening] = None
    source_finding: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


class ChallengeGenerator:
    """
    CTF Challenge Generator.
    
    Creates challenges from vulnerability findings or templates.
    """
    
    def __init__(
        self,
        ollama_model: str = None,
        ollama_host: str = None,
    ):
        self.ollama_model = ollama_model or os.environ.get("KATANA_OLLAMA_MODEL", "mistral-nemo")
        self.ollama_host = ollama_host or os.environ.get("KATANA_OLLAMA_HOST", "http://localhost:11434")
    
    def _generate_id(self) -> str:
        """Generate unique challenge ID."""
        return f"chal-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{random.randint(1000, 9999)}"
    
    def _generate_flag(self, keywords: List[str], hardening: AIHardening) -> str:
        """Generate a memorable flag."""
        keyword = random.choice(keywords) if keywords else "ctf"
        
        # Leet speak transformation
        leet_map = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7'}
        leeted = ''.join(leet_map.get(c, c) for c in keyword.lower())
        
        # Add random suffix
        suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        
        flag_content = f"{leeted}_{suffix}"
        
        if hardening == AIHardening.AGGRESSIVE:
            # Add more complexity for aggressive hardening
            flag_content = f"{leeted}_h4rd3n3d_{suffix}"
        
        return f"flag{{{flag_content}}}"
    
    def _generate_hints(
        self,
        vuln_type: str,
        difficulty: Difficulty,
    ) -> List[ChallengeHint]:
        """Generate progressive hints."""
        hints = []
        
        # Base costs by difficulty
        base_costs = {
            Difficulty.EASY: [25, 50, 75],
            Difficulty.MEDIUM: [50, 100, 150],
            Difficulty.HARD: [75, 150, 250],
            Difficulty.INSANE: [100, 200, 350],
        }
        costs = base_costs.get(difficulty, [50, 100, 150])
        
        # Generic hint templates
        hint_templates = [
            "Look at the input handling carefully.",
            f"This is a {vuln_type} vulnerability. Research common exploitation techniques.",
            "The flag is stored in a file called 'flag.txt' on the server.",
        ]
        
        for cost, text in zip(costs, hint_templates):
            hints.append(ChallengeHint(cost=cost, text=text))
        
        return hints
    
    def _apply_hardening(
        self,
        challenge: CTFChallenge,
        hardening_level: AIHardening,
    ) -> CTFChallenge:
        """Apply AI-hardening techniques to the challenge."""
        techniques = AI_HARDENING_TECHNIQUES[hardening_level]
        
        hardening = ChallengeHardening(
            techniques_applied=techniques,
            ai_resistance_score=len(techniques) + 3,
        )
        
        notes = []
        
        if "context_embedding" in techniques:
            notes.append("Flag embedded in realistic application context")
        
        if "red_herrings" in techniques:
            notes.append("Decoy vulnerabilities added to misdirect")
        
        if "multi_step" in techniques:
            notes.append("Requires multiple exploitation steps")
        
        if "visual_elements" in techniques:
            notes.append("Some information presented visually")
        
        if "timing_based" in techniques:
            notes.append("Solution requires specific timing")
        
        if "anti_pattern_injection" in techniques:
            notes.append("False positive patterns added")
        
        if "domain_knowledge" in techniques:
            notes.append("Requires domain-specific knowledge")
        
        hardening.notes = "; ".join(notes)
        challenge.hardening = hardening
        
        return challenge
    
    def _query_llm(self, prompt: str) -> str:
        """Query Ollama for challenge generation."""
        try:
            import requests
            
            response = requests.post(
                f"{self.ollama_host}/api/chat",
                json={
                    "model": self.ollama_model,
                    "messages": [{"role": "user", "content": prompt}],
                    "stream": False,
                },
                timeout=120,
            )
            response.raise_for_status()
            return response.json().get("message", {}).get("content", "")
        except Exception as e:
            logger.error(f"LLM query error: {e}")
            return ""
    
    def generate_from_finding(
        self,
        finding: Dict[str, Any],
        difficulty: Difficulty = Difficulty.MEDIUM,
        ai_hardening: AIHardening = AIHardening.STANDARD,
    ) -> CTFChallenge:
        """Generate challenge from a vulnerability finding."""
        vuln_type = finding.get('vuln_type', 'unknown')
        title = finding.get('title', 'Security Challenge')
        
        # Look up template
        template = CHALLENGE_TEMPLATES.get(vuln_type, {})
        category = template.get('category', Category.WEB)
        
        # Generate name
        name_templates = template.get('name_templates', [title])
        name = random.choice(name_templates)
        
        # Calculate points
        points_range = DIFFICULTY_POINTS[difficulty]
        points = random.randint(points_range[0], points_range[1])
        # Round to nearest 25
        points = round(points / 25) * 25
        
        # Generate description
        desc_templates = template.get('description_templates', [finding.get('description', '')])
        description = random.choice(desc_templates)
        
        # Generate flag
        keywords = template.get('flag_keywords', ['flag', 'ctf'])
        flag = self._generate_flag(keywords, ai_hardening)
        
        # Generate hints
        hints = self._generate_hints(vuln_type, difficulty)
        
        # Create solution
        solution = ChallengeSolution(
            walkthrough=f"""## Solution for {name}

This challenge demonstrates a {vuln_type} vulnerability.

### Step 1: Reconnaissance
Identify the vulnerable endpoint/function.

### Step 2: Exploitation
Use the appropriate technique to exploit the vulnerability.

### Step 3: Flag Retrieval
The flag is: {flag}
""",
            tools_required=["browser", "curl", "python"],
            time_estimate=f"{difficulty.value} difficulty = ~30 min",
        )
        
        challenge = CTFChallenge(
            id=self._generate_id(),
            name=name,
            category=category.value,
            difficulty=difficulty.value,
            points=points,
            description=description,
            flag=flag,
            hints=hints,
            solution=solution,
            source_finding=finding.get('id'),
        )
        
        # Apply hardening
        challenge = self._apply_hardening(challenge, ai_hardening)
        
        return challenge
    
    def generate_from_template(
        self,
        vuln_type: str,
        category: Category = None,
        difficulty: Difficulty = Difficulty.MEDIUM,
        ai_hardening: AIHardening = AIHardening.STANDARD,
    ) -> CTFChallenge:
        """Generate challenge from a vulnerability type template."""
        # Get or create template
        template = CHALLENGE_TEMPLATES.get(vuln_type, {
            "category": category or Category.WEB,
            "name_templates": [f"{vuln_type.replace('_', ' ').title()} Challenge"],
            "description_templates": [f"Exploit the {vuln_type} vulnerability to get the flag."],
            "flag_keywords": [vuln_type.replace('_', '')],
        })
        
        if category is None:
            category = template.get('category', Category.WEB)
        
        # Use LLM to enhance the challenge
        prompt = f"""Create a CTF challenge for the following vulnerability type:

VULNERABILITY TYPE: {vuln_type}
CATEGORY: {category.value}
DIFFICULTY: {difficulty.value}

Generate:
1. A creative challenge name
2. An intriguing description (2-3 sentences, don't reveal the solution)
3. 3 progressive hints

Output as JSON:
{{
    "name": "...",
    "description": "...",
    "hints": ["hint1", "hint2", "hint3"]
}}"""
        
        llm_response = self._query_llm(prompt)
        
        # Try to parse LLM response
        name = random.choice(template.get('name_templates', [f"{vuln_type} Challenge"]))
        description = random.choice(template.get('description_templates', ["Solve this challenge!"]))
        
        try:
            import re
            json_match = re.search(r'\{[\s\S]*\}', llm_response)
            if json_match:
                data = json.loads(json_match.group())
                name = data.get('name', name)
                description = data.get('description', description)
        except (json.JSONDecodeError, AttributeError):
            pass
        
        # Calculate points
        points_range = DIFFICULTY_POINTS[difficulty]
        points = round(random.randint(points_range[0], points_range[1]) / 25) * 25
        
        # Generate flag
        keywords = template.get('flag_keywords', [vuln_type])
        flag = self._generate_flag(keywords, ai_hardening)
        
        # Generate hints
        hints = self._generate_hints(vuln_type, difficulty)
        
        challenge = CTFChallenge(
            id=self._generate_id(),
            name=name,
            category=category.value,
            difficulty=difficulty.value,
            points=points,
            description=description,
            flag=flag,
            hints=hints,
        )
        
        challenge = self._apply_hardening(challenge, ai_hardening)
        
        return challenge


def run(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main entry point for Challenge Generator skill.
    """
    finding = params.get('finding')
    vuln_type = params.get('vuln_type')
    difficulty_str = params.get('difficulty', 'medium')
    category_str = params.get('category')
    ai_hardening_str = params.get('ai_hardening', 'standard')
    
    if not finding and not vuln_type:
        return {
            'status': 'error',
            'message': 'Either finding or vuln_type parameter required',
        }
    
    try:
        difficulty = Difficulty(difficulty_str)
    except ValueError:
        difficulty = Difficulty.MEDIUM
    
    try:
        ai_hardening = AIHardening(ai_hardening_str)
    except ValueError:
        ai_hardening = AIHardening.STANDARD
    
    category = None
    if category_str:
        try:
            category = Category(category_str)
        except ValueError:
            pass
    
    try:
        generator = ChallengeGenerator()
        
        if finding:
            challenge = generator.generate_from_finding(
                finding=finding,
                difficulty=difficulty,
                ai_hardening=ai_hardening,
            )
        else:
            challenge = generator.generate_from_template(
                vuln_type=vuln_type,
                category=category,
                difficulty=difficulty,
                ai_hardening=ai_hardening,
            )
        
        return {
            'status': 'success',
            'challenge': {
                'id': challenge.id,
                'name': challenge.name,
                'category': challenge.category,
                'difficulty': challenge.difficulty,
                'points': challenge.points,
                'description': challenge.description,
                'flag': challenge.flag,
                'flag_format': challenge.flag_format,
                'hints': [asdict(h) for h in challenge.hints],
                'solution': asdict(challenge.solution) if challenge.solution else None,
                'hardening': asdict(challenge.hardening) if challenge.hardening else None,
                'source_finding': challenge.source_finding,
                'created_at': challenge.created_at,
            },
        }
        
    except Exception as e:
        logger.error(f"Challenge generation error: {e}")
        return {
            'status': 'error',
            'message': str(e),
        }


def main():
    """CLI entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description='CTF Challenge Generator CLI')
    parser.add_argument('--vuln-type', '-v', help='Vulnerability type')
    parser.add_argument('--category', '-c',
                        choices=['web', 'pwn', 'crypto', 'forensics', 'reverse', 'misc', 'web3', 'mobile'])
    parser.add_argument('--difficulty', '-d',
                        choices=['easy', 'medium', 'hard', 'insane'],
                        default='medium')
    parser.add_argument('--hardening', choices=['none', 'standard', 'aggressive'], default='standard')
    
    args = parser.parse_args()
    
    if not args.vuln_type:
        print("Error: --vuln-type required")
        sys.exit(1)
    
    result = run({
        'vuln_type': args.vuln_type,
        'category': args.category,
        'difficulty': args.difficulty,
        'ai_hardening': args.hardening,
    })
    
    print(json.dumps(result, indent=2, default=str))


if __name__ == '__main__':
    main()

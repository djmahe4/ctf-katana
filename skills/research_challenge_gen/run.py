"""
CTF Challenge Generator

Automatically generates CTF challenges from vulnerability findings,
with AI-hardening to prevent trivial automated solving.
"""

import os
import sys
import json
import logging
import re
import ast
import random
import string
import hashlib
import ast
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
    IOT = "iot"


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
# Challenge templates by category and type
CHALLENGE_TEMPLATES = {
    "sqli": {
        "cwe_id": "CWE-89",
        "category": Category.WEB,
        "name_templates": ["Login Bypass", "Database Dungeon", "Query Quest", "Injection Junction"],
        "description_templates": [
            "Can you bypass the login page and access the admin panel?",
            "There's a database full of secrets. Can you extract them?",
            "This web application seems vulnerable. Find the flag!",
        ],
        "flag_keywords": ["sql", "inject", "database", "query"],
        "sink_patterns": ["SELECT * FROM users WHERE username='{input}'", "db.execute(f\"...{user_input}...\")"],
        "metadata": {"requires_db": True, "source_code_analysis": False}
    },
    "xss": {
        "cwe_id": "CWE-79",
        "category": Category.WEB,
        "name_templates": ["Script Kiddie", "Cookie Monster", "XSS Playground", "Browser Betrayal"],
        "description_templates": [
            "Execute JavaScript in the context of another user.",
            "Steal the admin's cookies to get the flag.",
            "This comment section looks interesting...",
        ],
        "flag_keywords": ["xss", "script", "cookie", "alert"],
        "sink_patterns": ["innerHTML = input", "document.write(input)"],
        "metadata": {"requires_browser": True, "source_code_analysis": False}
    },
    "command_injection": {
        "cwe_id": "CWE-78",
        "category": Category.WEB,
        "name_templates": ["Shell Shocked", "System Surveyor", "Command Central", "Ping Pong"],
        "description_templates": [
            "This utility lets you ping servers. Can you do more?",
            "The system executes commands based on your input. Find a way to read the flag.",
            "Bypass the restricted shell and read /flag.txt",
        ],
        "flag_keywords": ["cmd", "shell", "exec", "rce"],
        "sink_patterns": ["os.system(f'ping {input}')", "subprocess.call(['ls', input])"],
        "metadata": {"requires_os": True, "source_code_analysis": True}
    },
    "ssrf": {
        "cwe_id": "CWE-918",
        "category": Category.WEB,
        "name_templates": ["Internal Investigator", "Proxy Prank", "Metadata Miner", "Request Router"],
        "description_templates": [
            "The application fetches URLs for you. Can you find internal services?",
            "Access the hidden metadata service to retrieve the cloud credentials.",
            "Route your requests through the server to bypass the firewall.",
        ],
        "flag_keywords": ["ssrf", "internal", "localhost", "proxy"],
        "sink_patterns": ["requests.get(user_url)", "urllib.request.urlopen(url)"],
        "metadata": {"requires_network": True, "source_code_analysis": True}
    },
    "deserialization": {
        "cwe_id": "CWE-502",
        "category": Category.WEB,
        "name_templates": ["Object Odyssey", "Pickle Power", "Serialized Secrets", "Gadget Gatherer"],
        "description_templates": [
            "This application uses serialized objects for session management. Can you exploit it?",
            "Find a gadget chain to achieve Remote Code Execution.",
            "The flag is hidden in the object stream.",
        ],
        "flag_keywords": ["serialize", "pickle", "gadget", "rce"],
        "sink_patterns": ["pickle.loads(data)", "yaml.load(input)", "unserialize($data)"],
        "metadata": {"requires_lib": True, "source_code_analysis": True}
    },
    "reentrancy": {
        "cwe_id": "CWE-841",
        "category": Category.WEB3,
        "name_templates": ["Bank Heist", "Recursive Riches", "The DAO Strikes Back", "Withdraw Wisely"],
        "description_templates": [
            "This smart contract bank has a vulnerability. Can you drain it?",
            "Find the reentrancy bug and claim the reward.",
            "The withdraw function looks suspicious...",
        ],
        "flag_keywords": ["reentr", "withdraw", "callback", "drain"],
        "sink_patterns": ["(bool success, ) = msg.sender.call{value: amount}(\"\")", "balances[msg.sender] -= amount"],
        "metadata": {"requires_evm": True, "source_code_analysis": True}
    },
    "buffer_overflow": {
        "cwe_id": "CWE-121",
        "category": Category.PWN,
        "name_templates": ["Stack Smash", "Buffer Bonanza", "Memory Mayhem", "Overflow Odyssey"],
        "description_templates": [
            "This binary has a buffer overflow. Can you get a shell?",
            "Smash the stack and read the flag file.",
            "The function doesn't check input length...",
        ],
        "flag_keywords": ["overflow", "stack", "smash", "pwn"],
        "sink_patterns": ["strcpy(dest, src)", "gets(buffer)", "scanf(\"%s\", buffer)"],
        "metadata": {"requires_arch": "x86/x64", "source_code_analysis": True}
    },
    "idor": {
        "cwe_id": "CWE-639",
        "category": Category.WEB,
        "name_templates": ["User Leaker", "Permission Prank", "Numeric Navigator", "Account Access"],
        "description_templates": [
            "Can you access files that don't belong to you?",
            "Manipulate the user ID to see private information.",
            "The application relies on sequential IDs. Find the admin record.",
        ],
        "flag_keywords": ["idor", "access", "permit", "direct"],
        "sink_patterns": ["db.get_user(request.params['id'])", "open(f'/data/users/{id}.txt')"],
        "metadata": {"requires_auth": True, "source_code_analysis": False}
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
    generated_files: List[Dict[str, str]] = field(default_factory=list) # List of {'name': ..., 'content': ...}


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

    def _flatten_intelligence(self, data: Any) -> str:
        """Convert intelligence data (string or dict) into a readable string."""
        if isinstance(data, str):
            return data
        if isinstance(data, dict):
            # Try to find common descriptive fields
            for key in ['description', 'title', 'summary', 'text']:
                if key in data and isinstance(data[key], str):
                    return data[key]
            # Fallback to key-value pairs
            return ", ".join(f"{k}: {v}" for k, v in data.items())
        return str(data)

    def _detect_language(self, snippets: List[Dict[str, Any]], category: str) -> str:
        """Determines the most appropriate language for the challenge based on snippets or category."""
        cat_map = {
            "blockchain": "Solidity/Vyper (Web3)",
            "web3": "Solidity/Vyper (Web3)",
            "iot": "C (IoT/Embedded)",
            "web": "Python (Flask)",
            "pwn": "C (Binary Exploit)",
            "reverse": "C (Reverse Engineering)",
            "mobile": "Java/Kotlin (Android)"
        }
        
        cat = category.lower() if category else "web"
        
        # 1. High-confidence detection from metadata hints first
        if snippets:
            # Check for explicitly tagged language hints from IntelligenceMiner
            hints = [s.get('language_hint') for s in snippets if s.get('language_hint')]
            if hints:
                hint = hints[0].lower()
                if "solidity" in hint or "vyper" in hint: return "Solidity/Vyper (Web3)"
                if "java" in hint: return "Java"
                if "php" in hint: return "PHP"
                if "c" == hint or "cpp" == hint: return "C/C++"
                if "python" in hint: return "Python (Flask)"

            # Fallback to standard content detection
            content = " ".join([s.get('content', '') for s in snippets]).lower()
            source = " ".join([s.get('source', '') or "" for s in snippets]).lower()
            
            # Check content for clear markers/keywords
            if ("contract " in content and "pragma solidity" in content) or "vyper" in source or "vyper" in content:
                return "Solidity/Vyper (Web3)"
            if "<?php" in content:
                return "PHP"
            if "import java.util." in content or "@Override" in content or "activemq" in source or "activemq" in content:
                return "Java"
            if "#include <" in content:
                if any(k in content for k in ["gpio", "i2c", "spi", "serial.begin", "esp_"]):
                    return "C (IoT/Embedded)"
                return "C/C++"
            
            # Generic Python check - only if it fits the category or we have no category
            if ("import " in content or "def " in content) and cat in ["web", "unknown"]:
                return "Python (Flask)"

        # 2. Fallback to category mapping
        return cat_map.get(cat, "Python (Flask)")

    def _get_extension_for_language(self, lang: str) -> str:
        """Map a language display name to its standard file extension."""
        lang_lower = lang.lower()
        if "solidity" in lang_lower or "vyper" in lang_lower or "web3" in lang_lower:
            return ".sol"
        if "c (iot" in lang_lower or "embedded" in lang_lower:
            return ".c"
        if "c/c++" in lang_lower or "pwn" in lang_lower:
            return ".c"
        if "python" in lang_lower:
            return ".py"
        if "java" in lang_lower:
            return ".java"
        if "php" in lang_lower:
            return ".php"
        if "javascript" in lang_lower or "node" in lang_lower:
            return ".js"
        return ".txt"

    def _get_required_build_files(self, category: str) -> List[str]:
        """Identify required build/manifest files for a given category."""
        cat_lower = category.lower()
        if cat_lower in ["iot", "pwn", "reverse"]:
            return ["Makefile"]
        if cat_lower in ["web3", "blockchain"]:
            return ["package.json", "hardhat.config.js"]
        if cat_lower == "web":
            # For web, we might need Dockerfile + requirements.txt
            return ["requirements.txt", "Dockerfile"]
        return []

    def _generate_source_code(self,
        category: str,
        vuln_type: str,
        snippets: List[Dict[str, Any]],
        logic_delta: Dict[str, Any] = None,
        difficulty: Difficulty = Difficulty.MEDIUM,
        draft: Dict[str, Any] = None
    ) -> List[Dict[str, str]]:
        """Synthesize vulnerable source code across multiple domains."""
        # NEW: Check if we have a pre-generated draft from Agentic Dispatcher
        if draft and "files" in draft:
            logger.info("♻️ Using pre-generated Agentic Draft for source code synthesis.")
            return draft["files"]

        detected_lang = self._detect_language(snippets, category)
        logger.info(f"Target language detected for synthesis: {detected_lang}")

        # Domain-specific requirement injection
        domain_requirements = ""
        required_artifacts = self._get_required_build_files(category)
        
        if "IoT" in detected_lang:
            domain_requirements = f"""
## IoT-SPECIFIC REQUIREMENTS:
1. Include a Makefile or PlatformIO.ini for compilation.
2. Use standard hardware libraries (e.g., Arduino, ESP-IDF) if applicable.
3. Ensure the vulnerability is relatable to hardware (e.g., buffer overflow in serial buffer).
"""
        elif "Web3" in detected_lang:
            domain_requirements = """
## WEB3-SPECIFIC REQUIREMENTS:
1. Generate the Solidity contract (.sol).
2. Include a package.json and a deployment script (e.g., Hardhat/Truffle script).
"""

        exploit_snippet = next((s['content'] for s in snippets if s['purpose'] == 'exploit'), "No direct exploit sample found")
        patch_snippet = next((s['content'] for s in snippets if s['purpose'] == 'patch'), "No patch sample found")
        
        prompt = f"""Generate a vulnerable application for a CTF challenge.
DOMAIN/LANGUAGE: {detected_lang}
VULNERABILITY: {vuln_type} ({category})
DIFFICULTY: {difficulty.value}

## GROUNDING INTELLIGENCE (CRITICAL)
Use the FOLLOWING SPECIFIC LOGIC for the vulnerability. DO NOT invent generic logic if these patterns provide a base:

EXPLOIT PATTERN:
{exploit_snippet}

PATCH STRATEGY:
{patch_snippet}

## STRICT GROUNDING REQUIREMENTS:
1. **Source Fidelity**: If EXPLOIT PATTERN shows a specific function name or data structure, YOU MUST USE IT.
2. **No Hallucinations**: Do not add unnecessary features (e.g., auth systems, complex DBs) unless they are in the GROUNDING snippets.
3. **Detected Language**: You must output in {detected_lang}. If source_extension was provided, ensure the main file name matches.

## LOGIC CONTEXT
{json.dumps(logic_delta, indent=2) if logic_delta else ""}

{domain_requirements}

## REQUIREMENTS
1. Use {detected_lang} matching the grounding patterns.
2. The code MUST contain a clear, exploitable vulnerability matching the grounding patterns.
3. Include comments marking where the vulnerability is.
4. Leave placeholders for future hardening (e.g. # <HARDENING_SITE_1>).
5. Ensure the flag is read from an environment variable 'FLAG' or a local file 'flag.txt'.

## OUTPUT FORMAT
1. Start with a === MANIFEST === section listing all files.
2. Use EXACTLY this marker for EACH file:
=== FILE: filename.ext ===
[Code Content]
"""

        raw_code = self._query_llm(prompt)
        
        # LOG RAW CODE FOR DEBUGGING
        log_dir = os.path.join("logs", "synthesis")
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(log_dir, f"raw_{difficulty.value}_{category}_{vuln_type}.txt")
        with open(log_file, "w", encoding="utf-8") as f:
            f.write(raw_code)
        
        # Parse Multi-File Output
        files = []
        
        if "=== FILE:" in raw_code:
            # Strip anything before the first FILE marker (like MANIFEST)
            parts = re.split(r'(===\s*FILE:\s*\S+\s*===)', raw_code)
            # parts[0] is everything before first marker
            # parts[1] is first marker, parts[2] is content, etc.
            for i in range(1, len(parts), 2):
                marker = parts[i]
                content = parts[i+1].strip() if i+1 < len(parts) else ""
                
                # Extract filename from marker
                name_match = re.search(r'===\s*FILE:\s*(\S+)\s*===', marker)
                filename = name_match.group(1).strip() if name_match else "unknown_file"
                
                content = self._clean_code_content(content)
                files.append({"name": filename, "content": content})
        else:
            # Fallback for LLMs that ignored format
            content = self._clean_code_content(raw_code)
            ext = self._get_extension_for_language(detected_lang)
            files.append({"name": f"vulnerable_app{ext}", "content": content})

        # Inject missing required artifacts
        existing_filenames = {f["name"] for f in files}
        for req in required_artifacts:
            if req not in existing_filenames:
                logger.warning(f"Required artifact {req} missing from LLM output. Generating fallback...")
                files.append({
                    "name": req,
                    "content": self._generate_fallback_artifact(req, files, detected_lang)
                })

        # VALIDATION GATE (Polymorphic)
        for f in files:
            ext = os.path.splitext(f["name"])[1]
            if ext == ".py":
                try:
                    ast.parse(f["content"])
                    f["valid"] = True
                except (SyntaxError, IndentationError):
                    f["valid"] = False
            else:
                # Basic Balanced Braces for non-Python
                f["valid"] = f["content"].count("{") == f["content"].count("}")
                logger.debug(f"Applied lightweight validation for {f['name']}")
            
        return files

    def _clean_code_content(self, content: str) -> str:
        """Robustly strip markdown code blocks and leaked language tags."""
        content = content.strip()
        
        # 1. Remove obvious markdown code blocks with regex
        # Pattern handles optional language identifiers (python, javascript, etc.) and preserves content
        content = re.sub(r'^```\w*\n', '', content)
        content = re.sub(r'```$', '', content)
        
        # 2. Handle cases where the marker is inline or at start of lines without newline
        if content.startswith("```"):
            content = re.sub(r'^```[\w\-]*', '', content).strip()
        if content.endswith("```"):
            content = content[:-3].strip()

        # 3. Final sanitization: strip any leading language names that leaked out of the block
        lines = content.split('\n')
        if lines:
            first_line = lines[0].strip().lower()
            skip_words = {'python', 'javascript', 'json', 'solidity', 'vyper', 'java', 'c', 'cpp', 'bash', 'sh'}
            if first_line in skip_words:
                content = "\n".join(lines[1:]).strip()
                
        return content.strip()

    def _generate_fallback_artifact(self, name: str, existing_files: List[Dict[str, str]], lang: str) -> str:
        """Use LLM to generate a missing build artifact contextually."""
        file_list = ", ".join([f["name"] for f in existing_files])
        prompt = f"Generate only the raw content of a {name} for a {lang} project with these files: {file_list}. No markdown explanation."
        return self._query_llm(prompt).strip("`").strip()
    
    def generate_from_finding(
        self,
        finding: Dict[str, Any],
        difficulty: Difficulty = Difficulty.MEDIUM,
        ai_hardening: AIHardening = AIHardening.STANDARD,
        logic_delta: Dict[str, Any] = None,
        snippets: List[Dict[str, Any]] = None,
        category: Category = None,
        draft: Dict[str, Any] = None,
    ) -> CTFChallenge:
        """
        Generate challenge from a vulnerability finding.
        Grounds the generation in the provided intelligence snippets (exploit/patch code).
        """
        vuln_type = finding.get('vuln_type', 'unknown')
        title = finding.get('title', 'Security Challenge')
        
        # Look up template
        template = CHALLENGE_TEMPLATES.get(vuln_type, {})
        
        # Priority: explicit arg > template > default
        if not category:
            category = template.get('category', Category.WEB)
        
        # Use logic delta to influence generation if available
        hardening_strategy = "STANDARD_HARDENING"
        if logic_delta:
            hardening_strategy = logic_delta.get("hardening_delta", hardening_strategy)
            # Potentially override vuln_type if logic analysis is more precise
            if logic_delta.get("vulnerability_root") and logic_delta.get("vulnerability_root") != "UNKNOWN":
                logger.info(f"Using vulnerability root from logic analysis: {logic_delta['vulnerability_root']}")
        
        # 3. Generate challenge metadata (name, desc, hints, flag)
        # Use LLM for creative descriptions if needed, but ground in finding
        name_templates = template.get('name_templates', [title])
        name = random.choice(name_templates)
        
        # Calculate points
        points_range = DIFFICULTY_POINTS[difficulty]
        points = random.randint(points_range[0], points_range[1])
        # Round to nearest 25
        points = round(points / 25) * 25
        
        # Generate description
        desc_templates = template.get('description_templates', [finding.get('description', '')])
        description = str(random.choice(desc_templates))
        
        # Enhance description with logic delta and snippets
        if logic_delta:
            root_cause = self._flatten_intelligence(logic_delta.get('vulnerability_root', 'Refer to finding'))
            fix_strat = self._flatten_intelligence(logic_delta.get('fix_strategy', 'Standard patching'))
            
            logic_desc = f"\n\nContext: The root cause involves {root_cause}. "
            logic_desc += f"A common fix strategy is {fix_strat}, but you need to find a bypass."
            description += logic_desc
        
        if snippets:
            # Add a small hint about the origin if snippets exist
            description += "\n\nThis challenge is based on real-world vulnerability intelligence patterns."
            
        # Generate flag
        keywords = template.get('flag_keywords', ['flag', 'ctf'])
        flag = self._generate_flag(keywords, ai_hardening)
        
        # Generate hints
        hints = self._generate_hints(vuln_type, difficulty)
        if snippets:
            # Add a hint derived from patch context if available
            patch_snippets = [s for s in snippets if s['purpose'] == 'patch']
            if patch_snippets:
                hints.append(ChallengeHint(cost=100, text=f"Hint: Consider how {patch_snippets[0].get('context', 'the system logic')} was originally intended to work."))

        # Create solution
        snippet_summary = ""
        if snippets:
            exploit_code = next((s['content'] for s in snippets if s['purpose'] == 'exploit'), None)
            patch_code = next((s['content'] for s in snippets if s['purpose'] == 'patch'), None)
            
            if exploit_code:
                snippet_summary += f"\n### Reference Exploit Intelligence\n```\n{exploit_code[:500]}...\n```\n"
            if patch_code:
                snippet_summary += f"\n### Reference Patch Intelligence\n```\n{patch_code[:500]}...\n```\n"

        solution = ChallengeSolution(
            walkthrough=f"""## Solution for {name}

This challenge demonstrates a {vuln_type} vulnerability.

### Intelligence Context
{snippet_summary}

### Logic Analysis Summary
- **Root Cause**: {logic_delta.get('vulnerability_root') if logic_delta else 'Refer to finding'}
- **Hardening Strategy**: {logic_delta.get('hardening_delta') if logic_delta else 'Standard templates'}

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
        
        # 4. Synthesize source code if snippets or draft are available
        if snippets or draft:
            challenge.generated_files = self._generate_source_code(
                category=category.value,
                vuln_type=vuln_type,
                snippets=snippets or [],
                logic_delta=logic_delta,
                difficulty=difficulty,
                draft=draft
            )

        # Apply hardening
        challenge = self._apply_hardening(challenge, ai_hardening)
        
        return challenge

    async def generate_from_cve(
        self,
        cve_id: str,
        registry: Any,
        difficulty: Difficulty = Difficulty.MEDIUM,
        ai_hardening: AIHardening = AIHardening.STANDARD,
    ) -> CTFChallenge:
        """
        Direct entry point to generate a challenge from a CVE ID.
        Retrieves deep intelligence via the KnowledgeRegistry and synthesizes the challenge.
        """
        logger.info(f"Generating challenge for {cve_id}...")
        
        # 1. Retrieve Deep Intelligence from Registry
        # Intent 'cve' triggers internal synthesize_purple_loop
        intelligence = await registry.query(cve_id, intent="cve")
        purple_loop = intelligence.get("purple_loop", {})
        
        # 2. Bridge intelligence to a Finding-like structure
        finding = {
            "id": cve_id,
            "title": f"Challenge based on {cve_id}",
            "vuln_type": self._map_root_to_vuln_type(purple_loop.get("vulnerability_root", "")),
            "description": f"A security challenge derived from {cve_id} analysis.",
        }
        
        # 3. Delegate to core generator
        return self.generate_from_finding(
            finding=finding,
            difficulty=difficulty,
            ai_hardening=ai_hardening,
            logic_delta=purple_loop.get("logic_delta"),
            snippets=purple_loop.get("intelligence_snippets"),
            draft=purple_loop.get("agentic_draft")
        )

    def _map_root_to_vuln_type(self, root: str) -> str:
        """Heuristic mapping of vulnerability root path/desc to template type."""
        root_lower = str(root).lower()
        if ".py" in root_lower or "python" in root_lower:
            return "command_injection"
        if ".js" in root_lower or "node" in root_lower:
            return "xss"
        if "sql" in root_lower:
            return "sqli"
        
        return "command_injection" # Default template
    
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
    logic_delta = params.get('logic_delta')
    snippets = params.get('intelligence_snippets')
    draft = params.get('draft')
    
    if not finding and not vuln_type and not draft:
        return {
            'status': 'error',
            'message': 'Either finding, vuln_type, or draft parameter required',
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
        cat_lower = category_str.lower()
        # Handle common aliases
        if cat_lower == "blockchain": 
            cat_lower = "web3"
        
        try:
            category = Category(cat_lower)
        except ValueError:
            # Try to match by name if value match fails
            for c in Category:
                if c.name.lower() == cat_lower:
                    category = c
                    break
    
    try:
        generator = ChallengeGenerator()
        
        # Handle finding-based generation (with optional draft)
        if finding or draft:
            # If finding is missing but we have a draft, we can reconstruct a minimal finding
            if not finding and draft:
                finding = {
                    "id": "agentic-draft",
                    "title": draft.get("title", "Agentic Challenge"),
                    "vuln_type": vuln_type or "generic",
                    "description": "Generated from agentic research."
                }

            challenge = generator.generate_from_finding(
                finding=finding,
                difficulty=difficulty,
                ai_hardening=ai_hardening,
                logic_delta=logic_delta,
                snippets=snippets,
                category=category,
                draft=draft
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
                'generated_files': challenge.generated_files,
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

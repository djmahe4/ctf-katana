import re
from typing import List, Tuple

# Solidity reentrancy vulnerability patterns
PATTERNS = [
    # External call patterns
    (r'\.call\{.*value.*\}\s*\(', "External call with value transfer"),
    (r'\.transfer\s*\(', "Transfer that could trigger fallback"),
    (r'\.send\s*\(', "Send that could trigger fallback"),
    # State after call
    (r'(\.call|\.transfer|\.send)[^;]*;[^}]*\w+\s*=', "State update after external call"),
]

def check(content: str) -> List[dict]:
    """
    Check for reentrancy vulnerabilities in Solidity code.
    """
    results = []
    lines = content.split('\n')
    for pattern, description in PATTERNS:
        for line_num, line in enumerate(lines, 1):
            if re.search(pattern, line, re.IGNORECASE):
                results.append({
                    "line": line_num,
                    "description": description,
                    "pattern": line.strip()[:100],
                    "severity": "CRITICAL"
                })
    return results

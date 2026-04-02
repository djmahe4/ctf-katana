import re
from typing import List

# Solidity accounting/integer vulnerability patterns
PATTERNS = [
    # Pre-0.8.0 unchecked math
    {
        "pattern": r'pragma solidity\s*[<^]?\s*0\.[0-7]',
        "description": "Legacy Solidity version (< 0.8.0) without native overflow protection",
        "severity": "HIGH"
    },
    # Unchecked blocks in 0.8+
    {
        "pattern": r'unchecked\s*\{',
        "description": "Explicit 'unchecked' block found (manual validation required)",
        "severity": "MEDIUM"
    },
    # Division before multiplication
    {
        "pattern": r'\w+\s*/\s*\w+\s*\*\s*\w+',
        "description": "Potential precision loss: Division before multiplication",
        "severity": "MEDIUM"
    },
]

def check(content: str) -> List[dict]:
    """
    Check for accounting and integer vulnerabilities in Solidity.
    """
    results = []
    lines = content.split('\n')
    for p in PATTERNS:
        pattern = p["pattern"]
        description = p["description"]
        for line_num, line in enumerate(lines, 1):
            if re.search(pattern, line, re.IGNORECASE):
                results.append({
                    "line": line_num,
                    "description": description,
                    "pattern": line.strip()[:100],
                    "severity": p["severity"]
                })
    return results

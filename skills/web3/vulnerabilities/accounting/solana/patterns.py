import re
from typing import List

# Solana integer arithmetic security patterns
PATTERNS = [
    {
        "pattern": r'\b(\w+)\s*([+\-*])\s*(\w+)\b(?!.(checked|saturating|wrapping)_)',
        "description": "Unchecked arithmetic operation (+, -, *) (potential overflow/underflow)",
        "severity": "HIGH"
    }
]

def check(content: str) -> List[dict]:
    """
    Check for integer overflow/underflow in Solana/Rust code.
    """
    results = []
    lines = content.split('\n')
    for p in PATTERNS:
        pattern = p["pattern"]
        description = p["description"]
        for line_num, line in enumerate(lines, 1):
            if re.search(pattern, line):
                results.append({
                    "line": line_num,
                    "description": description,
                    "pattern": line.strip()[:100],
                    "severity": p["severity"]
                })
    return results

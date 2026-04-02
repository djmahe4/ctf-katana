import re
from typing import List

# Algorand/TEAL arithmetic security patterns
PATTERNS = [
    {
        "pattern": r'\b(\w+)\s*/\s*(\w+)\s*\*\s*(\w+)\b',
        "description": "Division before multiplication (precision loss in integer-only arithmetic)",
        "severity": "MEDIUM"
    },
    {
        "pattern": r'div\s+mul',
        "description": "Raw TEAL: div followed by mul opcode (potential precision loss)",
        "severity": "MEDIUM"
    }
]

def check(content: str) -> List[dict]:
    """
    Check for precision loss in Algorand/TEAL code.
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

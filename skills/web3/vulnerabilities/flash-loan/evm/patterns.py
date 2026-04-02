import re
from typing import List

# Solidity flash-loan/oracle vulnerability patterns
PATTERNS = [
    # Price calculation from pool
    {
        "pattern": r'reserve[01]\s*/\s*reserve[10]',
        "description": "Direct reserve ratio price calculation (Flash loan manipulation vector)",
        "severity": "CRITICAL"
    },
    {
        "pattern": r'getReserves\(\)',
        "description": "Using raw pool reserves for price (Vulnerable to oracle manipulation)",
        "severity": "CRITICAL"
    },
    # Single-block price
    {
        "pattern": r'block\.timestamp',
        "description": "Timestamp dependency (Potential for single-block manipulation)",
        "severity": "MEDIUM"
    },
]

def check(content: str) -> List[dict]:
    """
    Check for flash loan and oracle vulnerabilities in Solidity.
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

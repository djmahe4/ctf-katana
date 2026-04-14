import re
from typing import List

# Solana reentrancy (CPI) vulnerability patterns
PATTERNS = [
    {
        "pattern": r'\b(token::transfer|system_instruction::transfer|program::invoke|program::invoke_signed)!\s*\(',
        "description": "Direct cross-program invocation or token transfer (potential reentrancy if state not updated first)",
        "severity": "HIGH"
    }
]

def check(content: str) -> List[dict]:
    """
    Check for reentrancy (CPI) vulnerabilities in Solana/Rust code.
    """
    results = []
    lines = content.split('\n')
    for p in PATTERNS:
        pattern = p["pattern"]
        description = p["description"]
        severity = p["severity"]
        for line_num, line in enumerate(lines, 1):
            if re.search(pattern, line):
                results.append({
                    "line": line_num,
                    "description": description,
                    "pattern": line.strip()[:100],
                    "severity": severity
                })
    return results

import re
from typing import List

# Algorand flash-loan and oracle manipulation patterns
PATTERNS = [
    {
        "pattern": r'app_global_get\s+\w+\s+btoi\s+(?!.*(global\s+latest_timestamp))',
        "description": "Global state price read without latest_timestamp check (stale oracle)",
        "severity": "HIGH"
    },
    {
        "pattern": r'(asset_holding_get|app_global_get)\s+\w+\s+get\s+(div|mul|/|*)\s+(asset_holding_get|app_global_get|int|byte)',
        "description": "Price calculation via reserves (susceptible to group manipulation)",
        "severity": "HIGH"
    },
    {
        "pattern": r'itxn_field\s+TypeEnum\s+int\s+axfer\s+itxn_submit',
        "description": "Inner asset transfer (itxn.axfer) detected - likely flash loan issuance",
        "severity": "INFO"
    },
    {
        "pattern": r'txn\s+AssetAmount\s+(?:.*)\s+(?:==|!=|gt|lt|ge|le)',
        "description": "Flash loan repayment validation or loan amount check",
        "severity": "HIGH"
    }
]

def check(content: str) -> List[dict]:
    """
    Check for flash loan and oracle manipulation in Algorand/TEAL code.
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

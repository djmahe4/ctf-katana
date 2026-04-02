import re
from typing import List

# Algorand reentrancy (Group-Reentrancy/Atomic) vulnerability patterns
PATTERNS = [
    {
        "pattern": r'\bGtxn\[\d+\]\.(sender|type_enum|asset_id|application_id|amount|receiver|close_remainder_to|asset_amount|asset_receiver|asset_close_to|on_completion)\b',
        "description": "Flags transaction grouping properties. A high-fidelity scanner must then verify that `Global.group_size()` and `Txn.group_index()` are correctly checked to prevent single-transaction attacks or reordering.",
        "severity": "HIGH"
    },
    {
        "pattern": r'gtxn\s+\d+\s+(sender|typeenum|xfer_asset|application_id|amount|receiver|asset_receiver|asset_amount|asset_close_to)',
        "description": "Flags raw TEAL code accessing other transactions in a group. A high-fidelity scanner must then verify that `gsize` and `gtxn 0 GroupIndex` are correctly checked to prevent reordering or single-transaction bypass.",
        "severity": "HIGH"
    },
     {
        "pattern": r'(App\.globalPut|App\.localPut|InnerTxnBuilder\.SetFields)\(',
        "description": "Flags state modifications. These sensitive operations often require robust authorization checks (e.g., `Txn.sender() == Global.creator_address()` or specific `Txn.group_index()` roles) to prevent unauthorized access or state manipulation.",
        "severity": "HIGH"
    }
]

def check(content: str) -> List[dict]:
    """
    Check for reentrancy (Group/Atomic logic) vulnerabilities in Algorand/TEAL code.
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

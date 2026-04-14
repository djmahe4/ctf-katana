import re
from typing import List

# Solana flash-loan and oracle manipulation patterns
PATTERNS = [
    {
        "pattern": r'(pyth_sdk_solana::load_price_feed_from_account_info|pyth_sdk_solana::get_price_feed_from_account_info)\s*\.\s*(get_price_unchecked|get_ema_price_unchecked)',
        "description": "Direct use of Pyth 'unchecked' price methods (vulnerable to stale or unreliable feeds)",
        "severity": "HIGH"
    },
    {
        "pattern": r'(switchboard_v2::AggregatorAccountData::new|switchboard_v2::AggregatorAccountData::load).*;\s*(?!.*(last_round_timestamp))',
        "description": "Switchboard data loaded without staleness check (last_round_timestamp)",
        "severity": "MEDIUM"
    },
    {
        "pattern": r'(spl_token::state::Account|anchor_spl::token::TokenAccount)\s*\.\s*amount\s*/\s*(spl_token::state::Account|anchor_spl::token::TokenAccount)\s*\.\s*amount',
        "description": "Direct price calculation via pool balances (vulnerable to sandwich attacks)",
        "severity": "HIGH"
    }
]

def check(content: str) -> List[dict]:
    """
    Check for flash loan and oracle manipulation in Solana/Rust code.
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

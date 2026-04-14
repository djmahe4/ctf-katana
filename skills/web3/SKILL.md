---
name: web3-analyzer
version: "2.0.0"
description: Multi-Chain Smart Contract Security Swarm for Ethereum, Solana, and Algorand.
risk: high
source: local
---

# Web3 Security Swarm

Expert multi-chain smart contract security analysis tool.

## Capabilities
- **Multi-Chain Analysis**: Specialized handlers for Ethereum (Solidity), Solana (Rust/Anchor), and Algorand (TEAL).
- **Domain Engines**: Modular vulnerability detection for reentrancy, flash loans, and accounting logic.
- **Deep Audit**: Automated detection of critical bugs, logic errors, and integration risks.

## Usage

### Analysis
To analyze a smart contract:
```bash
python orchestrator.py <target> --chain <ethereum|solana|algorand> --mode <full|reentrancy|flash_loan|accounting>
```

### New Chain Support
Adding a new blockchain is simple:
1. Create a `handlers/<chain>_handler.py`.
2. Add a `<chain>/patterns.py` to each vulnerability module in `vulnerabilities/`.

## Architecture
- `orchestrator.py`: Main entry point and chain router.
- `handlers/`: Chain-specific logic and environment setup.
- `vulnerabilities/`: Cross-chain vulnerability domain modules.

## Triggers
- `analyze this smart contract`
- `check ethereum contract <address>`
- `audit solana program <path>`
- `scan algorand teal for rounding errors`

## Economically-Incentivized Auditing

> [!IMPORTANT]
> Think beyond simple code bugs; consider game theory, oracle manipulation, and cross-chain MEV opportunities. Assume the attacker has maximal resources and understands the deepest implications of multi-chain execution and protocol design.

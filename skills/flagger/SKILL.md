---
name: flagger
description: Anti-AI Flag Hardening & Poisoning. Tiered obfuscation and prompt injections to protect CTF flags from AI solvers. 
risk: low
source: local
---

# Flagger (Anti-AI Hardening)

This skill provides a unified workflow for hardening flags against AI prediction and automated solving using multi-layer obfuscation and anti-AI poisoning.

## Core Capabilities

- **Multi-layer Obfuscation**: Chained transformations (XOR, ROT, Base64, Opcodes) that require human intuition to reverse.
- **Anti-AI Poisoning**: Inert prompt injections and safety-filter triggers designed to confuse LLMs or cause them to refuse solving the challenge.
- **Tiered Intensity**:
  - **Moderate**: Subtle misdirection.
  - **Difficult**: Heavy obfuscation and aggressive poisoning.
  - **Expert**: AI-Refusal territory (Opcode mapping + contextual deception).

## Mandatory Context

- `Flag`: The original flag string (e.g., `CTF{...}`).
- `Level`: (`moderate`, `difficult`, `expert`).
- `Handler`: (`reverse`, `web`).

## Modular Architecture

The skill uses a handler-based orchestration pattern:
1. `Obfuscators`: Reversible transformations.
2. `Poisoners`: Anti-AI string generators.
3. `Handlers`: Embedding logic for specific challenge types.

## Execution Workflow

Generate a hardened Python challenge from a flag:
```bash
python skills/flagger/run.py "CTF{hArD_flAg_123}" --level difficult --handler reverse --template python
```

The output will contain:
- Obfuscated flag data.
- Reconstruction logic (as Python code).
- Anti-AI prompt injections (as comments).

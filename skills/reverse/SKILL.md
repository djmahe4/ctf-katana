---
name: reverse
description: Logic Architect: Bi-directional Logic RE & Challenge Synthesis. Uses 'Creator Thinking' to reverse logic and 'Attacker Thinking' to create challenges.
risk: low
source: local
---

# Logic Architect (Reverse v2)

This skill provides a unified orchestration layer for high-level logic analysis and synthesis across modern development environments (Solidity, Python, C, etc.).

## Core Capabilities

- **Logic Analysis (RE-Logic)**: Uses "Think like a creator" to identify intended vulnerability patterns, flags, and hidden secrets from code or decompiled snippets.
- **Challenge Synthesis (Challenge-Gen)**: Transforms vulnerability patterns into complete, pedagogical, and secure CTF challenges.
- **Bi-directional Synergy**: Leverages offensive RE insights from the **Binary Analyst** (`@reverse_engineering`) to build more resilient challenges and uses "Creator Thinking" to break complex logic.

## Mandatory Context

- `Target`: URL, Local File, or Snippet.
- `Mode`: (`offensive`, `synthesis`, `synergy`).
- `Action`: (`analyze`, `create`, `think`).
- `Vuln_ID`: (For synthesis) Target vulnerability ID from a source skill.

## Modular Architecture

The skill follows a handler-based orchestration pattern:
1. `LogicHandler`: Offensive logic extraction.
2. `SynthesisHandler`: Defensive challenge creation.
3. `REDesigner`: LLM-powered engine for "Thinking" and strategy brainstorming.

## Execution Workflow

1. **Strategy Design**: `python skills/reverse/run.py --action think --prompt "..."` to brainstorm RE or synthesis plans.
2. **Logic Extraction**: `python skills/reverse/run.py "import flag; ..." --action analyze` to find hidden flags.
3. **Challenge Generation**: `python skills/reverse/run.py --vuln_id "reentrancy" --action create` to generate a vulnerable Solidity challenge.

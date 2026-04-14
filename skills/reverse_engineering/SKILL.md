---
name: reverse_engineering
description: Binary Analyst: Technical Analysis (ELF/PE/ASM) & Technique-to-Logic Mapping. Analyzes disassembly, symbols, and headers.
risk: medium
source: local
---

# Binary Analyst (ReverseEngineering v2)

This skill provides a technical layer for analyzing compiled artifacts (ELF, PE, WASM) and instruction streams.

## Core Capabilities

- **Binary Analysis (RE-Technique)**: Disassembly, Symbol extraction, Header inspection (NX/PIE/RELRO).
- **Technique-to-Logic Mapping**: Uses LLMs (`free-llm-apis`) to interpret raw assembly instructions and control flow into high-level business logic.
- **Technical Synergy**: Leverages logic patterns from the **Logic Architect** (`@reverse`) to find specific vulnerabilities and gadgets.

## Mandatory Context

- `Path`: Path to the local binary file.
- `Action`: (`disassemble`, `symbols`, `elf_info`, `think`).

## Modular Architecture

The skill follows a handler-based orchestration pattern:
1. `BinaryHandler`: Technical extraction tools.
2. `TechDesigner`: LLM-powered engine for "Thinking" and technique-to-logic interpretation.

## Execution Workflow

1. **Information Gathering**: `python skills/reverse_engineering/run.py /bin/ls --action disassemble` to get code.
2. **Technique Design**: `python skills/reverse_engineering/run.py --action think --prompt "..."` to design a technical RE strategy.
3. **Symbol Analysis**: `python skills/reverse_engineering/run.py /bin/ls --action symbols` to see function entry points.

# Architecture

This document describes the internal design of the CTF-Katana agentic AI
system – an MCP server that orchestrates Ollama-backed agents and skill tools
to solve Capture-The-Flag challenges.

## System Overview

```
┌──────────────────────────────────────────────────────────────┐
│                     MCP Client (LLM host)                    │
│          e.g. Claude Desktop, VS Code Copilot, CLI           │
└──────────────────────┬───────────────────────────────────────┘
                       │  Model Context Protocol (stdio)
┌──────────────────────▼───────────────────────────────────────┐
│                   Katana MCP Server                          │
│                                                              │
│  ┌──────────┐  ┌──────────┐  ┌───────────────────────────┐  │
│  │Resources │  │ Prompts  │  │         39 Tools           │  │
│  │ (3)      │  │ (2)      │  │                            │  │
│  │ summary  │  │ analyze  │  │ ┌────────┐ ┌────────────┐ │  │
│  │ sections │  │ solve    │  │ │ Skills │ │Agent tools │ │  │
│  │ categories│  │          │  │ │ (35)   │ │ (4, async) │ │  │
│  └──────────┘  └──────────┘  │ └───┬────┘ └─────┬──────┘ │  │
│                              │     │             │        │  │
│                              └─────┼─────────────┼────────┘  │
│                                    │             │           │
│  ┌─────────────────────────────────▼─┐ ┌────────▼────────┐  │
│  │         Skill Modules             │ │  Agent Layer     │  │
│  │  analysis · crypto · stego        │ │  (Ollama LLM)   │  │
│  │  forensics · web · reversing      │ │                  │  │
│  │  pwn · recon                      │ │  Analyzer        │  │
│  │                                   │ │  Planner         │  │
│  │  Pure functions + subprocess      │ │  Executor        │  │
│  │  wrappers for external tools      │ │  Reporter        │  │
│  └─────────────────┬─────────────────┘ └────────┬─────────┘  │
│                    │                            │            │
│  ┌─────────────────▼────────────────────────────▼─────────┐  │
│  │              Knowledge Base (README.md)                 │  │
│  │  33 sections · 208 entries · 10 categories              │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

## Components

### MCP Server (`src/katana/server.py`)

The central entry point.  Built with
[FastMCP](https://github.com/modelcontextprotocol/python-sdk), it exposes
**resources**, **prompts**, and **tools** over the Model Context Protocol's
stdio transport.

| Surface  | Count | Purpose |
|----------|------:|---------|
| Resources | 3 | Read-only knowledge-base views (summary, section list, categories) |
| Prompts   | 2 | Pre-built templates: `analyze_challenge`, `solve_challenge` |
| Tools     | 39 | Callable skill functions + agent orchestration endpoints |

**Environment variables** (all optional):

| Variable | Default | Description |
|----------|---------|-------------|
| `KATANA_OLLAMA_MODEL` | `mistral` | Ollama model used by agents |
| `KATANA_OLLAMA_HOST`  | `http://localhost:11434` | Ollama server URL |

### Knowledge Base (`src/katana/knowledge_base.py`)

Parses the repository's `README.md` at server startup into a structured,
in-memory store:

* **KnowledgeSection** – one per README heading (e.g. *Cryptography*,
  *Steganography*).
* **KnowledgeEntry** – one per bullet point inside a section, containing a
  tool name, description, example commands, and URLs.
* **Category mapping** – normalises 33 section titles into 10 canonical
  categories: `crypto`, `stego`, `forensics`, `web`, `pwn`, `reversing`,
  `recon`, `exploitation`, `networking`, `misc`.

The knowledge base powers the `search_knowledge`, `get_knowledge_section`, and
`list_knowledge_categories` tools, giving agents instant access to the
community's collected CTF wisdom.

### Skill Modules (`src/katana/skills/`)

Each module is a collection of pure functions – no state, no LLM calls.  They
either perform computation directly (crypto, analysis) or shell out to
well-known external tools (steghide, binwalk, nmap, …) via safe subprocess
wrappers.

| Module | Examples |
|--------|----------|
| `analysis` | `analyze_file`, `identify_encoding` |
| `crypto` | `rot13`, `caesar`, `xor_bruteforce`, `vigenere_decrypt`, `base64_decode` |
| `stego` | `run_strings`, `run_exiftool`, `run_binwalk`, `run_steghide_extract` |
| `forensics` | `run_foremost`, `check_file_magic`, `pdf_to_text`, `run_pngcheck` |
| `web` | `check_headers`, `check_robots_txt`, `decode_jwt` |
| `reversing` | `disassemble`, `show_symbols`, `show_elf_info` |
| `pwn` | `checksec`, `find_rop_gadgets`, `pattern_create` |
| `recon` | `nmap_scan`, `whois_lookup`, `dig_lookup` |

### Agent Layer (`src/katana/agents/`)

Four specialised agents, each backed by an Ollama model, handle reasoning
tasks that require natural-language understanding:

| Agent | Responsibility | Key method |
|-------|---------------|------------|
| **AnalyzerAgent** | Inspect an artifact, classify its CTF category, list observations and suggested tools | `analyze()` / `aanalyze()` |
| **PlannerAgent** | Produce a numbered, step-by-step solving plan with tool names and arguments | `plan()` / `aplan()` |
| **ExecutorAgent** | Interpret tool output, decide whether to continue/retry/finish, detect flags | `interpret()` / `ainterpret()` |
| **ReporterAgent** | Generate a Markdown write-up and optional Python exploit PoC | `generate()` / `agenerate()` |

All agents inherit from `BaseAgent`, which wraps the Ollama Python client with
conversation-history management and JSON-response parsing.

## Solving Workflow

A typical end-to-end challenge solve follows this loop:

```
         ┌──────────────┐
         │ 1. Analyze    │  agent_analyze(artifact_path)
         │    artifact   │  → file type, category, observations
         └──────┬───────┘
                │
         ┌──────▼───────┐
         │ 2. Search KB  │  search_knowledge(query)
         │    for tips   │  → relevant tools & techniques
         └──────┬───────┘
                │
         ┌──────▼───────┐
         │ 3. Plan       │  agent_plan(analysis_json)
         │    strategy   │  → ordered list of steps
         └──────┬───────┘
                │
         ┌──────▼───────┐
         │ 4. Execute    │  skill tools (crypto_*, stego_*, …)
    ┌───►│    steps      │  → raw tool output
    │    └──────┬───────┘
    │           │
    │    ┌──────▼───────┐
    │    │ 5. Interpret  │  agent_interpret(step, output)
    │    │    results    │  → continue / retry / done
    │    └──────┬───────┘
    │           │
    │     ┌─────┴─────┐
    │     │           │
    │  continue     done
    │     │           │
    └─────┘    ┌──────▼───────┐
               │ 6. Report    │  agent_report(execution_log)
               │    write-up  │  → markdown + exploit PoC
               └──────────────┘
```

1. **Analyze** – `agent_analyze` inspects the challenge file (magic bytes, hex
   dump, encoding detection) and asks Ollama to classify it.
2. **Search** – The knowledge base is searched for techniques relevant to the
   detected category.
3. **Plan** – `agent_plan` receives the analysis and knowledge context and
   produces a numbered step list.
4. **Execute** – Each plan step maps to one or more skill tools (e.g.
   `crypto_caesar_bruteforce`, `stego_steghide`).
5. **Interpret** – `agent_interpret` reviews each tool's output and decides
   whether to proceed, retry with different parameters, or declare success.
6. **Report** – `agent_report` compiles the full execution log into a polished
   write-up and, where applicable, a proof-of-concept exploit script.

## Directory Layout

```
.
├── README.md                  # Living knowledge base (original Katana content)
├── docs/
│   └── ARCHITECTURE.md        # This file
├── pyproject.toml             # Project metadata & entry-point
├── requirements.txt           # Pinned runtime dependencies
├── src/katana/
│   ├── __init__.py
│   ├── __main__.py            # python -m katana
│   ├── server.py              # MCP server definition
│   ├── knowledge_base.py      # README parser
│   ├── agents/
│   │   ├── base.py            # BaseAgent (Ollama wrapper)
│   │   ├── analyzer.py        # AnalyzerAgent
│   │   ├── planner.py         # PlannerAgent
│   │   ├── executor.py        # ExecutorAgent
│   │   └── reporter.py        # ReporterAgent
│   ├── skills/
│   │   ├── analysis.py        # File analysis
│   │   ├── crypto.py          # Cryptography
│   │   ├── stego.py           # Steganography
│   │   ├── forensics.py       # Forensics
│   │   ├── web.py             # Web exploitation
│   │   ├── reversing.py       # Reverse engineering
│   │   ├── pwn.py             # Binary exploitation
│   │   └── recon.py           # Reconnaissance
│   └── utils/
│       └── __init__.py        # Subprocess helpers, hex dump, file I/O
└── tests/
    ├── test_knowledge_base.py
    ├── test_server.py
    └── test_skills/
        └── test_crypto.py
```

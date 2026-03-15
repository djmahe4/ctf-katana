# Architecture

This document describes the internal design of the CTF-Katana agentic AI
system – an MCP server that orchestrates Ollama-backed agents and Claude-style
skills to solve Capture-The-Flag challenges.

## System Overview

```
┌──────────────────────────────────────────────────────────────┐
│                     MCP Client (LLM host)                    │
│          e.g. Claude Desktop, VS Code Copilot, CLI           │
└──────────────────────┬───────────────────────────────────────┘
                       │  Model Context Protocol (stdio)
┌──────────────────────▼───────────────────────────────────────┐
│                   Katana MCP Server                          │
│                   server/mcp_server.py                       │
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
│  ┌──────────────┐ ┌───────────────▼─┐ ┌────────▼────────┐  │
│  │   Registry    │ │     Skills      │ │  Agent Layer     │  │
│  │  (discovery)  │ │  (10 skills,    │ │  (Ollama LLM)   │  │
│  │  server/      │ │   each with     │ │                  │  │
│  │  registry.py  │ │   skill.yaml    │ │  Analyzer        │  │
│  │               │ │   prompt.md     │ │  Planner         │  │
│  │  reads YAML   │ │   run.py)       │ │  Executor        │  │
│  │  loads run()  │ │                 │ │  Reporter        │  │
│  └──────────────┘ └────────┬────────┘ └────────┬─────────┘  │
│                            │                    │            │
│  ┌─────────────────────────▼────────────────────▼─────────┐  │
│  │            Context: Knowledge Base (README.md)          │  │
│  │  33 sections · 208 entries · 10 categories              │  │
│  │  context/knowledge_base.py                              │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐  │
│  │            Tool Wrappers  (tools/)                      │  │
│  │  nmap · binwalk · steghide · exiftool · objdump · …    │  │
│  │  Thin subprocess wrappers called by skills              │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

## Components

### 1. MCP Server (`server/mcp_server.py`)

The central entry point.  Built with
[FastMCP](https://github.com/modelcontextprotocol/python-sdk), it exposes
**resources**, **prompts**, and **tools** over the Model Context Protocol's
stdio transport.

| Surface  | Count | Purpose |
|----------|------:|---------|
| Resources | 3 | Read-only knowledge-base views (summary, section list, categories) |
| Prompts   | 2 | Pre-built templates: `analyze_challenge`, `solve_challenge` |
| Tools     | 39 | Callable skill functions + agent orchestration endpoints |

### 2. Skill Registry (`server/registry.py`)

Discovers skills automatically by scanning the `skills/` directory. For each
sub-directory it reads `skill.yaml`, loads `prompt.md`, and dynamically imports
`run.py`. This means adding a new skill is as simple as creating a new
directory.

### 3. Skills (`skills/`)

Each skill follows the **Claude Skills** pattern – a self-contained directory
with three files:

```
skills/<name>/
├── skill.yaml     → metadata: name, description, inputs, tools, category
├── prompt.md      → LLM reasoning instructions
└── run.py         → execution logic with a  run(inputs) -> dict  entry-point
```

| Skill | Category | Description |
|-------|----------|-------------|
| `analysis` | analysis | File type detection, encoding identification, hex dumps |
| `crypto_solver` | crypto | ROT-13, Caesar, XOR, Base64, Vigenère, Atbash |
| `stego_solver` | stego | strings, exiftool, binwalk, steghide, zsteg |
| `forensics` | forensics | foremost, pngcheck, pdftotext, file magic |
| `web_exploit` | web | HTTP headers, robots.txt, JWT decoding |
| `reverse_engineering` | reversing | objdump disassembly, nm symbols, readelf |
| `binary_exploit` | pwn | checksec, ROPgadget, cyclic patterns, GOT/PLT |
| `recon` | recon | nmap, whois, dig, smbmap |
| `exploit_gen` | exploit | Ollama-powered PoC script generation |
| `writeup_generator` | reporting | Ollama-powered write-up generation |

### 4. Tools (`tools/`)

Thin wrappers around external CLI programs. Every wrapper delegates to a shared
`safe_run()` helper that handles timeouts, missing binaries, and stderr
capture. Skills call these wrappers—they never run `subprocess` directly.

| Wrapper | External tool(s) |
|---------|-----------------|
| `nmap_wrapper.py` | nmap, whois, dig, smbmap, enum4linux |
| `binwalk_scan.py` | binwalk |
| `steghide_runner.py` | steghide |
| `strings_runner.py` | strings |
| `exiftool_runner.py` | exiftool |
| `objdump_runner.py` | objdump, nm, readelf |
| `checksec_runner.py` | checksec, ROPgadget |
| `curl_runner.py` | curl, gobuster, dirb |
| `foremost_runner.py` | foremost, unzip |
| `pdftotext_runner.py` | pdftotext |
| `pngcheck_runner.py` | pngcheck |
| `zsteg_runner.py` | zsteg, identify |

### 5. Agents (`agents/`)

Four Ollama-backed agents handle reasoning tasks:

| Agent | Responsibility | Key method |
|-------|---------------|------------|
| **AnalyzerAgent** | Inspect artifact, classify CTF category, list observations | `analyze()` / `aanalyze()` |
| **PlannerAgent** | Produce numbered step-by-step plan with tool names & args | `plan()` / `aplan()` |
| **ExecutorAgent** | Interpret tool output, decide continue/retry/done, detect flags | `interpret()` / `ainterpret()` |
| **ReporterAgent** | Generate Markdown write-up and optional exploit PoC | `generate()` / `agenerate()` |

All agents inherit from `BaseAgent` (`agents/base.py`), which wraps the Ollama
Python client with conversation history and JSON parsing.

### 6. Context (`context/`)

- **`knowledge_base.py`** – Parses the repo's `README.md` into structured
  `KnowledgeSection` and `KnowledgeEntry` objects, mapping 33 sections to 10
  canonical categories. Powers `search_knowledge`, `get_knowledge_section`, and
  `list_knowledge_categories` tools.
- **`prompts/system_prompt.md`** – The master system prompt describing the
  agent's capabilities and workflow.

### 7. Configs (`configs/`)

- **`model_config.yaml`** – Ollama provider settings (model name, host,
  temperature). Overridden by `KATANA_OLLAMA_MODEL` / `KATANA_OLLAMA_HOST` env
  vars.
- **`skills_config.yaml`** – Ordered list of skills with `enabled` flag for
  selective loading.

**Environment variables** (all optional):

| Variable | Default | Description |
|----------|---------|-------------|
| `KATANA_OLLAMA_MODEL` | `mistral` | Ollama model used by agents |
| `KATANA_OLLAMA_HOST`  | `http://localhost:11434` | Ollama server URL |

## Solving Workflow

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

## Directory Layout

```
.
├── README.md                  # Living knowledge base (original Katana content)
├── docs/
│   └── ARCHITECTURE.md        # This file
├── pyproject.toml             # Project metadata & entry-point
├── requirements.txt           # Pinned runtime dependencies
│
├── server/                    # ── MCP orchestration ──
│   ├── __init__.py
│   ├── mcp_server.py          # FastMCP server – registers tools/resources/prompts
│   └── registry.py            # Discovers & loads skills from skills/
│
├── skills/                    # ── Claude Skills (1 dir per skill) ──
│   ├── analysis/
│   │   ├── skill.yaml         # Metadata: name, inputs, category
│   │   ├── prompt.md          # LLM reasoning instructions
│   │   └── run.py             # Execution logic: run(inputs) -> dict
│   ├── crypto_solver/
│   │   └── …
│   ├── stego_solver/
│   │   └── …
│   ├── forensics/
│   │   └── …
│   ├── web_exploit/
│   │   └── …
│   ├── reverse_engineering/
│   │   └── …
│   ├── binary_exploit/
│   │   └── …
│   ├── recon/
│   │   └── …
│   ├── exploit_gen/           # Ollama-backed PoC generation
│   │   └── …
│   └── writeup_generator/     # Ollama-backed write-up generation
│       └── …
│
├── tools/                     # ── External tool wrappers ──
│   ├── __init__.py            # safe_run(), detect_file_type(), hex_dump()
│   ├── nmap_wrapper.py
│   ├── binwalk_scan.py
│   ├── steghide_runner.py
│   ├── strings_runner.py
│   ├── exiftool_runner.py
│   ├── objdump_runner.py
│   ├── checksec_runner.py
│   ├── curl_runner.py
│   ├── foremost_runner.py
│   ├── pdftotext_runner.py
│   ├── pngcheck_runner.py
│   └── zsteg_runner.py
│
├── agents/                    # ── Ollama-backed reasoning agents ──
│   ├── __init__.py
│   ├── base.py                # BaseAgent (Ollama wrapper)
│   ├── analyzer.py            # AnalyzerAgent
│   ├── planner.py             # PlannerAgent
│   ├── executor.py            # ExecutorAgent
│   └── reporter.py            # ReporterAgent
│
├── context/                   # ── Knowledge base & system prompts ──
│   ├── __init__.py
│   ├── knowledge_base.py      # README parser → searchable sections
│   └── prompts/
│       └── system_prompt.md   # Master system prompt
│
├── configs/                   # ── Configuration ──
│   ├── model_config.yaml      # Ollama provider settings
│   └── skills_config.yaml     # Skill registry & enable/disable
│
└── tests/                     # ── Test suite ──
    ├── test_knowledge_base.py
    ├── test_registry.py
    ├── test_server.py
    └── test_skills.py
```

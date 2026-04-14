---
name: reverse
description: >
  Reverse Skill Hub: Central intelligence hub for the CTF-Katana ecosystem.
  Orchestrates the full TRI-MODE execution engine via PipelineConductor.
risk: low
source: local
version: "3.0.0"
---

# Reverse Skill Hub (v3)

The `reverse` skill is the **central intelligence hub** for the CTF-Katana ecosystem,
orchestrating the full **TRI-MODE Execution Engine** through `PipelineConductor`
(purple_loop_orchestrator v1.0.0).

---

## TRI-MODE Execution Engine

### MODE A — SOLVE (Offensive / Red Team)

**Action:** `solve` (alias: `analyze`)

**Trigger keywords:** `reverse`, `pwn`, `exploit`, `solver`, `crack`,
`analyze binary`, `decompile`, `find flag`, `break this`

**13-step pipeline:**

| Step | Skill | Purpose |
|------|-------|---------|
| 1 | `flagger` | Detect flags, entropy, encoded data |
| 2 | `analysis` | Static + dynamic analysis (checksec, objdump, strings) |
| 3 | `reverse_engineering` | Decompile / disassemble / logic extraction |
| 4 | `binary_exploit` | Identify primitives (BOF, ROP, UAF, format string) |
| 5 | `research_ctftime` | Similar challenge lookup on CTFtime |
| 6 | `research_rag` | Contextual exploit knowledge from local KB |
| 7 | `research_agent` | Deep-dive research via swarm if needed |
| 8 | `purple_loop` | PipelineConductor iterative refinement loop |
| 9 | `exploit_gen` | Generate exploit strategies |
| 10 | `script_writer` | Produce `outputs/reverse/solver.py` |
| 11 | `exploitation` | Simulate attack end-to-end |
| 12 | `flagger.verify()` | Validate flag correctness |
| 13 | `writeup_generator` | Generate `outputs/reverse/writeup.md` |

**Output contract (strict):**

```json
{
  "status": true,
  "summary": "...",
  "result": {
    "flag": "CTF{...}",
    "solver": {
      "type": "pwntools|python|bash|web3",
      "path": "outputs/reverse/solver.py",
      "validated": true
    },
    "findings": [...],
    "artifacts": [...],
    "writeup": "outputs/reverse/writeup.md"
  }
}
```

---

### MODE B — BUILD (Defensive / CTF Author)

**Action:** `create`

**Trigger keywords:** `build challenge`, `create ctf`, `vuln→ctf`,
`generate challenge`, `from bug report`, `from cve`, `inspire from ctftime`,
`based on real ctf`, `clone challenge`, `android challenge`, `iot challenge`, `firmware ctf`

**Phases:**

- **Phase 0 — Intelligence Gathering**

  | Input type | Skill dispatched |
  |-----------|-----------------|
  | CVE-ID | `research_vuln_discovery` |
  | CTFtime reference | `research_ctftime` + `research_chrome_scraper` |
  | `kb:...` keyword | `research_rag` |
  | Default | `research_rag` general search |

- **Phase 1+ — PipelineConductor BUILD pipeline**
  (`purple_loop_orchestrator`, non-interactive)

**Docker image tag:** `ctf-challenge-base:latest`

---

### MODE C — THINK (REDesigner Brainstorm)

**Action:** `think`

Uses `REDesigner` with `groq/llama-3.3-70b-versatile` for:
- Logic strategy brainstorming (`brainstorm_re_strategy`)
- Challenge design reasoning (`brainstorm_challenge_design`)

---

## State Management

`PipelineMemory` is mandatory for all pipelines:
- State file: `data/sessions/reverse_{target_slug}/state.json`
- `load_state()` called at pipeline start
- `save_state()` called after every transition

---

## Critical Path Enforcement

| Area | Rule |
|------|------|
| `script_writer` | All outputs → `outputs/reverse/` |
| Solver path | `outputs/reverse/solver.py` |
| Writeup path | `outputs/reverse/writeup.md` |
| Docker image | `ctf-challenge-base:latest` |

---

## Execution Examples

```bash
# MODE A: Solve a binary challenge
python skills/reverse/run.py ./challenge_binary --action solve

# MODE A: Solve from a code snippet
python skills/reverse/run.py --snippet "import flag; ..." --action analyze

# MODE A: Auto-detect via trigger
python skills/reverse/run.py ./vuln_binary --trigger "pwn this binary"

# MODE B: Build a challenge from a CVE
python skills/reverse/run.py CVE-2024-1234 --action create --difficulty hard

# MODE B: Build from CTFtime inspiration
python skills/reverse/run.py "pwn200 from PicoCTF 2024" --action create --trigger "inspire from ctftime"

# MODE B: Build from KB knowledge
python skills/reverse/run.py "kb:heap UAF" --action create --language c

# MODE C: Brainstorm RE strategy
python skills/reverse/run.py ./obfuscated_binary --action think --prompt "How would a creator hide a flag in XOR logic?"

# JSON output
python skills/reverse/run.py ./binary --action solve --json
```

---

## Modular Architecture

```
skills/reverse/
├── run.py                          ← Entry point, tri-mode dispatcher
├── models.py                       ← ReverseMode, SolveOutputContract, SolverInfo
├── base.py                         ← ReverseHandlerBase
├── skill.yaml                      ← Capability manifest
├── SKILL.md                        ← This file
├── prompt.md                       ← LLM system prompt
├── handlers/
│   ├── solve_handler.py            ← MODE A: 13-step SOLVE pipeline
│   ├── logic_handler.py            ← Legacy logic extraction (RE-Logic)
│   └── synthesis_handler.py        ← MODE B: Phase 0 + PipelineConductor
└── engines/
    └── re_designer.py              ← MODE C: LLM brainstorm engine
```

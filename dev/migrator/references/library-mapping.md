# Library Mapping: Python to Rust (ctf-katana)

When migrating skills from Python to the **Crab** (Rust) core, use this mapping as a starting point. Always verify crate versions using **context7**.

## Hacking & Exploitation

| Python Library | Rust Equivalent (Crate) | Primary Use Case |
| :--- | :--- | :--- |
| **PwnTools** | `goblin` + `iced-x86` | Binary parsing, AFL/ELF manipulation, disasm. |
| **Z3 / PyZ3** | `z3` (Rust bindings) | SMT solving for shellcode/crypto. |
| **Scapy** | `pnet` / `etherparse` | Low-level packet crafting & analysis. |
| **Requests** | `reqwest` | HTTP exploit delivery & web scraping. |

## Concurrency & Performance

| Python Feature | Rust Equivalent (Crate) | Notes |
| :--- | :--- | :--- |
| `itertools` | `itertools` (Rust crate) | Nearly identical API, but lazy and typed. |
| `multiprocessing` | `rayon` | Massive data parallelism (XOR, hash brute-force). |
| `asyncio` | `tokio` | The standard for high-performance async runtimes. |
| `pydantic` | `serde` | The gold standard for JSON/YAML serialization. |

## Strategy for Research

Invoke **context7** with the query:
> *"I am porting a Python script using [LibraryX] to Rust for a CTF engine. What are the best modern crates for [FeatureY]?"*

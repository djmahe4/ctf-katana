# Async Debt Resolution (ctf-katana)

The transition from a single-threaded Python MCP server to the **Crab** (Rust) async-native runtime introduces "Async Debt" that can cause hangs and performance regressions.

## Identifying Async Issues

**Hanging Tools**:
-   A tool is `AWAIT`ed but the runtime is blocked by a synchronous `subprocess.run()`.
-   A Rust sidecar fails to return its response before the FastMCP timeout.

**Deadlocks**:
-   A Python skill attempts to read the `SQLite` state while a Rust sidecar has a write-lock.

## Resolution Strategies

1.  **Isolate Blocking Logic**: Use `asyncio.to_thread()` in Python to run synchronous library calls (like PwnTools) without blocking the `FastMCP` loop.
2.  **Tokio Runtime Integration**: When implementing Level 2/3 (Rust Core), ensure all IO is non-blocking using `tokio::fs` or `tokio::process`.
3.  **Timeout Enforcement**: Every inter-agent call must have a strict timeout (default: 30s) to prevent cascading failures.

## AI Orchestration

Invoke **@free-llms** with the task: 
> *"Refactor this synchronous Python MCP tool for the ctf-katana project into an async-native implementation using the patterns in dev/debugger/references/async-debt-resolution.md."*

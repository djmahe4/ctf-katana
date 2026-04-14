---
name: raum-dev-debugger
description: Expert skill for systematic debugging and root cause analysis. Specializes in MCP transport (STDIO/JSON-RPC) issues and 'Async Debt' resolution during the Rust transition. Uses @free-llms for log analysis.
---

# Dev Debugger

The `raum-dev-debugger` skill ensures the stability of the **ctf-katana** multi-agent ecosystem. It prevents "Agentic Unreliability" by identifying transport bottlenecks and synchronization errors.

## Context Anchors

- **Transport Architecture**: [MIGRATION_GUIDE.md](../docs/MIGRATION_GUIDE.md)
- **Engine Blueprint**: [Crab Engine (Rust Host)](../docs/MIGRATION_GUIDE.md#🦀-level-2-the-crab-engine-rust-host)

## Debugging Workflow

1.  **Isolate & Align**: Determine the failure point and align with the [Transport Specs](docs/MIGRATION_GUIDE.md) to verify expected behavior.
2.  **Analyze Transport**: Use [Transport Diagnostics](references/transport-diagnostics.md) to check for JSON-RPC malformation or stdio pollution.
3.  **Resolve Async Debt**: If the system hangs during a Rust transition, consult [Async Debt Resolution](references/async-debt-resolution.md).
4.  **Root Cause with AI**: Invoke **@free-llms** with the task: *"Perform a root cause analysis on these trace logs. Identify if the hang is due to a blocked event loop or a transport deadlock."*

## Success Conditions

-   **Zero Stdio Pollution**: No skills are printing raw output to stdout (which breaks MCP).
-   **Trace Visibility**: All components use standard logging that can be captured by the `TelemetryManager`.
-   **Non-Blocking Loops**: The `Purple Loop` orchestrator never blocks the main transport thread.

## Common Triggers
-   "The MCP server disconnected unexpectedly."
-   "The tool call returned an invalid JSON response."
-   "The system is hanging during the new Rust kernel execution."

---
name: raum-dev-migrator
description: Specialist skill for porting Python logic to Rust/TypeScript sidecars (CRAB Levels 1-4). Uses 'context7' for crate discovery and @free-llms for high-fidelity code transformation.
---

# Dev Migrator

The `raum-dev-migrator` skill ensures that the transition from Python to Rust is not just a rewrite, but a performance optimization. It follows the **CRAB** (Crab-Native Rust) 5-level strategy.

## Context Anchors

- **Canonical Guide**: [MIGRATION_GUIDE.md](../../docs/MIGRATION_GUIDE.md)
- **Current Roadmap**: [PROGRESS.md](../../docs/PROGRESS.md)

## Migration Workflow

1.  **Analyze & Align**: Identify CPU-bound logic and align it with the project's [Migration Strategy](docs/MIGRATION_GUIDE.md) to determine the target Level (1-5).
2.  **Research Crates**: Use **context7** to find the modern Rust equivalent (see [Library Mapping](references/library-mapping.md)).
3.  **Refactor with AI**: Invoke **@free-llms** with the prompt: *"Port this Python logic to a high-performance Rust sidecar following the patterns in dev/migrator/references/sidecar-patterns.md"*.
4.  **Implement Sidecar**: Deploy as a Level 4 Rust binary sidecar or a Level 2 Rust core module.
5.  **Verify L_r**: Use `raum-dev-benchmarker` to confirm the Latency Reduction ($L_r$).

## Success Conditions

-   **Zero Regression**: The Rust implementation must pass all existing Python test cases.
-   **Performance Gain**: Minimum $10\times$ improvement for CPU-bound tasks.
-   **Type Safety**: Use of `struct` and `enum` in Rust to replace loose Python dicts.

## Common Triggers
-   "Port this crypto skill to Rust."
-   "Help me find a Rust crate for decompilation."
-   "Implement a sidecar for this binary analysis tool."

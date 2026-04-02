---
name: raum-dev-architect
description: Expert skill for architecting cross-language orchestration loops and handoff protocols. Use when planning multi-skill workflows (e.g., Web -> Kavach) or implementing 'Level 3.5' logic. Uses @free-llms for high-level technical decisions.
---

# Dev Architect

This skill guides the evolution of the **ctf-katana** orchestration engine. It ensures that data shared between skills is deterministic and that the "Purple Loop" (Analyze-Plan-Execute-Verify) is strictly followed.

## Context Anchors

- **Canonical Guide**: [MIGRATION_GUIDE.md](file:///c:/Users/mahes/OneDrive/Desktop/Python-Projects/ctf-katana/docs/MIGRATION_GUIDE.md)
- **Architecture Source**: [Level 3.5: Agentic Security Hardening](file:///c:/Users/mahes/OneDrive/Desktop/Python-Projects/ctf-katana/docs/MIGRATION_GUIDE.md#️-level-35-agentic-security-hardening--performance-optimization)

## Orchestration Flow

1.  **Identify Boundary**: Determine if a task requires multiple skills and align with the [Level 3.5 Strategy](file:///c:/Users/mahes/OneDrive/Desktop/Python-Projects/ctf-katana/docs/MIGRATION_GUIDE.md#️-level-35-agentic-security-hardening--performance-optimization).
2.  **Plan Handoff**: Use the [Handoff Protocol](references/handoff-protocol.md) to define the shared state.
3.  **Implement Loop**: Use [Orchestration Loops](references/orchestration-loops.md) to wrap the execution in a verification cycle.
4.  **Refactor with AI**: When modifying the core orchestrator, invoke **@free-llms** to ensure thread-safety and async compatibility.

## Success Conditions

-   Elimination of "Agentic Decay" (loss of context between tool calls).
-   Deterministic handoffs via `metadata` dictionaries.
-   Strict adherence to the 5-layer "Crab" migration strategy.

## Common Triggers
-   "How do I pass results from one tool to another?"
-   "Implementing the Purple Loop for a new challenge type."
-   "Refactoring the orchestrator for async performance."

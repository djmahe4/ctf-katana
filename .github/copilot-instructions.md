# Copilot Workflow

## How To Work In This Repo

1. Read the local source and project docs first when the task is about this repository.
2. Use the Knowledge Base and existing prompts for repo-specific behavior.
3. Use Context7 MCP for any external library, framework, or API research before proposing code changes.
4. Prefer current, upstream documentation over stale examples or memory.
5. Keep edits small, consistent with the existing codebase, and aligned with the current architecture.

## Context7 MCP Usage

- Resolve the library or package name before fetching docs.
- Pull the relevant Context7 docs for the exact topic being worked on.
- Use the retrieved docs to verify APIs, configuration, and recommended patterns.
- If a dependency is not covered by Context7, fall back to the upstream docs or the local source tree.

## Repository Priority

- For code in this workspace, inspect the implementation before editing.
- For workflow, orchestration, and challenge-solving behavior, preserve the existing CTF-Katana / Purple Engine conventions.
- For new guidance, prefer a single source of truth in this file instead of scattering instructions across multiple docs.
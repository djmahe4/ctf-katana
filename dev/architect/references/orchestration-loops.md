# Orchestration Loops

The **Purple Loop** is the engine's cognitive cycle. It prevents the agent from "guessing" results without validation.

## The 4-Phase Cycle

1.  **Analyze**: Use `grep` and `file` tools to understand the target environment.
2.  **Plan**: Draft an `implementation_plan.md` (even for small tasks).
3.  **Execute**: Run the selected skills (Web, Crypto, Rev, etc.).
4.  **Verify**: ALWAYS run a verification tool (e.g., `check_flag`, `test_exploit`) before concluding.

## Recursive Loops

If **Verify** fails, the loop restarts at **Analyze** with the failure logs as fresh context.

## Best Practices
-   **No Stubs**: Replace `# TODO` placeholders in orchestrators with actual sub-agent calls.
-   Also check '# In a real scenario', '# Handoff', '# Verification' or '# Refactor' or '# Placeholder' in the code for more details.
-   **Async First**: Ensure loop iterations do not block the MCP stdio transport.

## Commands
- `grep -rn "# TODO" .` : To find all the TODOs in the code.
- `grep -rn "# In a real scenario" .` : To find all the In a real scenario in the code.

### Dirs and filetypes to ignore

REFER [.gitignore](./.gitignore)


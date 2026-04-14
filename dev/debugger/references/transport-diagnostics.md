# Transport Diagnostics (ctf-katana)

The **ctf-katana** project uses STDIO for MCP communication. Any unexpected output from a skill (e.g., `print("debug")`) will pollute the transport stream and cause a JSON-RPC error.

## Common Transport Failures

1.  **Stdio Pollution**: A Python library or Rust binary prints to stdout instead of using a structured log.
2.  **JSON Malformation**: A skill returns a non-serializable object (e.g., a complex class instance).
3.  **Buffer Deadlock**: A synchronous skill blocks the main event loop while waiting for a long-running process (like the XOR brute-forcer).

## Diagnostic Steps

-   **Check Logs**: Always use `TelemetryManager` or standard `logging` directed to stderr.
-   **Trace Transport**: Use the `mcp-inspector` tool to view raw JSON-RPC traffic.
-   **Verify Payload**: Invoke **@free-llms** to validate that a tool's output schema matches the registered FastMCP definition.

## Handled Responses (JSON-RPC)

-   `-32700`: Parse error (likely stdout pollution).
-   `-32602`: Invalid params (schema mismatch).
-   `-32603`: Internal error (skill execution failed).

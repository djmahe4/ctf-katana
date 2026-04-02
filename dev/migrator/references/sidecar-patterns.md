# Sidecar Patterns (ctf-katana)

When porting a skill to Rust as a sidecar binary (Level 4 Migration), use these patterns to maintain clean process separation.

## Pattern A: JSON-over-STDIO (Local)

The simplest way to invoke a Rust tool from the Python MCP server.

**Python (Caller):**
```python
import subprocess
import json

def run_crab_tool(input_data):
    res = subprocess.run(
        ["./dev/bin/crab_tool"], 
        input=json.dumps(input_data),
        capture_output=True, text=True
    )
    return json.loads(res.stdout)
```

**Rust (Callee):**
```rust
use serde::{Deserialize, Serialize};
use std::io::{self, Read};

fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let data: InputData = serde_json::from_str(&input).unwrap();
    // ... logic ...
    println!("{}", serde_json::to_string(&output).unwrap());
}
```

## Pattern B: Shared State (Redis/SQLite)

For multi-agent workflows where a Rust tool produces data for a later Python skill.

-   **Rust Tool**: Processes binary, writes summary to SQLite `state` table.
-   **Python Tool**: Reads `state` table, generates AI walkthrough.

## Pattern C: FastMCP/Rust

In Phase 5+, use the **mcp-sdk-rs** to directly register tools in Rust.

-   Skip the Python wrapper entirely.
-   Invoke **@free-llms** to generate the boilerplate for a new Rust MCP registration.

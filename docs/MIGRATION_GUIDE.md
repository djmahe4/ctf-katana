# 🦀 Purple Engine: Migration Guide (Crab Project)

This guide documents the transition from a pure Python implementation to a high-performance, multi-language **Crab** (Rust-native) architecture. It is designed to be beginner-friendly, starting with basic TypeScript connectivity and evolving into a professional TUI-monitored system.

---

## 🚦 Prerequisites: Your Toolkit
Before you begin, ensure you have these "Requirement" tools installed:

1.  **Node.js (v18+)**: For the **Interface Layer** (TypeScript).
2.  **Rust / Cargo**: For the **Core Engine** (The Crab Host).
3.  **Python (v3.10+)**: For the **Skill Sidecars** (AI/Research tools).
4.  **Ollama**: For local agent reasoning.

---

## 🏗️ Level 1: The 'Interface' (TypeScript)
**Why TypeScript is a Requirement:** Most Model Context Protocol (MCP) clients and VS Code extensions are built in TS. It is the easiest way to "Boot Up" your first server.

### 1-Click Simple Setup:
```bash
# Initialize the Gatekeeper
npm init -y
npm install @modelcontextprotocol/sdk
```

**Snippet: `index.ts` - Your First Gatekeeper**
```typescript
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const server = new McpServer({ name: "katana-gatekeeper", version: "1.0.0" });

// Simple Tool Registration
server.tool("hello_katana", {}, async () => ({
  content: [{ type: "text", text: "Welcome to Purple Engine!" }]
}));

const transport = new StdioServerTransport();
await server.connect(transport);
```

---

## 🦀 Level 2: The 'Crab' Engine (Rust Host)
Once you pass Level 1, you migrate the heavy lifting to Rust. This is where the **Purple Engine (Crab)** truly lives, providing the performance needed for CTF challenges.

**Logic:** Rust handles the **Black Box (State)** and the **Pause Button (HITL)**.

### The Entry Point (`src/main.rs`):
```rust
use rust_mcp_sdk::{*, mcp_server::server_runtime, schema::*};

#[tokio::main]
async fn main() -> SdkResult<()> {
    let server_info = InitializeResult {
        server_info: Implementation { name: "katana-crab".into(), version: "2.0.0".into(), ..Default::default() },
        capabilities: ServerCapabilities { 
            tools: Some(ServerCapabilitiesTools::default()), 
            resources: Some(ServerCapabilitiesResources::default()), ..Default::default() 
        },
        ..Default::default()
    };

    let transport = StdioTransport::new(TransportOptions::default())?;
    let server = server_runtime::create_server(server_info, transport, KatanaHandler::default());
    
    server.start().await // Engine Online
}
```

### 2. Defining Tools (Crab Style)
Use the `#[mcp_tool]` macro to define the 30+ skills. This automatically generates the JSON schema for the LLM.

```rust
use rust_mcp_sdk::macros::{mcp_tool, JsonSchema};
use serde::{Deserialize, Serialize};

#[mcp_tool(
    name = "bin_analyze",
    description = "Perform deep binary analysis using the native Rust engine"
)]
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct BinAnalyzeTool {
    /// Absolute path to the challenge binary
    pub path: String,
    /// Analysis level (0: strings, 1: symbols, 2: decompile)
    pub level: u8,
}
```

---

## 📦 Level 3: State & Rollback (The 'Black Box')
To ensure the Purple Engine is "beginner-proof," we use a **Black Box (SQLite)** to record every action.

### 🔄 The Rollback (Undo) Logic
If a tool fails or you hit the **Deny** button in the TUI, the system triggers a **Rollback**.

1.  **Checkpoint**: Rust opens a transaction in `katana.db`.
2.  **Simulation**: The tool runs.
3.  **Failure/Deny**: Rust calls `ROLLBACK`, reverting the DB to the previous state.
4.  **Success**: Rust calls `COMMIT`.

### 🤝 Human-in-the-Loop (The 'Pause Button')
Using **Rust oneshot channels**, the tool execution "Pauses" automatically for sensitive actions.

**Wait Pattern:**
```rust
// In src/handler.rs
let (tx, rx) = oneshot::channel();
send_to_tui_modal(ApprovalRequest { tx });
let approved = rx.await.unwrap_or(false); // Code SLEEPS here until you hit 'Y'
```

---

## 🐍 Level 4: Python Skill Sidecars
Existing Python tools are not being deleted! They are "plugged in" using the **Purple SDK**.

```python
# scripts/kavach_shield.py
import purple_sdk as katana

def run():
    # Ask the Rust TUI for permission
    if katana.request_user_approval("Deploying Firewall..."):
        # Actual work happens here
        pass
```

---

## ⚖️ Decision Matrix: Rust vs. Python

When migrating or adding new skills, use the following criteria to decide which language to implementation:

| Use **Rust** When... | Use **Python** When... |
| :--- | :--- |
| **CPU-Bound**: Heavy binary parsing or brute-forcing. | **Agility-First**: Rapidly prototyping a new idea. |
| **Safety-Critical**: Handling untrusted binaries. | **AI/ML Heavy**: LangChain or complex LLM flows. |
| **Static Analysis**: Building stable decompilers. | **Web/IO-Bound**: High-level scraping or Synthesis. |
| **Low Latency**: Tools called in the TUI Master Loop. | **Library Dependency**: Specific Python package exists. |

---

## 🚀 Phase 5: The Ratatui TUI

A dedicated Rust-based terminal interface will replace the current raw stdout logs.

- **Real-time Telemetry**: Monitoring active agent "thoughts" and loop progress.
- **HITL Intervener**: A split-pane view for human approval of dangerous exploit payloads.
- **Visualizers**: Custom widgets for displaying heap layouts (Pwn) and assembly (RE).

---

## 📅 Migration Roadmap

### Phase A: Setup Node.js Workspace (Immediate)
- Initialize `package.json` in the root.
- Setup `tsup` or `esbuild` for the server core.
- Port `server/registry.py` logic to TypeScript (`registry.ts`).

### Phase B: Sidecar Scaffolding
- Initialize Rust workspace (`Cargo.toml`) in `skills/core_engines`.
- Port the `analysis` and `binary_exploit` tools to Rust.

### Phase C: TUI Development
- Scaffold the `ratatui` dashboard.
- Connect the TUI to the MCP server via stdio/websocket transport.

---

## ⚠️ Critical Path: `PURPLE_HOME`
To ensure cross-language compatibility, all components **must** resolve paths relative to a `PURPLE_HOME` environment variable (defaulting to the repository root). This prevents pathing errors when TS, Rust, and Python processes interact.

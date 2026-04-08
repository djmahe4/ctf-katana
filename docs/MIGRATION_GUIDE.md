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

> [!NOTE]
> For a broader overview of current development milestones and feature status, see [Project Progress & Roadmap](PROGRESS.md).

## 🛡️ Level 3.5: Agentic Security Hardening & Performance Optimization

This phase refines the core project architecture to minimize **Agentic Decay** and maximize **Execution Velocity**. It builds on the existing Purple Loop (Analyze → Search KB → Plan → Execute → Shield → HITL) and secures the hybrid architecture for your B.Tech thesis.

### 1. Core Objective
Minimize failures across multi-step tool chains and migrate high-latency tasks (binary analysis, crypto) to Rust. This ensures local-first execution reliability and memory safety.

### 2. Technical Implementation Stack & Resources
The following selections prioritize stability and seamless integration with the current Python MCP server while supporting the Rust transition.

| Category | Recommended Tooling | Purpose in Phase 4.5 | Key Resources |
| :--- | :--- | :--- | :--- |
| **Language** | Rust (Official SDK) | Replace Python for high-latency tasks (Binary/RE/Crypto). | [rust-sdk](https://github.com/modelcontextprotocol/rust-sdk) |
| **Isolation** | Firecracker / gVisor | Secure sandbox for untrusted AI-generated payloads. | [Firecracker](https://firecracker-microvm.github.io/) |
| **Orchestration**| FastMCP (Python) | High-level routing and tool discovery. | [FastMCP](https://github.com/PrefectHQ/fastmcp) |
| **Binary Analysis**| r2pipe + radare2 | Scriptable LLM-driven reverse engineering interface. | [r2pipe](https://github.com/radareorg/radare2-r2pipe) |
| **Web Security** | Nuclei | Template-based scanning to replace brittle custom fuzzers. | [Nuclei](https://github.com/projectdiscovery/nuclei) |
| **Data Layer** | Redis | State persistence and caching for multi-step loops. | [Redis](https://redis.io/) |
| **Prexisting models integration** | Github | Training Cybersecuirty specific models for semantic understanding | [1](https://github.com/sajjadium/ctf-archives/) [2](https://github.com/swisskyrepo/PayloadsAllTheThings) [3](https://github.com/ljagiello/ctf-skills/tree/main) |


#### Datasets to learn from

| Repository Name | Description | Dataset Details & Format | Usage for Model Training | Usage for RAG (Direct Pass) | Reference URL |
| :--- | :--- | :--- | :--- | :--- | :--- |
| OSTIS-Organization-Specific-Threat-Intelligence-System | Organization-Specific Threat Intelligence System with knowledge graph (OSTIKG) | /Dataset folder: labeled data for relevance filtering, domain classification (Education, Finance, Government, Healthcare, ICS, IoT), and cybersecurity NER (entities: malware groups, tools, etc.). BERT-ready labels. | Fine-tune BERT-based models for content relevance, domain mapping, and 12+ cyber entity NER. Use datasets library + Hugging Face Trainer for multi-label classification. | Chunk JSON/CSV into vector DB; retrieve organization-specific threats during Purple Loop Search KB → improves agentic threat analysis and Kavach Shield context. | https://github.com/OPTIMA-CTI/OSTIS-Organization-Specific-Threat-Intelligence-System (Dataset: /tree/main/Dataset) |
| Twitter-CTI | Automated pipeline for collecting and analyzing CTI from Twitter (OSINT) | dataset/ folder: ~200k+ security-related tweets with IoCs, account features, bot/human labels, temporal data, and threat indicators (CVEs, URLs, hashes). 47 features per record. | Train XGBoost / BERT classifiers for bot detection, tweet relevance, and IoC extraction. Labeled subset (3,231 human + 452 automated accounts) ready for supervised fine-tuning. | Embed tweets/IoCs as RAG chunks for real-time social-media threat intelligence in research skills; query “latest Twitter-reported CVEs” directly in Analyze/Plan phases. | https://github.com/OPTIMA-CTI/Twitter-CTI |
| DroidTTP | Android TTP (Tactics, Techniques, Procedures) mapping using problem transformation and LLM analysis | dataset/ folder: curated Android malware datasets mapped to MITRE ATT&CK TTPs; supports problem-transformation approach and LLM fine-tuning. | Fine-tune LLMs for TTP prediction or use as supervised dataset for multi-label classification of Android behaviors. | Load into RAG index for mobile/IoT skills; retrieve ATT&CK-mapped examples during Execute phase for Android/IoT challenges. Perfect for your existing mobile skills category. | https://github.com/OPTIMA-CTI/DroidTTP (Dataset: /tree/main/dataset) |
| CyberNER | Cybersecurity Named Entity Recognition models and dataset | Jupyter Notebook-based dataset with 12 cyber-specific entity types (malware, tools, vulnerabilities, actors, etc.). | Direct fine-tuning of spaCy/BERT NER models on cybersecurity corpus. | Embed labeled entities into your local KB/RAG for high-precision entity extraction in the Analyze agent (boosts Red/Blue separation and tool selection). | https://github.com/OPTIMA-CTI/CyberNER |
| XAITrafficIntell | Explainable AI for traffic intelligence (darknet/threat traffic analysis) | Intelligence folder: scripts + datasets derived from darknet traffic (threat indicators, anomalies). | Train XAI models (e.g., SHAP/LIME + classifiers) on traffic features for anomaly detection. | RAG-augment network/forensics skills with darknet-derived threat patterns; useful for binary/web recon in Purple Loop. | https://github.com/OPTIMA-CTI/XAITrafficIntell |



### 🏗️ Architectural Considerations & WSL2 Readiness

> [!IMPORTANT]
> **WSL2 Requirement for Windows Isolation**
> Since you are on Windows, high-performance isolation via **Firecracker** or **gVisor** requires a **WSL2 (Windows Subsystem for Linux)** environment with KVM enabled. Firecracker leverages Linux-native virtualization which is now fully supported in modern WSL2 kernels.

*   **Hybrid State Engine**: While Level 3 uses SQLite for persistent telemetry, Phase 4.5 introduces **Redis** as a volatile "Fast Memory" layer. This allows the Purple Loop to share state across multiple agents (Red/Blue/Research) in real-time while maintaining long-term history in SQLite.
*   **Decay Mitigation via Logic Gates**: To prevent "Agentic Decay," we implement **Context Pruning** and **CoT Verification** within the FastMCP orchestrator. This ensures the LLM's context window stays clean during long-running CTF challenges.

### 📊 Mathematical Benchmarking Equations
These metrics provide verifiable quantifiers for your thesis performance evaluation:

*   **Reliability Decay Equation**: Measures the product of component reliability across $n$ steps.
    $$ P_s = \prod_{i=1}^{n} (P_i \times C_i) $$
*   **Execution Efficiency Factor**: The ratio of solved flags/vulnerabilities per minute.
    $$ E = \frac{V_d}{T_e} $$
*   **Latency Reduction Ratio**: Comparing Python baseline against Rust optimization on hot paths.
    $$ L_r = \frac{T_{python}}{T_{rust}} $$
*   **Security Guardrail Residual Risk**: Risk reduction via layered filters (Pydantic + Sandbox + HITL).
    $$ R_r = R_u \times (1 - F_e)^m $$

### 🎯 Baselines for Comparison
Compare these targets against your Phase 4 baseline to quantify the success of the hardening:

| Metric | Industry Baseline | Phase 4.5 Target |
| :--- | :--- | :--- |
| **Initial Recon Time** | 10–15 minutes | < 90 seconds (Rust + Nuclei) |
| **Tool Calling Accuracy**| ~100% (Manual) | > 88% (LLM + FastMCP) |
| **Vulnerability Recall** | 60% (Auto-scanners) | > 82% (Reasoning + Nuclei) |
| **Security Breaches** | High (Static Scripts) | Near Zero (Firecracker/gVisor) |

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

## 🔬 Level 5: Performance Benchmarking & Learning Pipeline

To validate the **"Crab" (Rust)** transition for the B.Tech Final Year Thesis, we implemented a dual-tier benchmarking suite and an AI-driven educational explainer.

### 📊 Empirical Performance Results ($L_r$)
Workload: Multi-byte XOR Brute-force (Search through $2^{32}$ combinations).

| Metric | Python (Baseline) | Rust (Crab Target) | Improvement ($L_r$) |
| :--- | :--- | :--- | :--- |
| **Search Velocity** | ~2,201,116 keys/s | **~4,719,744,281 keys/s** | **~2,144x** |
| **4.2B Keys Time** | ~32.52 minutes | **0.9099 seconds** | **~2,144x** |
| **Parallelism** | Single-threaded | Multi-threaded (Rayon) | Hardware-bound |

**Thesis Conclusion**: The migration to a Rust-native core provides a **three-orders-of-magnitude** performance gain, enabling near-instantaneous cryptographic and binary analysis tasks that previously required human-unfriendly wait times.

### 🎓 Educational Hacking (The Learning Pipeline)
To prevent "Agentic Decay" and ensure the user *learns* from the tool, the Purple Engine now features a **Learning Explainer** ($E_x$):

1.  **Event Telemetry**: Every tool execution is logged with CPU/RAM metrics and LLM reasoning "overhead" timestamps.
2.  **AI Walkthroughs**: After successful exploits, the engine triggers an **Ollama (Llama3)** module To generate a "Learning Moment" walkthrough.
3.  **Quantifiable Learning**: By tracking the delta between "Tool Output" and "User Understanding" (via the Walkthrough recall), we define a new metric: **Educational Reliability ($R_e$)**.

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

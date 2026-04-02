# Phase 6 Readiness Audit: Technical Debt & Orchestration Gaps

This audit identifies critical regions across the `skills/` and `server/` directories that require improvement before entering **Phase 6: Advanced Orchestration & Interaction**.

## 🔴 High-Priority Blockers (Phase 6)
These items directly impact the ability of the system to function as a multi-agent orchestrated engine.

### 1. Missing Handoff Mechanism
- **File**: `skills/web/run.py:L69`
- **Issue**: `# TODO: implement handoff`
- **Impact**: The Web skill currently cannot "pass the baton" to subsequent skills (e.g., passing a discovered RCE to the `kavach` protector). This breaks the **Synthesis-to-Shield** pipeline.

### 2. Broken Loop Orchestration
- **File**: `skills/purple_loop_orchestrator/run.py:L121, L127`
- **Issue**: `# TODO: Implement deeper Flagger integration` and `# TODO: Implement actual deployment logic`.
- **Impact**: The primary orchestrator is using stubs for deployment and flag verification. Phase 6 requires these to be fully functional for automated "Solve-Harden" loops.

### 3. Fuzzing Engine Gaps
- **Files**: 
    - `skills/fuzzing/handlers/protocol_handler.py:L40` (`Define custom protocol layers`)
    - `skills/fuzzing/handlers/binary_handler.py:L74, L98` (`Link with target binary`, `Call target entry point`)
- **Impact**: The Fuzzing skill is currently a skeleton. It cannot perform targeted binary or protocol fuzzing without these native implementations.

---

## 🟡 Technical Debt & Refinement
These items should be addressed to ensure stability and professional-grade performance.

### 1. Web3 Simulation Stubs
- **File**: `skills/web3/orchestrator.py:L113`
- **Issue**: `# Since I am the agent, I'll simulate the refinement step for now`
- **Impact**: Reduces the autonomy of the Web3 skill. It relies on the LLM's internal knowledge rather than a deterministic refinement process.

### 2. Async Transition Debt
- **File**: `skills/reverse_engineering/handlers/binary_handler.py:L30`
- **Issue**: `# In a full-async refactor, this would be await engine.decompile(...)`
- **Impact**: Potential performance bottlenecks in the TUI (Crab) host if synchronous calls block the main event loop.

---

## 🟢 Housekeeping & Cleanup

### 1. Deprecated Skill Purge
- **Directory**: `skills/web_exploit/`
- **Status**: Marked as **DEPRECATED** in `skill.yaml`.
- **Action**: Should be archived or deleted to avoid LLM confusion and reduce the search space for the `RegistryManager`.

---

## 🚀 Recommendation for Phase 6
To ensure success in the next phase, the following sequence is recommended:
1. **Implement the `handoff` protocol** in the base skill class to allow cross-skill data sharing.
2. **Flesh out `purple_loop_orchestrator`** to use real Docker/Flagger calls instead of `TODO` stubs.
3. **Migrate Fuzzing Handlers** to native Rust (Level 2 Crab) to solve the "linking" and "entry point" issues efficiently.

# Report Templates (ctf-katana)

Use these templates when updating the **PROGRESS.md** or for thesis chapters.

## Template: Benchmark Analysis

```markdown
### Performance Report: [SkillName]

- **Benchmark Method**: [Direct Binary / FastMCP]
- **Target Workload**: [e.g., 1GB Memory Dump]
- **Latency Ratio (L_r)**: [X]
- **Efficiency Gain (R_e)**: [Y%]

**Analysis Summary**:
[The Rust kernel yielded an L_r of X. CPU utilization was pinned at 100% across all Rayon threads.]

**Thesis Integration**:
- Add to Table [[X]] in Chapter 4.
- Update Figure [[Y]] with the neuen baseline.
```

## Template: Migration Level Check

```markdown
### CRAB Level Migration Status: [SkillName]

| Level | Status | Details |
| :--- | :--- | :--- |
| **Level 1 (TS)** | [Completed/In Progress] | JSON-RPC Schemas generated. |
| **Level 2 (Rust)** | [Completed/In Progress] | Core logic using `mcp-sdk-rs`. |
| **Level 3 (State)** | [N/A] | Persistent storage required? |
| **Level 4 (Sidecar)** | [Yes/No] | Currently invoked as subprocess. |
```

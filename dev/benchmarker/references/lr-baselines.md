# Latency Reduction (L_r) Baselines

These are the primary performance metrics for the **ctf-katana** B.Tech thesis. 

## Key Metrics

- **$L_r$ (Latency Reduction Ratio)**: $L_r = T_{python} / T_{rust}$
- **$R_e$ (Relativity Efficiency)**: Measures resource utilization (CPU/Mem) per task.

## Latest Benchmarks (April 2026)

| Workload | Python (Baseline) | Rust (Crab Target) | **Current $L_r$** |
| :--- | :--- | :--- | :--- |
| XOR Brute-force (4.2B keys) | 2008.34s | 0.8415s | **2386.62x** |
| Memory Forensics (1GB Dump) | TBD | TBD | - |
| Fuzzing (Protocol Layer) | TBD | TBD | - |

## Performance Goals

- Maintain $L_r > 1000\times$ for all CPU-intensive kernels.
- Achieve $L_r > 5\times$ for IO-bound MCP tools through async-parallelism.

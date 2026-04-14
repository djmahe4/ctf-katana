
### Crab Transition Performance Metrics (B.Tech Thesis Experiment)

| Metric | Python (Baseline) | Rust (Crab Target) | Improvement ($L_r$) |
| :--- | :--- | :--- | :--- |
| **Search Velocity** | 2,137,830.62 keys/s | 5,102,898,499.31 keys/s | **2386.95x** |
| **4.2B Keys Time** | ~33.48 min | 0.8417 s | **2386.95x** |
| **Parallelism** | Single-threaded | Multi-threaded (Rayon) | Hardware-bound |

**Verdict**: The migration to Rust provides a three-orders-of-magnitude increase in execution efficiency for CPU-bound agentic tasks.

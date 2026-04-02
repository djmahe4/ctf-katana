---
name: raum-dev-benchmarker
description: Expert skill for performance benchmarking and empirical validation. Runs 'runner.py' to calculate L_r (Latency Reduction) and uses @free-llms for automated data analysis and thesis reporting.
---

# Dev Benchmarker

The `raum-dev-benchmarker` skill is the "truth engine" for your thesis. It provides the numbers that prove the Rust **Crab** architecture is superior to the Python baseline.

## Context Anchors

- **Performance Baselines**: [PROGRESS.md](docs/PROGRESS.md)
- **Experimental Goals**: [Level 3.5: Performance Optimization](docs/MIGRATION_GUIDE.md#️-level-35-agentic-security-hardening--performance-optimization)

## Benchmarking Workflow

1.  **Prepare Environment**: Ensure `cargo build --release` has been run for the current Rust kernels.
2.  **Execute Runner**: Run the [Benchmark Runner](research/benchmarks/runner.py).
3.  **Analyze Results**: Invoke **@free-llms** with the prompt: *"Analyze these benchmark logs. Calculate the Latency Reduction Ratio (L_r) and update the baselines in dev/benchmarker/references/lr-baselines.md"*.
4.  **Update Progress**: Use the [Report Templates](references/report-templates.md) to update [PROGRESS.md](docs/PROGRESS.md) and [MIGRATION_GUIDE.md](docs/MIGRATION_GUIDE.md).

## Success Conditions

-   **Empirical Rigor**: All benchmarks must be run at least 3 times to ensure statistical significance.
-   **Documentation Accuracy**: $L_r$ values in the migration guide must match the latest `runner.py` output.
-   **Thesis-Ready Output**: Data is formatted as LaTeX-ready tables or Markdown charts.

## Common Triggers
-   "How much faster is the new Rust kernel?"
-   "Run the benchmarking suite and give me a report."
-   "Update the thesis performance chapter with new data."

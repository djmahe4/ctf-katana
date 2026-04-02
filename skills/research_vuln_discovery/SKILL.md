---
name: vuln-discovery
description: Automated vulnerability discovery engine for high-fidelity security research. Use for identifying vulnerabilities in code, repos, binaries, or URLs using Nuclei and custom logic.
risk: moderate
source: local
---

# Vulnerability Discovery Agent

This skill orchestrates the automated discovery of security vulnerabilities by combining static analysis, dynamic testing (Nuclei), and knowledge-guided hunting.

## Core Triggers

- `Discovery_Target`: Identifying vulnerabilities in a specific path, repository, or URL.
- `Nuclei_Check`: Requesting verification of a target against known templates.
- `Security_Audit`: Performing an end-to-end audit for specific vulnerability classes (e.g., RCE, SQLi, LFI).
- `CVE_Verification`: Confirming if a specific CVE is present on a target.

## Mandatory Context

- `Target_Type`: (`code`, `web`, `repo`, `binary`) - Crucial for selecting the discovery engine.
- `Vuln_Classes`: List of specific vulnerabilities to prioritize (e.g., `["rce", "sqli"]`).
- `Discovery_Depth`: (`quick`, `medium`, `deep`) - Controls the intensity of the scan.
- `Nuclei_Templates`: (Optional) Custom template paths to include in the scan.

## Orchestration Workflow

1. **Reconnaissance**: Identify the target type and language (if code).
2. **Template Selection**: Query the `NucleiManager` for relevant templates based on `Vuln_Classes`.
3. **Execution**: Run the `vuln_discovery/run.py` script with the resolved context.
4. **Analysis**: Parse findings and categorize them by severity.
5. **Deduplication**: Compare with existing entries in the `vulnerability_catalog`.

## When to Use

- When tasked with finding security flaws in a new repository or live service.
- When generating CTF challenges based on target-specific vulnerabilities.
- For periodic security checks on project dependencies.

## When NOT to Use

- For generic bug hunting (use a standard linter/static analyzer instead).
- When the target is entirely unknown and requires intensive manual reverse engineering first.

## Strategy: Advanced Hunting

> [!TIP]
> Use "Knowledge-Guided Hunting" by cross-referencing your target's tech stack with the `DiscoveryAgent`'s latest CVE delta reports. This ensures you find the most recent, often unpatched, vulnerabilities.

---
name: web
description: Advanced Web Security & Exploit Orchestrator. Refactored for modular handling of Injection, Auth, XSS, Access Control, and more with LLM-driven 'Think' mode and automated exploit chaining.
risk: moderate
source: local
---

# Advanced Web Security & Exploit Orchestrator

This skill provides a unified, next-generation orchestration layer for modern web application security, spanning traditional reconnaissance to complex vulnerability chaining and LLM-driven attack surface analysis.

## Core Capabilities

- **Discovery (DiscoveryHandler)**: Initial surface mapping including header analysis, robots.txt, and security.txt.
- **Injection (InjectionHandler)**: Detection and exploitation of SQLi, NoSQLi, Command Injection, and SSTI.
- **Authentication (AuthHandler)**: JWT tampering (`alg: none`, payload analysis) and session cookie audit.
- **XSS (XSSHandler)**: Context-aware detection and exploitation of Stored, Reflected, and DOM XSS.
- **Access Control (AccessHandler)**: Identify Broken Access Control flaws including IDOR and privilege escalation.
- **Web Designer (LLM-Engine)**: Brainstorming complex attack chains and custom bypass payloads using Llama-3.3-70b.

## Mandatory Context

- `Target`: URL or local codebase path.
- `Mode`: (`auto`, `discovery`, `injection`, `auth`, `xss`, `access`).
- `Action`: (`analyze`, `fuzz`, `exploit`, `think`, `mutate`).
- `Token`: (Optional) JWT or session cookie for auth analysis.

## Modular Architecture

The skill is organized into specialized, extensible handlers:
1. `DiscoveryHandler`: Enhanced reconnaissance and fingerprinting.
2. `InjectionHandler`: Unified logic for all injection vulnerabilities.
3. `AuthHandler`: JWT and session-specific analysis.
4. `XSSHandler`: Precision detection of Cross-Site Scripting.
5. `AccessHandler`: Logic-heavy access control testing.
6. `WebDesigner`: Intelligent engine for complex exploit designs.

## Execution Workflow

1. **Discovery**: `python skills/web/run.py <url> --mode discovery` to map the target.
2. **Strategy Brainstorming**: `python skills/web/run.py <url> --action think --prompt "..."` to design exploit chains.
3. **Targeted Exploitation**: Use specialized modes (e.g. `--mode auth --token "..."`) for in-depth analysis.
4. **Automated Analysis**: `python skills/web/run.py <url> --mode auto` to let the orchestrator decide.

## When to Use

- When performing comprehensive web application audits.
- When existing basic scripts (`web_exploit`) fail to find complex vulnerabilities.
- For brainstorming and designing multi-stage exploit chains for CTFs.

## When NOT to Use

- For high-volume load testing or simple directory brute-forcing (use `fuzzing` skill).
- On targets where intrusive scanning is strictly prohibited.

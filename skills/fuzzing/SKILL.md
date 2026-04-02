---
name: fuzzing
description: Advanced Fuzzing & Target Designer Engine. Refactored for modular handling of Web, Binary, Protocol, and Cloud targets with LLM-driven mutation and harness generation.
risk: moderate
source: local
---

# Advanced Fuzzing & Target Designer

This skill provides a unified orchestration layer for modern fuzzing, spanning traditional web discovery to cloud-native emulation and binary harness generation.

## Core Capabilities

- **Web Fuzzing**: Directory, parameter, and header discovery with integrated `ffuf` support.
- **Binary Analysis**: ELF/PE static analysis and automatic generation of `AFL++` or `LibFuzzer` harnesses.
- **Protocol Fuzzer**: Scapy-based template generation for stateful, custom network protocol fuzzing.
- **Cloud-Native Scaffolding**: LocalStack/SAM template generation for fuzzing serverless functions (Lambda, Azure Functions).
- **LLM-Driven "Think" Mode**: Utilizing Llama models to analyze attack surfaces and draft complex mutation engines.

## Mandatory Context

- `Target`: URL, file path, or protocol name.
- `Mode`: (`web`, `binary`, `protocol`, `cloud`, `auto`).
- `Action`: (`fuzz`, `analyze`, `harness`, `think`, `mutate`).
- `Payload_Type`: (`generic`, `sqli`, `xss`, `lfi`, `rce`, `ssti`).

## Modular Architecture

The skill is organized into specialized handlers:
1. `WebHandler`: Enhanced web discovery and parameter fuzzing.
2. `BinaryHandler`: Binary vulnerability detection and fuzzer integration.
3. `ProtocolHandler`: Stateful network protocol templates.
4. `CloudHandler`: Serverless emulation scaffolding.
5. `FuzzDesigner`: LLM engine for mutation scripts and strategy brainstorming.

## Execution Workflow

1. **Discovery**: Use `fuzzing/run.py <target> --mode auto` to identify the target type.
2. **Strategy Generation**: Use `--action think --prompt "..."` to brainstorm fuzzer designs.
3. **Scaffolding**: Generate harnesses (`--action harness`) or cloud templates (`--mode cloud`).
4. **Fuzzing**: Run active fuzzing sessions with `fuzzing/run.py`.
5. **Mutation**: Create custom Python mutation scripts with `--action mutate`.

## When to Use

- When building or breaking CTF challenges.
- When standard fuzzer configurations are insufficient for complex protocols.
- When auditing serverless cloud-native applications locally.

## When NOT to Use

- For production-scale, long-running heavy binary fuzzing (use dedicated fuzzer clusters).
- On targets where rate-limiting is strictly enforced without rotating proxies.

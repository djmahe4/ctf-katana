# IoT/Embedded Security Analyzer

## Overview
A research-driven, modular security scanner for IoT and Embedded devices. It supports both high-level firmware filesystem analysis and low-level binary static analysis.

## Key Features
- **Modular Analysis Engine**: Extensible vulnerability modules for targeted scanning.
- **Firmware rootfs Scanning**: Deep inspection of extracted filesystems for secrets, misconfigurations, and backdoors.
- **Binary Static Analysis**: Detection of dangerous function calls, format string vulnerabilities, and missing compiler protections (Stack Canaries).
- **Proactive CLI Utility**: Integrated tools for string extraction and architecture detection.

## Multi-Chain Research Integration
While independent of the Web3 skill, the IoT analyzer follows the same robust metadata standards, ensuring findings include severity, remediation, and evidence.

## Usage
Run the analyzer from the workspace root or directly via its `run.py` using the `.venv` environment.

### Firmware Analysis
Scan an extracted root filesystem directory:
```powershell
python skills/iot_embedded/run.py path/to/rootfs --mode firmware
```

### Binary Analysis
Scan a compiled ELF binary:
```powershell
python skills/iot_embedded/run.py path/to/target_binary --mode binary
```

### Full Scan
Automatically detects the target type and performs the appropriate analysis:
```powershell
python skills/iot_embedded/run.py path/to/target --mode full
```

## Vulnerability Database
The analyzer pulls from a curated database of IoT security patterns, categorized into:
- **Firmware**: Hardcoded Secrets, Insecure Services, Sensitive File Exposure, Weak Permissions, Command Injection, Debug Accounts.
- **Binary**: Dangerous C Functions, Format String Vulnerabilities, Weak Crypto, Hardcoded Endpoint Addresses.

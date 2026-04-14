# Kavach AI Firewall Integration

**Python security wrapper for Purple Engine MCP skill executions**

Adapts the Kavach EDR concepts from [github.com/LucidAkshay/kavach](https://github.com/LucidAkshay/kavach) (Tauri/Rust desktop EDR application) into a Python library for autonomous AI agent containment.

---

## Overview

Kavach (Sanskrit for "Armor") provides comprehensive security layer around skill executions with:

- **Phantom Workspace:** Isolated copy-on-write workspace for safe destructive operations
- **Auto-Enforcer:** Automatic timeout-based process termination
- **Tripwire Monitor:** Honeypot files that trigger alarms when accessed
- **PII Sanitizer:** Real-time detection and redaction of sensitive data
- **Audit Ledger:** Cryptographic immutable log of all security events
- **Loop Detection:** Prevents high-velocity repetitive command loops
- **Process Monitoring:** Limits and tracks child process spawning

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    Skill Execution                       │
├──────────────────────────────────────────────────────────┤
│                   KavachWrapper                          │
│  ┌────────────────────────────────────────────────────┐  │
│  │  1. PhantomWorkspace (intercept file operations)   │  │
│  │  2. PIISanitizer (scan output for secrets)         │  │
│  │  3. AutoEnforcer (timeout monitoring)              │  │
│  │  4. TripwireMonitor (honeypot detection)           │  │
│  │  5. AuditLedger (log all events)                   │  │
│  └────────────────────────────────────────────────────┘  │
├──────────────────────────────────────────────────────────┤
│                 SecurityPolicy (YAML config)             │
└──────────────────────────────────────────────────────────┘
```

---

## Quick Start

### 1. Installation

```python
# Already included in Purple Engine
# Dependencies: psutil, pyyaml
```

### 2. Basic Usage

```python
from skills.firewall.kavach import KavachWrapper, SecurityPolicy
from pathlib import Path

# Load security policy
policy = SecurityPolicy.from_yaml(
    Path("configs/kavach/security-policies.yaml")
)

# Or use predefined profiles
policy = SecurityPolicy.default_strict()  # Maximum security
policy = SecurityPolicy.default_standard()  # Balanced
policy = SecurityPolicy.default_permissive()  # Minimal restrictions

# Create wrapper
wrapper = KavachWrapper(
    policy=policy,
    workspace=Path.cwd(),
)

# Execute skill with protection
def my_skill_function(param1, param2):
    # Skill code here
    return {"status": "success"}

result = wrapper.execute(
    my_skill_function,
    skill_name="my_skill",
    param1="value1",
    param2="value2"
)

print(result)
# {
#     'status': 'success',
#     'result': {'status': 'success'},
#     'audit': {
#         'duration': 0.123,
#         'pii_detections': 0,
#         'phantom_operations': {'write': 2, 'delete': 1}
#     }
# }
```

### 3. Context Manager Pattern

```python
from skills.firewall.kavach import KavachWrapper, SecurityPolicy

policy = SecurityPolicy.default_standard()
wrapper = KavachWrapper(policy=policy)

try:
    # Execute protected skill
    result = wrapper.execute(skill_func, "skill_name", *args, **kwargs)
finally:
    # Cleanup resources
    wrapper.cleanup()
```

---

## Core Components

### PhantomWorkspace

Intercepts destructive file operations and redirects them to `.kavach_phantom` directory:

```python
from skills.firewall.kavach import PhantomWorkspace
from pathlib import Path

phantom = PhantomWorkspace(
    real_workspace=Path.cwd(),
    phantom_dir_name=".kavach_phantom"
)

# Intercept write operation
content = b"malicious data"
phantom_path = phantom.intercept_write(
    Path("important_file.txt"),
    content
)
# File written to .kavach_phantom/important_file.txt instead

# Intercept delete
phantom.intercept_delete(Path("database.sqlite"))
# File moved to .kavach_phantom instead of deleted

# Rollback changes (1-click restore)
phantom.rollback_file(Path("important_file.txt"))

# Or commit changes (make permanent)
phantom.commit_changes()

# Or discard everything
phantom.discard_changes()
```

**Features:**
- ✅ Copy-on-write semantics
- ✅ Automatic file snapshots (<50MB files)
- ✅ 1-click rollback
- ✅ Operation tracking
- ✅ Batch commit/discard

### PIISanitizer

Detects and redacts sensitive data in outputs:

```python
from skills.firewall.kavach import PIISanitizer

sanitizer = PIISanitizer()

text = """
Here's my API key: sk-1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890
And my email: user@example.com
Credit card: 4532-1234-5678-9010
"""

sanitized_text, detections = sanitizer.sanitize(text)

print(sanitized_text)
# Here's my API key: sk-12345***********************************
# And my email: ****@example.com
# Credit card: ************9010

print(detections)
# [
#     {'type': 'openai_key', 'value': 'sk-...', 'entropy': 4.8},
#     {'type': 'email', 'value': 'user@example.com', 'entropy': 3.2},
#     {'type': 'credit_card', 'value': '4532-1234-5678-9010', 'entropy': 2.1},
# ]
```

**Detected PII Types:**
- OpenAI API keys (`sk-...`)
- AWS keys (`AKIA...`)
- GitHub tokens (`ghp_...`)
- Credit cards (Luhn validated)
- Email addresses
- Private keys (PEM format)
- JWT tokens
- Generic high-entropy secrets

### AutoEnforcer

Automatic timeout-based process termination:

```python
from skills.firewall.kavach import AutoEnforcer
import os
import time

enforcer = AutoEnforcer(
    timeout_seconds=60,
    check_interval=1.0
)

# Start background enforcement thread
enforcer.start()

# Monitor a process
enforcer.monitor_process(
    pid=os.getpid(),
    command="long_running_task.py"
)

# If process runs > 60 seconds, auto-enforcer will SIGTERM/SIGKILL it

# Stop enforcement
enforcer.stop()
```

**Features:**
- ✅ Background thread monitoring
- ✅ Graceful SIGTERM → SIGKILL escalation
- ✅ Process tree tracking
- ✅ Configurable timeout and check interval

### TripwireMonitor

Honeypot files that detect suspicious access:

```python
from skills.firewall.kavach import TripwireMonitor
from pathlib import Path

tripwire = TripwireMonitor(
    workspace=Path.cwd(),
    custom_tripwires={
        "fake_credentials.json": '{"password": "admin123"}',
    }
)

# Deploy tripwires
tripwire.deploy()

# Check if file access triggers tripwire
if tripwire.check_access(Path("fake_credentials.json")):
    print("🚨 TRIPWIRE TRIGGERED!")
    # Take defensive action

# Cleanup at end
tripwire.cleanup()
```

**Default Tripwires:**
- `system_auth_tokens.json` - Fake AWS/OpenAI keys
- `.env.production` - Fake database credentials
- `credentials.txt` - Fake admin credentials

### AuditLedger

Cryptographic immutable audit log:

```python
from skills.firewall.kavach import AuditLedger
from pathlib import Path

ledger = AuditLedger(
    ledger_path=Path("~/.purple-engine/kavach_audit.jsonl")
)

# Log security event
event_hash = ledger.log_event(
    event_type="pii_detected",
    skill_name="ctfd_solve",
    severity="CRITICAL",
    details={"pii_type": "openai_key", "count": 1}
)

# Verify ledger integrity
is_valid, errors = ledger.verify_integrity()

# Query events
recent_critical = ledger.query_events(
    severity="CRITICAL",
    limit=10
)
```

**Features:**
- ✅ FNV-1a hash chain (blockchain-style)
- ✅ Tamper-proof
- ✅ JSONL format (append-only)
- ✅ Integrity verification
- ✅ Event querying

---

## Security Policies

### Policy Profiles

**Strict** (Maximum Security):
```yaml
allowed_read_paths: ["context/*", "skills/*", "configs/*"]
allowed_write_paths: ["context/outputs/*", "/tmp/*"]
allow_network: false
max_child_processes: 3
execution_timeout: 60
enable_phantom_workspace: true
enable_tripwires: true
sanitize_pii: true
```

**Standard** (Balanced):
```yaml
allowed_read_paths: ["*"]
allowed_write_paths: ["context/*", "skills/*/outputs/*", "/tmp/*"]
allow_network: true
max_child_processes: 10
execution_timeout: 300
enable_phantom_workspace: true
enable_tripwires: true
sanitize_pii: true
```

**Permissive** (Development):
```yaml
allowed_read_paths: ["*"]
allowed_write_paths: ["*"]
allow_network: true
max_child_processes: 20
execution_timeout: 600
enable_phantom_workspace: false
enable_tripwires: false
sanitize_pii: false
```

### Per-Skill Overrides

```yaml
skill_overrides:
  ctfd_solve:
    profile: "standard"
    allow_network: true
    execution_timeout: 600
  
  research_agent:
    profile: "standard"
    allowed_domains:
      - "github.com"
      - "arxiv.org"
```

---

## Exceptions

All security violations raise `KavachSecurityViolation` or subclasses:

```python
from skills.firewall.kavach.exceptions import (
    KavachSecurityViolation,      # Base exception
    PhantomWorkspaceError,         # Phantom workspace failures
    PIIDetectionError,             # PII sanitization errors
    TripwireTriggered,             # Honeypot access
    ExecutionTimeoutError,         # Auto-enforcer timeout
    FileAccessViolation,           # Unauthorized file access
    NetworkAccessViolation,        # Unauthorized network access
    ProcessLimitExceeded,          # Too many child processes
    LoopDetectionError,            # High-velocity command loop
)

try:
    wrapper.execute(skill_func, "skill_name")
except TripwireTriggered as e:
    print(f"Tripwire triggered: {e.tripwire_path}")
    print(f"Access type: {e.access_type}")
except PIIDetectionError as e:
    print(f"PII detected: {e.pii_type} (count: {e.detected_count})")
except KavachSecurityViolation as e:
    print(f"Security violation: {e}")
    print(f"Severity: {e.severity}")
    print(f"Context: {e.context}")
```

---

## Integration with Purple Engine

Kavach automatically wraps all MCP skill executions through registry modification:

```python
# In server/registry.py (future integration)
from skills.firewall.kavach import KavachWrapper, SecurityPolicy

class SkillRegistry:
    def __init__(self):
        self.policy = SecurityPolicy.from_yaml(
            Path("configs/kavach/security-policies.yaml")
        )
        self.kavach = KavachWrapper(policy=self.policy)
    
    def execute_skill(self, skill_name, skill_func, *args, **kwargs):
        # All skills automatically protected
        return self.kavach.execute(skill_func, skill_name, *args, **kwargs)
```

---

## Advanced Features

### Loop Detection

```python
from skills.firewall.kavach.monitor import LoopDetector

detector = LoopDetector(
    threshold=10,  # Max repetitions
    time_window=30.0  # In 30 seconds
)

for _ in range(15):
    command = "npm install"
    
    if detector.check_loop(command):
        print("🔁 LOOP DETECTED - Terminating!")
        break
    
    # Execute command...
```

### File System Watching

```python
from skills.firewall.kavach.monitor import FileWatcher
from pathlib import Path

watcher = FileWatcher(
    workspace=Path.cwd(),
    tripwire_monitor=tripwire,
    on_violation=lambda event, path, access_type: print(f"Violation: {path}")
)

watcher.start()
# Monitors file system in real-time
# ...
watcher.stop()
```

### Process Monitoring

```python
from skills.firewall.kavach.monitor import ProcessMonitor

monitor = ProcessMonitor(max_children=10)

monitor.register_parent(parent_pid=1234)
monitor.check_and_register_child(parent_pid=1234, child_pid=5678)

# Raises ProcessLimitExceeded if too many children
```

---

## Comparison with Original Kavach

| Feature | Original Kavach (Tauri/Rust) | Purple Engine Integration (Python) |
|---------|------------------------------|-------------------------------------|
| **Platform** | Desktop EDR application | Library for AI agent containment |
| **Language** | Rust (backend) + React (UI) | Python |
| **Phantom Workspace** | ✅ Full implementation | ✅ Python equivalent |
| **Auto-Enforcer** | ✅ Rust background thread | ✅ Python threading |
| **Tripwires** | ✅ Honeypot files | ✅ Python implementation |
| **PII Sanitizer** | ✅ "Gag Order" | ✅ Regex + entropy analysis |
| **Audit Ledger** | ✅ FNV hash chain | ✅ SHA-256 hash chain |
| **File Watching** | ✅ Native FS events | ✅ watchdog library (optional) |
| **Loop Detection** | ✅ Heuristic detection | ✅ Pattern matching |
| **UI Dashboard** | ✅ React webview | ❌ (CLI/logging only) |
| **Kernel Drivers** | 🚧 Roadmap (v1.2) | ❌ Not applicable |
| **Clipboard Guard** | ✅ Shannon entropy | 🚧 Optional (pyperclip) |
| **CVE Scanning** | ✅ Supply chain auditor | 🚧 Optional (safety) |

---

## Configuration

Full configuration reference: `configs/kavach/security-policies.yaml`

```bash
# Edit security policies
vim configs/kavach/security-policies.yaml

# Verify policy syntax
python -c "
from skills.firewall.kavach import SecurityPolicy
from pathlib import Path

policy = SecurityPolicy.from_yaml(
    Path('configs/kavach/security-policies.yaml')
)
print(f'Policy loaded: {policy.default_profile}')
print(f'Timeout: {policy.execution_timeout}s')
print(f'Max processes: {policy.max_child_processes}')
"
```

---

## Testing

```bash
# Test PII sanitizer
python -c "
from skills.firewall.kavach import PIISanitizer

sanitizer = PIISanitizer()
text = 'My key: sk-1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ'
sanitized, detections = sanitizer.sanitize(text)
print(sanitized)
print(f'{len(detections)} PII instances detected')
"

# Test phantom workspace
python -c "
from skills.firewall.kavach import PhantomWorkspace
from pathlib import Path

phantom = PhantomWorkspace(Path.cwd())
phantom.intercept_write(Path('test.txt'), b'data')
print(f'Phantom operations: {phantom.get_operation_summary()}')
phantom.discard_changes()
"

# Test audit ledger integrity
python -c "
from skills.firewall.kavach import AuditLedger

ledger = AuditLedger()
ledger.log_event('test', 'test_skill', 'INFO', {})
is_valid, errors = ledger.verify_integrity()
print(f'Ledger valid: {is_valid}')
"
```

---

## Roadmap

### Phase 2 (Current)
- [x] Core components (PhantomWorkspace, PIISanitizer, AuditLedger)
- [x] Monitoring (AutoEnforcer, TripwireMonitor, FileWatcher)
- [x] Security policies (YAML configuration)
- [ ] Registry integration (wrap all skill executions)
- [ ] Comprehensive tests

### Phase 2.5 (Enhancements)
- [ ] Web dashboard (optional Gradio UI for audit log viewing)
- [ ] Advanced clipboard monitoring (Faraday Guard)
- [ ] CVE scanning integration (Supply Chain Auditor)
- [ ] Blast radius analysis (dependency mapping before deletion)
- [ ] CPU throttling (PID Chokehold)

### Future
- [ ] Network traffic interception (local proxy)
- [ ] Machine learning anomaly detection
- [ ] Integration with external SIEM systems

---

## License

GPLv3 - Same as original Kavach by Akshay Sharma

Attribution to original Kavach project required: github.com/LucidAkshay/kavach

---

## Credits

**Original Kavach EDR:** Akshay Sharma (@LucidAkshay)  
**Python Integration:** Purple Engine Team  
**Inspired by:** Original Kavach architecture and security concepts

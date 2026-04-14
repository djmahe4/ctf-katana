# Handoff Protocol (ctf-katana)

To prevent context loss ("Agentic Decay"), all skills must share data using a standardized **Metadata Protocol**.

## Core Schema

```json
{
  "source_skill": "web_exploit",
  "target_skill": "kavach",
  "payload": {
    "vulnerability_type": "rce",
    "entry_point": "http://target/api/upload",
    "exploit_primitive": "python_reverse_shell"
  },
  "confidence": 0.95,
  "requires_verification": true
}
```

## Implementation (Python)

When a skill finishes, it should return its findings in the `metadata` field of the tool response.

```python
# skills/web/run.py
def execute(self, params):
    # ... exploit logic ...
    return {
        "output": "Exploit successful",
        "metadata": {
            "handoff": {
                "type": "binary_path",
                "path": "/tmp/dumped_binary"
            }
        }
    }
```

## Implementation (Rust "Crab")

In the Level 2/3 migration, handoffs are managed via the `StateStore` (SQLite/Redis).

-   **Write**: `crab_put_state(key, value)`
-   **Read**: `crab_get_state(key)`

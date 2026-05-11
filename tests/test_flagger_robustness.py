import sys
import os
import subprocess
import json
import pytest

# Add project root to sys.path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, project_root)

from skills.flagger.run import run as run_flagger

def test_flagger_grepability():
    print("Testing flagger grepability...")
    flag = "flag{robustness_test_123}"
    params = {
        "flag": flag,
        "level": "expert",
        "handler": "reverse",
        "template": "python"
    }
    
    result = run_flagger(params)
    assert result.get("status"), f"FAILED: Flagger run failed: {result.get('summary')}"
        
    payload = result["result"]["payload"]
    lines = payload.strip().split("\n")
    last_line = lines[-1]
    
    print(f"Last line: {last_line}")
    
    assert last_line.startswith("flag ="), "[FAILURE] Last line is NOT flag assignment."
        
    # Test grepability
    temp_file = "scratch/temp_payload.py"
    os.makedirs("scratch", exist_ok=True)
    with open(temp_file, "w") as f:
        f.write(payload)
        
    try:
        # Check if we can find the final assignment
        output = subprocess.check_output(['grep', '-i', 'flag =', temp_file], text=True)
        print(f"Grep output:\n{output}")
        # The last line of grep output should be our final assignment
        grep_lines = output.strip().split("\n")
        assert grep_lines[-1] == last_line, "[FAILURE] Grep mismatch."
    except Exception as e:
        if isinstance(e, AssertionError):
            raise
        pytest.fail(f"[ERROR] Grep failed: {e}")
        
    print("[DONE] All flagger robustness tests passed.")

if __name__ == "__main__":
    test_flagger_grepability()

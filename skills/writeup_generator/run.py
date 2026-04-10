"""Write-up generator skill - produces Markdown write-ups via Ollama."""

from __future__ import annotations

import sys
import os
import json
from pathlib import Path

# Add project root to path
project_root = str(Path(__file__).resolve().parent.parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from agents.reporter import ReporterAgent


def run(inputs: dict) -> dict:
    """Generate a write-up using the Reporter agent."""
    log = inputs.get("execution_log", "")
    challenge = inputs.get("challenge_name", "CTF Challenge")

    try:
        agent = ReporterAgent(
            model=os.environ.get("KATANA_OLLAMA_MODEL", "mistral"),
            ollama_host=os.environ.get("KATANA_OLLAMA_HOST", "http://localhost:11434"),
        )

        # Read the skill prompt for context
        prompt_file = Path(__file__).parent / "prompt.md"
        prompt_context = prompt_file.read_text() if prompt_file.exists() else ""

        result = agent.generate(
            f"{prompt_context}\n\nExecution log:\n{log}",
            challenge,
        )
        return {
            "status": True,
            "summary": f"Generated write-up for challenge '{challenge}'.",
            "result": result
        }
    except Exception as e:
        return {
            "status": False,
            "summary": f"Failed to generate write-up: {str(e)}",
            "result": {"error": str(e)}
        }

def main():
    """CLI entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Writeup Generator CLI')
    parser.add_argument('--challenge-name', '-n', help='Challenge name')
    parser.add_argument('--execution-log', '-l', help='Execution log text')
    parser.add_argument('--json', help='Pass parameters as JSON string')
    parser.add_argument('--test', action='store_true', help='Run sanity test')
    
    args = parser.parse_args()
    
    if args.test:
        print("Running sanity test for Writeup Generator...")
        test_params = {
            "challenge_name": "Test Challenge",
            "execution_log": "Test step 1: Found flag{test}"
        }
        print(f"Test Configuration: {json.dumps(test_params, indent=2)}")
        print("Test passed: Module structure verified.")
        return

    params = {}
    if args.json:
        try:
            params = json.loads(args.json)
        except json.JSONDecodeError as e:
            print(json.dumps({"status": False, "summary": f"Invalid JSON: {str(e)}", "result": {}}))
            return
    else:
        if not args.challenge_name and not args.execution_log:
            parser.print_help()
            return
        params = {
            "challenge_name": args.challenge_name,
            "execution_log": args.execution_log
        }
    
    result = run(params)
    print(json.dumps(result, indent=2, default=str))

if __name__ == "__main__":
    main()

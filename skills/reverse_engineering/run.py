import sys
import os
import argparse
import logging
from pathlib import Path

# Ensure project skills directory is in path
sys.path.append(str(Path(__file__).resolve().parent.parent))

from reverse_engineering.handlers.binary_handler import BinaryHandler
from reverse_engineering.engines.tech_designer import TechDesigner

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("skills.reverse_engineering.run")

def run(inputs: dict) -> dict:
    """Skill entry-point called by the registry."""
    path = inputs.get("path")
    action = inputs.get("action", "disassemble")
    
    # Think action (LLM-driven)
    if action == "think":
        prompt = inputs.get("prompt")
        if not prompt:
            return {"error": "--prompt required for 'think' action."}
        designer = TechDesigner(model=inputs.get("model", "groq/llama-3.3-70b-versatile"))
        logger.info(f"[*] Triggering Llama-based technical RE brainstorming: '{prompt}'")
        # Agent uses free-llm-apis/think tools in practice
        return {"status": "think_success", "prompt": prompt}

    if not path:
        return {"error": "Path parameter required for binary analysis."}

    handler = BinaryHandler()
    logger.info(f"[*] Running binary analyst for {path} with action {action}")
    
    # Technical Analysis
    result = handler.analyze_binary(path, action)
    
    return result

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CTF-Katana Binary Analyst (ReverseEngineering v2)")
    parser.add_argument("path", nargs="?", help="Path to binary file.")
    parser.add_argument("--action", "-a", choices=["disassemble", "symbols", "elf_info", "think"], default="disassemble")
    parser.add_argument("--prompt", help="Technical RE designer prompt.")
    parser.add_argument("--model", help="LLM model.")

    args = parser.parse_args()
    print(run(vars(args)))

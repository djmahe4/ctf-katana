import sys
import os
import argparse
import logging
from pathlib import Path

# Standardize path for standalone execution
project_root = Path(__file__).resolve().parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

try:
    from skills.reverse_engineering.handlers.binary_handler import BinaryHandler
    from skills.reverse_engineering.engines.tech_designer import TechDesigner
except ImportError:
    # Fallback for different execution contexts
    from .handlers.binary_handler import BinaryHandler
    from .engines.tech_designer import TechDesigner

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("skills.reverse_engineering.run")

def run(params: dict) -> dict:
    """Skill entry-point called by the registry."""
    path = params.get("path")
    action = params.get("action", "disassemble")
    
    # Think action (LLM-driven)
    if action == "think":
        prompt = params.get("prompt")
        if not prompt:
            return {"status": "error", "summary": "--prompt required for 'think' action."}
        # In practice, this would use free-llm-apis
        return {
            "status": "success", 
            "summary": f"Brainstorming initiated for: {prompt}", 
            "result": {"action": "think", "prompt": prompt}
        }

    if not path:
        return {"status": "error", "summary": "Path parameter required for binary analysis."}

    try:
        handler = BinaryHandler()
        logger.info(f"[*] Running binary analyst for {path} with action {action}")
        
        # Technical Analysis
        res_data = handler.analyze_binary(path, action)
        
        return {
            "status": "success",
            "summary": f"Technical analysis '{action}' completed on {path}.",
            "result": res_data
        }
    except Exception as e:
        return {"status": "error", "summary": str(e)}

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CTF-Katana Binary Analyst (ReverseEngineering v2)")
    parser.add_argument("path", nargs="?", help="Path to binary file.")
    parser.add_argument("--action", "-a", choices=["disassemble", "symbols", "elf_info", "think", "ghidra_decompile"], default="disassemble")
    parser.add_argument("--prompt", help="Technical RE designer prompt.")
    parser.add_argument("--model", help="LLM model.")

    args = parser.parse_args()
    print(run(vars(args)))

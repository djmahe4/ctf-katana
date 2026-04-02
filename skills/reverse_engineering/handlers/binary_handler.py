import logging
import subprocess
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class BinaryHandler:
    """Handler for technical binary analysis (ELF/PE)."""

    def analyze_binary(self, path: str, action: str) -> Dict[str, Any]:
        """Orchestrates technical analysis actions."""
        if action == "disassemble":
            return self.disassemble(path)
        elif action == "symbols":
            return self.show_symbols(path)
        elif action == "elf_info":
            return self.show_elf_info(path)
        elif action == "ghidra_decompile":
            return self.decompile_ghidra(path)
        else:
            return {"error": f"Unknown action: {action}"}

    def decompile_ghidra(self, path: str) -> Dict[str, Any]:
        """Wrapper for Ghidra headless decompiler."""
        from reverse_engineering.engines.ghidra_engine import GhidraEngine
        import asyncio
        
        engine = GhidraEngine()
        # Note: Since the handler is currently synchronous, we run the async engine in a loop
        # In a full-async refactor, this would be await engine.decompile(...)
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
        result = loop.run_until_complete(engine.decompile(path, os.path.dirname(path)))
        return result

    def disassemble(self, path: str) -> Dict[str, Any]:
        """Simple wrapper for objdump (simulated for current environment)."""
        logger.info(f"[*] Disassembling: {path}")
        # In practice, this calls tools.objdump_runner
        return {"action": "disassemble", "target": path, "status": "success", "asm_count": 0}

    def show_symbols(self, path: str) -> Dict[str, Any]:
        """Simple wrapper for nm (simulated)."""
        logger.info(f"[*] Extracting symbols: {path}")
        return {"action": "symbols", "target": path, "status": "success", "symbol_count": 0}

    def show_elf_info(self, path: str) -> Dict[str, Any]:
        """Simple wrapper for readelf (simulated)."""
        logger.info(f"[*] Extracting ELF info: {path}")
        return {"action": "elf_info", "target": path, "status": "success"}

# -*- coding: utf-8 -*-
import os
import subprocess
import logging
import asyncio
from pathlib import Path
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

class GhidraEngine:
    """
    Technical Binary Analyst Engine powered by Ghidra (Headless).
    """
    
    def __init__(self, ghidra_path: Optional[str] = None):
        self.ghidra_path = ghidra_path or os.environ.get('KATANA_GHIDRA_PATH')
        self.analyze_headless = None
        if self.ghidra_path:
            self.analyze_headless = Path(self.ghidra_path) / "support" / "analyzeHeadless.bat"

    async def ensure_path(self) -> bool:
        """Interactive/HITL path configuration if missing."""
        if self.ghidra_path and self.analyze_headless and self.analyze_headless.exists():
            return True
            
        print("\n" + "="*50)
        print("🔍 Ghidra Headless (analyzeHeadless.bat) not found.")
        print("Please provide the path to your Ghidra installation folder.")
        print("Example: C:\\Tools\\ghidra_11.0_PUBLIC")
        print("="*50)
        
        path_input = await asyncio.get_event_loop().run_in_executor(None, input, "Ghidra Path: ")
        if not path_input:
            logger.warning("No Ghidra path provided. Ghidra features will be disabled.")
            return False
            
        self.ghidra_path = path_input.strip('"')
        self.analyze_headless = Path(self.ghidra_path) / "support" / "analyzeHeadless.bat"
        
        if not self.analyze_headless.exists():
             # Try nested folder if user pointed to the root containing the zip name
             alt_path = list(Path(self.ghidra_path).glob("ghidra_*"))
             if alt_path and (alt_path[0] / "support" / "analyzeHeadless.bat").exists():
                 self.ghidra_path = str(alt_path[0])
                 self.analyze_headless = Path(self.ghidra_path) / "support" / "analyzeHeadless.bat"
                 
        if self.analyze_headless.exists():
            logger.info(f"[SUCCESS] Ghidra found at: {self.ghidra_path}")
            return True
        else:
            logger.error(f"[ERROR] Could not find analyzeHeadless.bat at {self.analyze_headless}")
            return False

    async def decompile(self, binary_path: str, output_dir: str) -> Dict[str, Any]:
        """Decompile a binary using Ghidra's headless mode."""
        if not await self.ensure_path():
            return {'status': False, 'message': 'Ghidra not configured.'}
            
        binary_path = str(Path(binary_path).resolve())
        project_dir = str(Path(output_dir).resolve() / "ghidra_project")
        os.makedirs(project_dir, exist_ok=True)
        
        # Ghidra Headless Command: 
        # analyzeHeadless <project_path> <project_name> -import <binary> -postScript Decompile.java <output>
        # Note: Requires Decompile.java script to be present in Ghidra's script path or provided.
        
        cmd = [
            str(self.analyze_headless),
            project_dir,
            "KatanaProject",
            "-import", binary_path,
            "-deleteProject" # Clean up after analysis
        ]
        
        try:
            logger.info(f"[START] Running Ghidra Headless on {binary_path}...")
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                return {
                    'status': False, 
                    'message': f"Ghidra exited with code {process.returncode}",
                    'stderr': stderr.decode()
                }
                
            return {
                'status': True,
                'output_dir': project_dir,
                'stdout': stdout.decode()
            }
            
        except Exception as e:
            logger.error(f"Ghidra execution failed: {e}")
            return {'status': False, 'message': str(e)}

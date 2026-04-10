import os
import shutil
import subprocess
import logging
from pathlib import Path
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class APKCompiler:
    """Wrapper for apktool and build tools to unpack/repack APKs."""
    
    def __init__(self, apktool_path: str = "apktool"):
        self.apktool = apktool_path

    def unpack(self, apk_path: str, output_dir: str) -> bool:
        """Unpack APK to source using apktool."""
        logger.info(f"[*] Unpacking APK: {apk_path} -> {output_dir}")
        if os.path.exists(output_dir):
            shutil.rmtree(output_dir)
            
        cmd = [self.apktool, "d", apk_path, "-o", output_dir, "-f"]
        try:
            subprocess.run(cmd, check=True, capture_output=True)
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Unpack failed: {e.stderr.decode()}")
            return False

    def build(self, source_dir: str, output_apk: str) -> bool:
        """Repack source to APK using apktool."""
        logger.info(f"[*] Building APK from source: {source_dir} -> {output_apk}")
        cmd = [self.apktool, "b", source_dir, "-o", output_apk]
        try:
            subprocess.run(cmd, check=True, capture_output=True)
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Build failed: {e.stderr.decode()}")
            return False

    def sign(self, apk_path: str) -> bool:
        """Placeholder for APK signing (requires apksigner)."""
        logger.info(f"[*] Signing APK: {apk_path}")
        # Note: In a real environment, we'd use apksigner/uber-apk-signer here
        # For now, we assume development/debug builds or external signing.
        return True

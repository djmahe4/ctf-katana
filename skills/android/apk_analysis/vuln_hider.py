import os
import re
import logging
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)

class VulnerabilityHider:
    """Injects intentional security vulnerabilities into Android source code (smali)."""

    def hide_vulnerability(self, source_dir: str, vulnerability_type: str = "hardcoded_secret",flag:str = "CTF{K4T4N4_SM4L1_H1D3R}") -> bool:
        """Inject vulnerabilities into unpacked APK source folder."""
        logger.info(f"[*] Hiding vulnerability of type: {vulnerability_type} in {source_dir}")
        
        smali_files = list(Path(source_dir).rglob("*.smali"))
        if not smali_files:
            logger.error("No smali files found in source directory.")
            return False
            
        if vulnerability_type == "hardcoded_secret":
            return self._inject_hardcoded_secret(smali_files,flag)
        elif vulnerability_type == "insecure_logging":
            return self._inject_insecure_logging(smali_files)
        else:
            logger.warning(f"Vulnerability type {vulnerability_type} not supported yet.")
            return False

    def _inject_hardcoded_secret(self, smali_files: List[Path],flag:str = "CTF{K4T4N4_SM4L1_H1D3R}") -> bool:
        """Inject a hardcoded secret in a common place (e.g., MainActivity)."""
        secret_smali = f'\n    const-string v0, "{flag}"\n    iput-object v0, p0, Lcom/katana/MainActivity;->secret:Ljava/lang/String;\n'
        
        target_file = None
        for f in smali_files:
            if "MainActivity" in f.name:
                target_file = f
                break
        
        if not target_file:
            target_file = smali_files[0] # Fallback to first file
            
        logger.info(f"[*] Target for secret injection: {target_file}")
        
        with open(target_file, "r") as f:
            content = f.read()
            
        # Inject into constructor or onCreate (super simplified for demonstration)
        new_content = content.replace(".method constructor <init>()V", ".attribute secret \"Ljava/lang/String;\"\n\n.method constructor <init>()V")
        new_content = re.sub(r'(\.method.*constructor <init>\(\)V.*invoke-direct \{p0\}, Ljava/lang/Object;-><init>\(\)V)', r'\1' + secret_smali, new_content)
        
        with open(target_file, "w") as f:
            f.write(new_content)
            
        return True

    def _inject_insecure_logging(self, smali_files: List[Path]) -> bool:
        """Inject Log.d calls with sensitive info."""
        log_smali = '\n    const-string v0, "KatanaDebug"\n    const-string v1, "User interaction detected with sensitive context."\n    invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I\n'
        
        # Inject into any .method except constructor
        target_file = smali_files[0]
        with open(target_file, "r") as f:
            content = f.read()
            
        # Find first non-constructor method
        methods = re.findall(r'\.method (?!constructor).*', content)
        if methods:
            new_content = content.replace(methods[0], methods[0] + log_smali)
            with open(target_file, "w") as f:
                f.write(new_content)
            return True
        return False

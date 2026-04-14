import os
import subprocess
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from pathlib import Path
from skills.forensics.models import ForensicsFinding, ForensicsResult, ForensicsCategory, Severity

class ForensicsHandlerBase(ABC):
    """Abstract base class for forensic specialized handlers."""
    
    def __init__(self, category: ForensicsCategory):
        self.category = category

    @abstractmethod
    def analyze(self, target_path: Path, **kwargs) -> ForensicsResult:
        """Perform forensic analysis on the target."""
        pass

    def run_command(self, cmd: List[str], cwd: Optional[str] = None) -> str:
        """Helper to run system commands."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=cwd,
                check=False
            )
            return f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
        except Exception as e:
            return f"ERROR: Failed to execute {cmd[0]}: {str(e)}"

    def foremost_carving(self, target_path: Path, output_dir: Optional[Path] = None) -> List[str]:
        """Utility for automated file carving."""
        if output_dir is None:
            output_dir = target_path.parent / f"carved_{target_path.name}"
        
        output_dir.mkdir(exist_ok=True)
        # cmd = ["foremost", "-i", str(target_path), "-o", str(output_dir)]
        # Simulation if foremost is not installed or available via wrapper
        # return [str(f) for f in output_dir.rglob('*') if f.is_file()]
        return [] # Placeholder until tool presence is verified

    def add_finding(self, result: ForensicsResult, id: str, severity: Severity, description: str, evidence: str, file_path: str, remediation: str = ""):
        """Helper to add a finding to the result."""
        result.findings.append(ForensicsFinding(
            category=self.category,
            vulnerability_id=id,
            severity=severity,
            description=description,
            file_path=file_path,
            evidence=evidence,
            remediation=remediation
        ))

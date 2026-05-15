from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

class ReverseMode(Enum):
    OFFENSIVE = "offensive"   # RE logic (finding flags)
    SYNTHESIS = "synthesis"   # Creating challenges
    SYNERGY = "synergy"       # Both interactively

class ReverseSeverity(Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

class ReverseFinding(BaseModel):
    finder_id: str
    category: str
    description: str
    severity: ReverseSeverity
    logic_pattern: Optional[str] = None
    extracted_flag: Optional[str] = None
    pseudocode: Optional[str] = None

class ChallengeSpec(BaseModel):
    vulnerability_id: str
    target_language: str
    difficulty: str
    obfuscation_level: int = 0
    patterns: List[str] = []

class ReverseRunResult(BaseModel):
    target: str
    mode: ReverseMode
    success: bool
    summary: str
    findings: List[ReverseFinding] = []
    artifacts: List[str] = []
    statistics: Dict[str, Any] = {}


# ── SOLVE output contract ─────────────────────────────────────────────────────

class SolverInfo(BaseModel):
    """Describes the generated solver script."""
    type: str = Field(
        default="python",
        description="Solver type: pwntools | python | bash | web3",
    )
    path: str = Field(
        default="outputs/reverse/solver.py",
        description="Relative path to the solver script.",
    )
    validated: bool = Field(
        default=False,
        description="Whether the solver was validated by flagger.verify().",
    )


class SolveOutputContract(BaseModel):
    """
    Strict output contract for SOLVE mode (Mode A).

    Schema
    ------
    {
        "status": true,
        "summary": "...",
        "result": {
            "flag": "CTF{...}",
            "solver": {
                "type": "pwntools|python|bash|web3",
                "path": "outputs/reverse/solver.py",
                "validated": true
            },
            "findings": [...],
            "artifacts": [...],
            "writeup": "outputs/reverse/writeup.md"
        }
    }
    """
    flag: Optional[str] = None
    solver: SolverInfo = Field(default_factory=SolverInfo)
    findings: List[Dict[str, Any]] = []
    artifacts: List[str] = []
    writeup: str = "outputs/reverse/writeup.md"

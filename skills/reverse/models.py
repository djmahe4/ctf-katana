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

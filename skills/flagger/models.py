from typing import List, Optional, Dict
from pydantic import BaseModel, Field

class FlagPart(BaseModel):
    """A segment of the original flag."""
    original: str
    transformed: str
    order: int
    metadata: Dict[str, str] = Field(default_factory=dict)

class ObfuscationResult(BaseModel):
    """Result of an obfuscation chain."""
    flag_parts: List[FlagPart]
    reconstruction_logic: str  # Code snippet to rebuild the flag
    intensity: str  # moderate, difficult, expert
    keys: Dict[str, str] = Field(default_factory=dict)

class PoisoningResult(BaseModel):
    """Result of anti-AI poisoning."""
    injections: List[str]
    fake_flags: List[str]
    context: str  # e.g., 'memory dump', 'system log'

class HardenedPayload(BaseModel):
    """Final output of the flagger skill."""
    obfuscation: ObfuscationResult
    poisoning: PoisoningResult
    target_format: str  # c, python, js, etc.

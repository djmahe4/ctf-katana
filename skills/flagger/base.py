from abc import ABC, abstractmethod
from typing import List, Dict, Any, Tuple
from skills.flagger.models import FlagPart, ObfuscationResult, PoisoningResult, HardenedPayload

class BaseObfuscator(ABC):
    @abstractmethod
    def encrypt(self, data: str, **kwargs) -> str:
        """Apply a reversible transformation."""
        pass

    @abstractmethod
    def decrypt_logic(self, var_name: str, **kwargs) -> str:
        """Return the code snippet to reverse the transformation."""
        pass

class BasePoisoner(ABC):
    @abstractmethod
    def generate(self, intensity: str, **kwargs) -> List[str]:
        """Generate anti-AI strings/injections."""
        pass

class BaseChallengeHandler(ABC):
    @abstractmethod
    def embed(self, payload: HardenedPayload, template: str) -> str:
        """Embed the hardened payload into a full challenge template."""
        pass

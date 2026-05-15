from skills.flagger.base import BaseChallengeHandler
from skills.flagger.models import HardenedPayload

class ReverseHandler(BaseChallengeHandler):
    """Embeds flags into C/Python/Binary-style challenges."""
    
    def embed(self, payload: HardenedPayload, template: str = "python") -> str:
        logic = payload.obfuscation.reconstruction_logic
        injections = "\n".join(payload.poisoning.injections)
        
        if template == "python":
            return (f"{injections}\n"
                    f"# Reconstruction Logic\n"
                    f"{logic}\n")
        
        return f"Unsupported reverse template: {template}"

from skills.flagger.base import BaseChallengeHandler
from skills.flagger.models import HardenedPayload

class ReverseHandler(BaseChallengeHandler):
    """Embeds flags into C/Python/Binary-style challenges."""
    
    def embed(self, payload: HardenedPayload, template: str = "python") -> str:
        flag_val = payload.obfuscation.flag_parts[0].transformed
        logic = payload.obfuscation.reconstruction_logic
        injections = "\n".join(payload.poisoning.injections)
        
        if template == "python":
            return (f"{injections}\n"
                    f"# Reconstruction Logic\n"
                    f"flag = '{flag_val}'\n"
                    f"{logic}\n"
                    f"print('Challenge Locked. Found flag?')")
        
        return f"Unsupported reverse template: {template}"

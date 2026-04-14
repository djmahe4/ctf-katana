from skills.flagger.base import BaseChallengeHandler
from skills.flagger.models import HardenedPayload

class WebHandler(BaseChallengeHandler):
    """Embeds flags into HTML/JS/CSS challenges."""
    
    def embed(self, payload: HardenedPayload, template: str = "html") -> str:
        flag_val = payload.obfuscation.flag_parts[0].transformed
        logic = payload.obfuscation.reconstruction_logic
        injections = "\n".join([f"<!-- {inj} -->" for inj in payload.poisoning.injections])
        
        if template == "html":
            return (f"<!DOCTYPE html>\n<html>\n<body>\n"
                    f"{injections}\n"
                    f"<script>\n"
                    f"  let flag = '{flag_val}';\n"
                    f"  // Reconstruct the flag\n"
                    f"  {logic}\n"
                    f"  console.log('Challenge Loaded.');\n"
                    f"</script>\n"
                    f"</body>\n</html>")
        
        return f"Unsupported web template: {template}"

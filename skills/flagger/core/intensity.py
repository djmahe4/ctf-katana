from typing import List, Dict, Any
from skills.flagger.models import FlagPart, ObfuscationResult, PoisoningResult, HardenedPayload
from skills.flagger.obfuscators.base_encoders import Base64Obfuscator, HexObfuscator, Base85Obfuscator
from skills.flagger.obfuscators.ciphers import ROT13Obfuscator, XORObfuscator
from skills.flagger.obfuscators.advanced import OpcodeObfuscator, ArithmeticObfuscator
from skills.flagger.poisoners.tiered import ModeratePoisoner, DifficultPoisoner, ExpertPoisoner

class IntensityArchitect:
    """Orchestrates the tiered intensity for anti-AI hardening."""
    
    def __init__(self):
        self.obfuscators = {
            "base64": Base64Obfuscator(),
            "hex": HexObfuscator(),
            "base85": Base85Obfuscator(),
            "rot13": ROT13Obfuscator(),
            "xor": XORObfuscator(),
            "opcodes": OpcodeObfuscator(),
            "arithmetic": ArithmeticObfuscator()
        }
        self.poisoners = {
            "moderate": ModeratePoisoner(),
            "difficult": DifficultPoisoner(),
            "expert": ExpertPoisoner()
        }

    def get_preset(self, level: str) -> Dict[str, Any]:
        """Map human-friendly levels to obfuscator chains."""
        presets = {
            "moderate": {
                "chain": ["hex", "base64"],
                "poison_level": "moderate",
            },
            "difficult": {
                "chain": ["xor", "rot13", "base85"],
                "poison_level": "difficult",
            },
            "expert": {
                "chain": ["opcodes", "xor", "arithmetic"],
                "poison_level": "expert",
            }
        }
        return presets.get(level.lower(), presets["moderate"])

    def harden_flag(self, flag: str, level: str = "moderate") -> HardenedPayload:
        """Harden the flag based on the preset level."""
        preset = self.get_preset(level)
        current_val = flag
        logic_steps = []
        
        # Apply obfuscation chain
        for step in reversed(preset["chain"]):
            obf = self.obfuscators.get(step)
            if obf:
                current_val = obf.encrypt(current_val)
                logic_steps.append(obf.decrypt_logic("flag"))

        obf_result = ObfuscationResult(
            flag_parts=[FlagPart(original=flag, transformed=current_val, order=0)],
            reconstruction_logic="\n".join(logic_steps),
            intensity=level
        )
        
        # Generate Poisoning
        p_level = preset["poison_level"]
        p_gen = self.poisoners.get(p_level)
        injections = p_gen.generate(p_level) if p_gen else []
        
        poison_result = PoisoningResult(
            injections=injections,
            fake_flags=[],
            context=level
        )

        return HardenedPayload(
            obfuscation=obf_result,
            poisoning=poison_result,
            target_format="python"  # Default
        )

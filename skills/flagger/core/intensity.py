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
        
        # Determine split count based on level
        num_parts = 1
        if level == "difficult": num_parts = 3
        elif level == "expert": num_parts = 5
        
        # Split flag into parts
        part_len = max(1, len(flag) // num_parts)
        flag_segments = [flag[i:i+part_len] for i in range(0, len(flag), part_len)]
        
        flag_parts = []
        all_logic = []
        
        # Map human-friendly names to internal variable IDs for reconstruction
        # e.g., _0x1, _0x2...
        
        for idx, segment in enumerate(flag_segments):
            current_val = segment
            logic_steps = []
            var_name = f"_0x{idx+1:x}"
            
            # Apply obfuscation chain to each part
            for step in preset["chain"]:
                obf = self.obfuscators.get(step)
                if obf:
                    current_val = obf.encrypt(current_val)
                    logic_steps.insert(0, obf.decrypt_logic(var_name))
            
            flag_parts.append(FlagPart(original=segment, transformed=current_val, order=idx))
            # Prepend the assignment
            part_logic = [f"{var_name} = '{current_val}'"] + logic_steps
            all_logic.append("\n".join(part_logic))

        # Final reconstruction logic
        reconstruction = "\n".join(all_logic)
        final_var = f"_0x{len(flag_segments)+1:x}"
        merge_parts = " + ".join([f"_0x{i+1:x}" for i in range(len(flag_segments))])
        reconstruction += f"\n{final_var} = {merge_parts}\nflag = {final_var}"

        obf_result = ObfuscationResult(
            flag_parts=flag_parts,
            reconstruction_logic=reconstruction,
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

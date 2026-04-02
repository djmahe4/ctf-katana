from typing import List, Dict, Any
from skills.flagger.base import BaseObfuscator

class OpcodeObfuscator(BaseObfuscator):
    """Encodes flag bytes as immediate values in x86-like opcodes."""
    def encrypt(self, data: str, **kwargs) -> str:
        # B8 {byte} 00 00 00 -> MOV EAX, {byte}
        res = []
        for char in data:
            byte_hex = format(ord(char), '02x')
            res.append(f"B8 {byte_hex} 00 00 00")
        return " ".join(res)

    def decrypt_logic(self, var_name: str, **kwargs) -> str:
        return (f"import re\n"
                f"bytes_list = re.findall(r'B8 ([0-9A-Fa-f]{2}) 00 00 00', {var_name})\n"
                f"{var_name} = ''.join(chr(int(b, 16)) for b in bytes_list)")

class ArithmeticObfuscator(BaseObfuscator):
    """Encodes characters as arithmetic expressions."""
    def encrypt(self, data: str, **kwargs) -> str:
        # e.g., 'a' (97) -> "(10 * 10 - 3)"
        res = []
        for char in data:
            val = ord(char)
            res.append(f"({val//2} * 2 + {val%2})")
        return ", ".join(res)

    def decrypt_logic(self, var_name: str, **kwargs) -> str:
        return f"{var_name} = ''.join(chr(eval(x)) for x in {var_name}.split(', '))"

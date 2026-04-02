import string
from typing import List, Dict, Any
from skills.flagger.base import BaseObfuscator

class XORObfuscator(BaseObfuscator):
    def encrypt(self, data: str, key: str = "CTFKATANA") -> str:
        res = []
        for i in range(len(data)):
            char = data[i]
            k_char = key[i % len(key)]
            res.append(chr(ord(char) ^ ord(k_char)))
        return "".join(res)

    def decrypt_logic(self, var_name: str, key: str = "CTFKATANA") -> str:
        return (f"def xor_dec(data, key):\n"
                f"    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(data))\n"
                f"{var_name} = xor_dec({var_name}, '{key}')")

class ROT13Obfuscator(BaseObfuscator):
    def encrypt(self, data: str, **kwargs) -> str:
        abc = "abcdefghijklmnopqrstuvwxyz"
        ABC = abc.upper()
        res = []
        for char in data:
            if char in abc:
                index = (abc.find(char) + 13) % 26
                res.append(abc[index])
            elif char in ABC:
                index = (ABC.find(char) + 13) % 26
                res.append(ABC[index])
            else:
                res.append(char)
        return "".join(res)

    def decrypt_logic(self, var_name: str, **kwargs) -> str:
        return f"{var_name} = str.translate({var_name}, str.maketrans(string.ascii_letters, string.ascii_letters[13:] + string.ascii_letters[:13]))"

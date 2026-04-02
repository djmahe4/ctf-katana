import base64
from typing import List, Dict, Any
from skills.flagger.base import BaseObfuscator

class Base64Obfuscator(BaseObfuscator):
    def encrypt(self, data: str, **kwargs) -> str:
        return base64.b64encode(data.encode()).decode()

    def decrypt_logic(self, var_name: str, **kwargs) -> str:
        return f"import base64\n{var_name} = base64.b64decode({var_name}).decode()"

class HexObfuscator(BaseObfuscator):
    def encrypt(self, data: str, **kwargs) -> str:
        return data.encode().hex()

    def decrypt_logic(self, var_name: str, **kwargs) -> str:
        return f"{var_name} = bytes.fromhex({var_name}).decode()"

class Base85Obfuscator(BaseObfuscator):
    def encrypt(self, data: str, **kwargs) -> str:
        return base64.b85encode(data.encode()).decode()

    def decrypt_logic(self, var_name: str, **kwargs) -> str:
        return f"import base64\n{var_name} = base64.b85decode({var_name}).decode()"

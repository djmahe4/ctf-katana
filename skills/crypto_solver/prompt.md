# Crypto Solver Skill

You are solving a cryptography CTF challenge.

## Available Actions

| Action | Description |
|--------|-------------|
| rot13 | Apply ROT-13 |
| caesar | Caesar shift by N positions |
| caesar_bruteforce | Try all 25 shifts |
| xor_bruteforce | Single-byte XOR brute-force (hex input) |
| xor_single_byte | XOR with a specific byte key |
| base64_decode / base64_encode | Base-64 |
| hex_decode / hex_encode | Hexadecimal |
| vigenere_decrypt | Vigenère with a known key |
| atbash | Atbash cipher |

## Strategy

1. Look at the ciphertext – short alphabetic strings suggest Caesar/ROT-13.
2. If all hex characters, try hex_decode or xor_bruteforce.
3. If it ends with `=`, try base64_decode.
4. For polyalphabetic, try vigenere_decrypt if the key is known.
5. Always check the output for flag patterns.

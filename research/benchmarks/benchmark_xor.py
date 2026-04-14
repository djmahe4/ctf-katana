import time
import itertools
from typing import Optional, Tuple

def xor_crypt(data: bytes, key: bytes) -> bytes:
    """Standard multi-byte XOR encryption/decryption."""
    return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))

def brute_force_xor(ciphertext: bytes, key_len: int, magic: bytes = b"FLAG{", max_attempts: Optional[int] = None) -> Tuple[Optional[bytes], int, float]:
    """
    Brute-forces a multi-byte XOR key.
    
    Returns: (found_key, attempts_count, elapsed_time)
    """
    start_time = time.perf_counter()
    attempts = 0
    
    # Iterate through all 256^key_len combinations
    for key_tuple in itertools.product(range(256), repeat=key_len):
        attempts += 1
        key = bytes(key_tuple)
        
        # Check first N bytes for magic header (optimised)
        # We only decrypt enough to check the magic header first
        match = True
        for i in range(len(magic)):
            if (ciphertext[i] ^ key[i % len(key)]) != magic[i]:
                match = False
                break
        
        if match:
            elapsed = time.perf_counter() - start_time
            return key, attempts, elapsed
            
        if max_attempts and attempts >= max_attempts:
            break
            
    elapsed = time.perf_counter() - start_time
    return None, attempts, elapsed

if __name__ == "__main__":
    # Test Setup: "FLAG{B_TECH_THESIS_2026}"
    # Key: b"\xDE\xAD\xBE" (3-byte)
    original = b"FLAG{B_TECH_THESIS_2026_EXPERIMENT_SUCCESS}"
    key = b"\xDE\xAD\xBE"
    cipher = xor_crypt(original, key)
    
    print(f"[*] Starting Python XOR Brute-force (Key Length: {len(key)})")
    print(f"[*] Ciphertext (hex): {cipher.hex()}")
    print(f"[*] Target Magic: FLAG{{")
    
    found_key, count, duration = brute_force_xor(cipher, len(key))
    
    if found_key:
        print(f"\n[+] SUCCESS!")
        print(f"[+] Key Found: {found_key.hex()}")
        print(f"[+] Decrypted: {xor_crypt(cipher, found_key).decode()}")
    else:
        print("\n[-] Failed to find key.")
        
    print(f"[*] Total Attempts: {count:,}")
    print(f"[*] Time Taken: {duration:.4f} seconds")
    print(f"[*] Velocity: {count/duration:,.2f} keys/sec")

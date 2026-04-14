import hmac
import hashlib
import time
import base64

def generate_dynamic_secure_payload(flag, shared_secret, window_seconds=30):
    """
    Template for Sidecar Flag Delivery (Sentinel Pattern).
    
    This logic generates a dynamic XOR key from a time-windowed HMAC signature,
    ensuring every delivery is unique and zero-file based.
    """
    # 1. Generate Timestamp (Windows UTC)
    current_time = int(time.time())
    
    # 2. Create HMAC Signature for this specific request window
    # In a real impl, the client sends 'current_time' and 'signature'
    message = str(current_time).encode()
    signature = hmac.new(shared_secret.encode(), message, hashlib.sha256).hexdigest()
    
    # 3. Derive Dynamic XOR Key from Signature
    # Use SHA256 of the signature to get a robust, high-entropy key
    dynamic_key = hashlib.sha256(signature.encode()).digest()
    
    # 4. XOR Encrypt the Flag
    flag_bytes = flag.encode()
    encrypted = bytes([b ^ dynamic_key[i % len(dynamic_key)] for i, b in enumerate(flag_bytes)])
    
    return {
        "timestamp": current_time,
        "signature": signature,
        "payload": base64.b64encode(encrypted).decode()
    }

def verify_and_decrypt(payload_b64, signature, timestamp, shared_secret, window_seconds=30):
    """
    Verifies the HMAC window and decrypts using the derived dynamic key.
    """
    # 1. Check Window
    if abs(int(time.time()) - int(timestamp)) > window_seconds:
        raise ValueError("Security window expired")
    
    # 2. Re-verify Signature
    expected_sig = hmac.new(shared_secret.encode(), str(timestamp).encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_sig, signature):
        raise ValueError("Invalid signature")
    
    # 3. Derive same Dynamic Key
    dynamic_key = hashlib.sha256(signature.encode()).digest()
    
    # 4. Decrypt
    encrypted_bytes = base64.b64decode(payload_b64)
    decrypted = bytes([b ^ dynamic_key[i % len(dynamic_key)] for i, b in enumerate(encrypted_bytes)])
    
    return decrypted.decode()

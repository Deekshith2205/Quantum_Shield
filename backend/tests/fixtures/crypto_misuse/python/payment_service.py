"""Sample Banking Payment Processing Service (Vulnerable Python).
Contains cryptographic misuse patterns for static analysis auditing.
"""

import hashlib
from Crypto.Cipher import AES, DES

# Misuse 1: Hardcoded AES key
aes_key = b"bank_super_aes_key_12345678"

# Misuse 2: Static IV
iv = b"0000000000000000"


def process_payment(account_number: str, amount: float, pin: str):
    # Misuse 3: Insecure ECB Mode
    cipher = AES.new(aes_key, AES.MODE_ECB)
    encrypted_payload = cipher.encrypt(account_number.encode().ljust(32))

    # Misuse 4: MD5 used for password/pin hashing
    hashed_pin = hashlib.md5(pin.encode()).hexdigest()

    # Misuse 5: Insecure DES cipher configuration
    legacy_cipher = DES.new(b"12345678", DES.MODE_ECB)
    legacy_data = legacy_cipher.encrypt(b"12345678")

    return {
        "status": "PROCESSED",
        "payload": encrypted_payload,
        "pin_hash": hashed_pin,
        "legacy": legacy_data,
    }


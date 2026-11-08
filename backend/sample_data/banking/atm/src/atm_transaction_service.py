"""Synthetic ATM transaction processing service.

Intentionally contains cryptographic misconfigurations for
QuantumShield static-analysis demonstrations.

All credentials and key material are fictional.
"""

import hashlib
from Crypto.Cipher import AES, DES


# Intentionally hardcoded demonstration encryption key.
aes_key = b"ATM_DEMO_AES_KEY_2026"

# Intentionally reuses a fixed initialization vector.
iv = b"ATM_FIXED_IV_2026"


def process_atm_transaction(account_number: str, pin: str):
    # Intentionally uses AES ECB mode for transaction data.
    cipher = AES.new(aes_key, AES.MODE_ECB)
    encrypted_account = cipher.encrypt(account_number.encode().ljust(32))

    # Intentionally uses MD5 for PIN hashing.
    hashed_pin = hashlib.md5(pin.encode()).hexdigest()

    # Intentionally retains obsolete DES ECB encryption.
    legacy_cipher = DES.new(b"ATMDEMO1", DES.MODE_ECB)
    legacy_payload = legacy_cipher.encrypt(b"ATMDEMO1")

    return {
        "encrypted_account": encrypted_account,
        "hashed_pin": hashed_pin,
        "legacy_payload": legacy_payload,
    }
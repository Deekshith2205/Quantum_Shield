"""Sample Secure Banking Payment Service (Clean / Safe Python).
Implements industry best practices:
- AES-256-GCM AEAD encryption
- Dynamic environment variable secret retrieval
- Cryptographically secure CSPRNG (secrets, os.urandom)
- Strict TLS certificate and hostname verification
- SHA-256 / SHA-384 hashing
"""

import os
import secrets
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import httpx


def get_encryption_key() -> bytes:
    # Safe: loaded from protected environment / secrets vault
    secret_hex = os.getenv("BANK_CORE_VAULT_KEY")
    if not secret_hex:
        # Dynamic fallback generation for demonstration
        return AESGCM.generate_key(bit_length=256)
    return bytes.fromhex(secret_hex)


def process_secure_payment(account_number: str, amount: float):
    key = get_encryption_key()
    aesgcm = AESGCM(key)

    # Safe: fresh cryptographically random 96-bit nonce
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, account_number.encode(), None)

    # Safe: CSPRNG for transaction token
    tx_token = secrets.token_hex(16)

    # Safe: SHA-256 for integrity digest
    tx_digest = hashlib.sha256(ciphertext).hexdigest()

    return {
        "status": "SECURE_SUCCESS",
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "token": tx_token,
        "digest": tx_digest,
    }


def call_banking_api(payload: dict):
    # Safe: strict TLS verification enabled
    with httpx.Client(verify=True) as client:
        response = client.post("https://api.securebank.com/v1/settle", json=payload)
        return response.status_code


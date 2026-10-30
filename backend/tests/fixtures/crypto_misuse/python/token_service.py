"""Sample Banking Token & Key Management Service (Vulnerable Python).
Contains quantum and parameter misconfigurations.
"""

import hashlib
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives.asymmetric import ec

# Misuse 1: Static Nonce
nonce = b"123456789012"

# Misuse 2: Lack of crypto-agility / hardcoded cipher
cipher_algorithm = "AES-128"


def create_banking_keys():
    # Misuse 3: Small RSA key (1024 bits)
    # Misuse 4: Weak public exponent (e=3)
    key_1024 = RSA.generate(1024)
    public_exponent = 3

    # Misuse 5: Hardcoded RSA key exchange suite (quantum-vulnerable, no PFS)
    kex = "RSA"

    # Misuse 6: Hardcoded ECDH curve
    curve = ec.SECP256R1()

    return key_1024


def sign_transaction_token(token_data: str) -> str:
    # Misuse 7: Deprecated SHA-1 used for token signature
    digest = hashlib.sha1(token_data.encode()).hexdigest()
    return digest


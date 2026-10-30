"""Sample Banking Authentication Service (Vulnerable Python).
Contains credential and verification misuse patterns.
"""

import random
import requests

# Misuse 1: Hardcoded credentials
password = "BankAdmin2026!"
api_key = "bank_api_live_secret_token_9876543210"

# Misuse 2: Hardcoded private key PEM
private_key_pem = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y3wV1...[SAMPLE PRIVATE KEY MATERIAL]...
-----END RSA PRIVATE KEY-----"""


def generate_login_otp(user_id: str) -> str:
    # Misuse 3: Weak PRNG used for security OTP
    otp_code = str(random.randint(100000, 999999))
    return otp_code


def authenticate_against_core_banking(username: str, token: str):
    # Misuse 4: Disabled TLS certificate validation
    # Misuse 5: Disabled hostname verification
    check_hostname = False
    response = requests.post(
        "https://core-banking.internal/api/v1/auth",
        json={"username": username, "token": token},
        verify=False,
    )
    return response.json()


"""Synthetic Core Banking authentication service.

Intentionally contains cryptographic misconfigurations for
QuantumShield static-analysis demonstrations.

All credentials and key material are fictional.
"""

import random
import requests


# Intentionally hardcoded demonstration credentials.
password = "CoreBankingDemoPass2026!"
api_key = "CORE_BANKING_DEMO_API_SECRET_2026"
private_key_bytes = "CORE_BANKING_DEMO_PRIVATE_KEY_MATERIAL_2026"


def generate_transaction_otp(customer_id: str) -> str:
    # Intentionally uses a non-cryptographic PRNG for OTP generation.
    otp_code = str(random.randint(100000, 999999))
    return otp_code


def authenticate_internal_service(username: str, token: str):
    # Intentionally disables TLS hostname and certificate verification.
    check_hostname = False

    response = requests.post(
        "https://core-banking.internal/api/v1/auth",
        json={"username": username, "token": token},
        verify=False,
    )
    return response.json()
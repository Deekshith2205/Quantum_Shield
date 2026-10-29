"""Unit tests for X.509 certificate parsing.
"""

from tests.fixtures.cert_generator import (
    generate_mock_rsa_cert_der,
    generate_mock_ecdsa_cert_der,
    generate_mock_ed25519_cert_der,
)
from app.scanners.certificate_parser import parse_der_certificate, parse_certificate_chain
from cryptography.hazmat.primitives.asymmetric import ec


def test_parse_rsa_certificate():
    der = generate_mock_rsa_cert_der(key_size=2048, common_name="rsa.test.org")
    parsed = parse_der_certificate(der)

    assert parsed["subject_cn"] == "rsa.test.org"
    assert parsed["issuer_cn"] == "rsa.test.org"
    assert parsed["public_key_algorithm"] == "RSA"
    assert parsed["key_size_bits"] == 2048
    assert parsed["curve_name"] is None
    assert "sha256" in parsed["signature_algorithm"].lower()
    assert parsed["is_expired"] is False
    assert parsed["days_remaining"] >= 20
    assert "rsa.test.org" in parsed["subject_alt_names"]
    assert len(parsed["fingerprint_sha256"]) == 95  # 32 hex bytes separated by colons


def test_parse_ecdsa_certificate():
    der = generate_mock_ecdsa_cert_der(curve_cls=ec.SECP256R1, common_name="ecdsa.test.org")
    parsed = parse_der_certificate(der)

    assert parsed["subject_cn"] == "ecdsa.test.org"
    assert parsed["public_key_algorithm"] == "ECC"
    assert parsed["key_size_bits"] == 256
    assert "P-256" in parsed["curve_name"]
    assert parsed["is_expired"] is False


def test_parse_ed25519_certificate():
    der = generate_mock_ed25519_cert_der(common_name="ed25519.test.org")
    parsed = parse_der_certificate(der)

    assert parsed["subject_cn"] == "ed25519.test.org"
    assert parsed["public_key_algorithm"] == "EdDSA"
    assert parsed["curve_name"] == "Ed25519"
    assert parsed["key_size_bits"] == 256


def test_parse_expired_certificate():
    der = generate_mock_rsa_cert_der(expired=True)
    parsed = parse_der_certificate(der)

    assert parsed["is_expired"] is True
    assert parsed["days_remaining"] < 0


def test_parse_chain():
    der1 = generate_mock_rsa_cert_der(common_name="intermediate-ca.org")
    der2 = generate_mock_rsa_cert_der(common_name="root-ca.org")
    chain_summaries = parse_certificate_chain([der1, der2])

    assert len(chain_summaries) == 2
    assert chain_summaries[0]["subject_cn"] == "intermediate-ca.org"
    assert chain_summaries[1]["subject_cn"] == "root-ca.org"


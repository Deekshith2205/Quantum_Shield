"""Unit tests for cryptographic normalization, observability, and anti-inference rules.
"""

import pytest
from app.security.normalizer import normalize_cryptographic_mechanisms


def test_tls13_key_exchange_is_not_observable():
    """
    In TLS 1.3, key exchange is decoupled from cipher suites and negotiated in KeyShare.
    Standard client TLS APIs do not expose the group, so it must be marked NOT_OBSERVABLE
    and must NEVER be claimed as observed or blindly inferred as X25519.
    """
    cert_data = {
        "public_key_algorithm": "ECC",
        "key_size_bits": 256,
        "curve_name": "NIST P-256 (prime256v1)",
        "signature_algorithm": "ecdsa-with-SHA256",
    }
    tls_data = {
        "negotiated_protocol": "TLSv1.3",
        "negotiated_cipher": "TLS_AES_256_GCM_SHA384",
        "cipher_bits": 256,
    }

    mechs, not_observable = normalize_cryptographic_mechanisms(cert_data, tls_data)

    # 1. Key Exchange must be NOT_OBSERVABLE
    kx = next(m for m in mechs if m.category == "key_exchange")
    assert kx.evidence == "NOT_OBSERVABLE"
    assert kx.observability == "NOT_OBSERVABLE"
    assert kx.value == "Not observable"
    assert kx.role == "Key Exchange"
    # Verify no false claim of X25519
    assert "x25519" not in kx.value.lower()
    assert "x25519" not in kx.algorithm_name.lower()

    # 2. Symmetric Cipher must be OBSERVED from TLS_AES_256_GCM_SHA384
    sym = next(m for m in mechs if m.category == "symmetric_cipher")
    assert sym.role == "Symmetric Bulk Cipher"
    assert sym.value == "AES-256-GCM"
    assert sym.evidence == "OBSERVED"
    assert sym.key_size == 256

    # 3. Hash must be OBSERVED from PRF
    h = next(m for m in mechs if m.category == "hash")
    assert h.role == "Hash / MAC"
    assert h.value == "SHA-384"
    assert h.evidence == "OBSERVED"

    # 4. Certificate Public Key must be OBSERVED from leaf cert
    pk = next(m for m in mechs if m.category == "public_key")
    assert pk.role == "Certificate Public Key"
    assert "P-256" in pk.value
    assert pk.evidence == "OBSERVED"

    # 5. Protocol Version must be OBSERVED
    proto = next(m for m in mechs if m.category == "protocol")
    assert proto.value == "TLSv1.3"
    assert proto.evidence == "OBSERVED"


def test_tls12_ecdhe_is_observed_from_cipher_suite():
    """
    In TLS 1.2, ECDHE is explicitly specified in the negotiated cipher suite prefix.
    """
    cert_data = {
        "public_key_algorithm": "RSA",
        "key_size_bits": 2048,
        "curve_name": None,
        "signature_algorithm": "sha256WithRSAEncryption",
    }
    tls_data = {
        "negotiated_protocol": "TLSv1.2",
        "negotiated_cipher": "ECDHE-RSA-AES128-GCM-SHA256",
        "cipher_bits": 128,
    }

    mechs, _ = normalize_cryptographic_mechanisms(cert_data, tls_data)

    kx = next(m for m in mechs if m.category == "key_exchange")
    assert kx.role == "Key Exchange"
    assert kx.value == "ECDHE"
    assert kx.evidence == "OBSERVED"
    assert "TLS 1.2 Negotiated Cipher Suite prefix" in kx.source

    sym = next(m for m in mechs if m.category == "symmetric_cipher")
    assert sym.value == "AES-128-GCM"
    assert sym.evidence == "OBSERVED"
    assert sym.key_size == 128


def test_tls12_dhe_is_observed_from_cipher_suite():
    """
    In TLS 1.2, DHE is explicitly specified in the cipher suite.
    """
    cert_data = {
        "public_key_algorithm": "RSA",
        "key_size_bits": 3072,
        "curve_name": None,
        "signature_algorithm": "sha256WithRSAEncryption",
    }
    tls_data = {
        "negotiated_protocol": "TLSv1.2",
        "negotiated_cipher": "DHE-RSA-AES256-GCM-SHA384",
        "cipher_bits": 256,
    }

    mechs, _ = normalize_cryptographic_mechanisms(cert_data, tls_data)

    kx = next(m for m in mechs if m.category == "key_exchange")
    assert kx.role == "Key Exchange"
    assert kx.value == "DHE"
    assert kx.evidence == "OBSERVED"


def test_tls12_static_rsa_is_observed():
    """
    In TLS 1.2, static RSA key transport without forward secrecy is identified.
    """
    cert_data = {
        "public_key_algorithm": "RSA",
        "key_size_bits": 2048,
        "curve_name": None,
        "signature_algorithm": "sha256WithRSAEncryption",
    }
    tls_data = {
        "negotiated_protocol": "TLSv1.2",
        "negotiated_cipher": "AES128-SHA",
        "cipher_bits": 128,
    }

    mechs, _ = normalize_cryptographic_mechanisms(cert_data, tls_data)

    kx = next(m for m in mechs if m.category == "key_exchange")
    assert kx.value == "Static RSA"
    assert kx.evidence == "OBSERVED"


def test_all_mechanisms_have_explicit_evidence_fields():
    """
    Every normalized mechanism must strictly contain role, value, source, and evidence.
    """
    cert_data = {
        "public_key_algorithm": "EdDSA",
        "key_size_bits": 256,
        "curve_name": "Ed25519",
        "signature_algorithm": "ed25519",
    }
    tls_data = {
        "negotiated_protocol": "TLSv1.3",
        "negotiated_cipher": "TLS_CHACHA20_POLY1305_SHA256",
        "cipher_bits": 256,
    }

    mechs, _ = normalize_cryptographic_mechanisms(cert_data, tls_data)
    for m in mechs:
        assert m.role
        assert m.value
        assert m.source
        assert m.evidence in ("OBSERVED", "INFERRED", "NOT_OBSERVABLE")

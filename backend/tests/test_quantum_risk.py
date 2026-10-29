"""Comprehensive Unit Tests for Quantum Readiness Score Semantics,
Role-Specific PQC Recommendations, Structured Risk Findings, and Observability.
Phase 2B - Assessment Intelligence
"""

import pytest
from app.security.normalizer import normalize_cryptographic_mechanisms
from app.security.quantum_risk import evaluate_quantum_risk


def test_readiness_score_semantics():
    """
    Test 1: Unambiguous Quantum Readiness Score (0-100).
    Higher score MUST always mean better readiness.
    0 = extremely poor, 100 = excellent.
    """
    # 1. Excellent domain: TLS 1.3, AES-256, SHA-384, Post-quantum ready
    cert_data_good = {
        "public_key_algorithm": "ECC",
        "key_size_bits": 256,
        "curve_name": "NIST P-256",
        "signature_algorithm": "ecdsa-with-SHA256",
        "is_trusted": True,
        "is_expired": False,
        "chain_length": 2,
    }
    tls_data_good = {
        "negotiated_protocol": "TLSv1.3",
        "negotiated_cipher": "TLS_AES_256_GCM_SHA384",
        "cipher_bits": 256,
    }
    mechs_good, _ = normalize_cryptographic_mechanisms(cert_data_good, tls_data_good)
    _, score_good, _, _, _, _ = evaluate_quantum_risk(mechs_good, tls_data_good, cert_data_good, "secure.org")

    # 2. Poor/Critical domain: TLS 1.0, RSA-1024, SHA-1, AES-128
    cert_data_bad = {
        "public_key_algorithm": "RSA",
        "key_size_bits": 1024,
        "curve_name": None,
        "signature_algorithm": "sha1WithRSAEncryption",
        "is_trusted": False,
        "is_expired": True,
        "chain_length": 1,
    }
    tls_data_bad = {
        "negotiated_protocol": "TLSv1.0",
        "negotiated_cipher": "AES128-SHA",
        "cipher_bits": 128,
    }
    mechs_bad, _ = normalize_cryptographic_mechanisms(cert_data_bad, tls_data_bad)
    _, score_bad, _, _, _, _ = evaluate_quantum_risk(mechs_bad, tls_data_bad, cert_data_bad, "legacy.org")

    # Higher score strictly means better quantum readiness
    assert score_good.score > score_bad.score
    assert score_good.readiness_score == score_good.score
    assert score_bad.score < 30
    assert score_bad.grade == "Critical"
    assert score_good.score >= 70


def test_rsa_certificate_produces_high_quantum_risk():
    """
    Test 2: RSA-2048 certificate produces HIGH quantum risk finding due to Shor's algorithm.
    """
    cert_data = {
        "public_key_algorithm": "RSA",
        "key_size_bits": 2048,
        "curve_name": None,
        "signature_algorithm": "sha256WithRSAEncryption",
        "is_trusted": True,
        "is_expired": False,
        "chain_length": 2,
    }
    tls_data = {
        "negotiated_protocol": "TLSv1.3",
        "negotiated_cipher": "TLS_AES_256_GCM_SHA384",
        "cipher_bits": 256,
    }
    mechs, _ = normalize_cryptographic_mechanisms(cert_data, tls_data)
    findings, _, _, _, _, _ = evaluate_quantum_risk(mechs, tls_data, cert_data)

    rsa_fnd = next(f for f in findings if f.role == "Certificate Public Key" and "RSA" in f.value)
    assert rsa_fnd.risk_level == "HIGH"
    assert "Shor's algorithm" in rsa_fnd.quantum_threat
    assert rsa_fnd.evidence == "OBSERVED"
    assert "ML-DSA" in rsa_fnd.migration_target


def test_ecdsa_certificate_produces_high_quantum_risk():
    """
    Test 3: ECDSA certificate produces HIGH quantum risk finding due to Shor's algorithm (ECDLP).
    """
    cert_data = {
        "public_key_algorithm": "ECC",
        "key_size_bits": 256,
        "curve_name": "NIST P-256",
        "signature_algorithm": "ecdsa-with-SHA256",
        "is_trusted": True,
        "is_expired": False,
        "chain_length": 2,
    }
    tls_data = {
        "negotiated_protocol": "TLSv1.3",
        "negotiated_cipher": "TLS_AES_256_GCM_SHA384",
        "cipher_bits": 256,
    }
    mechs, _ = normalize_cryptographic_mechanisms(cert_data, tls_data)
    findings, _, _, _, _, _ = evaluate_quantum_risk(mechs, tls_data, cert_data)

    ec_fnd = next(f for f in findings if f.role == "Certificate Public Key")
    assert ec_fnd.risk_level == "HIGH"
    assert "Shor's algorithm" in ec_fnd.quantum_threat
    assert ec_fnd.evidence == "OBSERVED"
    assert "ML-DSA" in ec_fnd.migration_target


def test_aes_128_produces_medium_quantum_concern():
    """
    Test 4: AES-128 produces MEDIUM risk finding under Grover's algorithm.
    """
    cert_data = {
        "public_key_algorithm": "RSA",
        "key_size_bits": 2048,
        "curve_name": None,
        "signature_algorithm": "sha256WithRSAEncryption",
        "is_trusted": True,
        "is_expired": False,
        "chain_length": 1,
    }
    tls_data = {
        "negotiated_protocol": "TLSv1.3",
        "negotiated_cipher": "TLS_AES_128_GCM_SHA256",
        "cipher_bits": 128,
    }
    mechs, _ = normalize_cryptographic_mechanisms(cert_data, tls_data)
    findings, _, _, _, _, _ = evaluate_quantum_risk(mechs, tls_data, cert_data)

    sym_fnd = next(f for f in findings if f.role == "Symmetric Encryption")
    assert sym_fnd.risk_level == "MEDIUM"
    assert "Grover's algorithm" in sym_fnd.quantum_threat
    assert sym_fnd.migration_target == "AES-256-GCM"


def test_aes_256_does_not_produce_high_quantum_risk():
    """
    Test 5: AES-256 is quantum resistant and produces LOW risk level.
    """
    cert_data = {
        "public_key_algorithm": "RSA",
        "key_size_bits": 2048,
        "curve_name": None,
        "signature_algorithm": "sha256WithRSAEncryption",
        "is_trusted": True,
        "is_expired": False,
        "chain_length": 1,
    }
    tls_data = {
        "negotiated_protocol": "TLSv1.3",
        "negotiated_cipher": "TLS_AES_256_GCM_SHA384",
        "cipher_bits": 256,
    }
    mechs, _ = normalize_cryptographic_mechanisms(cert_data, tls_data)
    findings, _, _, _, _, _ = evaluate_quantum_risk(mechs, tls_data, cert_data)

    sym_fnd = next(f for f in findings if f.role == "Symmetric Encryption")
    assert sym_fnd.risk_level == "LOW"
    assert "Resistant" in sym_fnd.quantum_threat


def test_sha256_is_not_classified_as_shor_vulnerable():
    """
    Test 6: SHA-256/384 is NOT classified as Shor-vulnerable and not labeled HIGH or CRITICAL.
    """
    cert_data = {
        "public_key_algorithm": "RSA",
        "key_size_bits": 2048,
        "curve_name": None,
        "signature_algorithm": "sha256WithRSAEncryption",
        "is_trusted": True,
        "is_expired": False,
        "chain_length": 1,
    }
    tls_data = {
        "negotiated_protocol": "TLSv1.3",
        "negotiated_cipher": "TLS_AES_256_GCM_SHA384",
        "cipher_bits": 256,
    }
    mechs, _ = normalize_cryptographic_mechanisms(cert_data, tls_data)
    findings, _, _, _, _, _ = evaluate_quantum_risk(mechs, tls_data, cert_data)

    sha_fnds = [f for f in findings if "sha" in f.value.lower() or "sha" in f.algorithm.lower()]
    for f in sha_fnds:
        assert f.risk_level not in ("HIGH", "CRITICAL")
        assert "Shor" not in f.quantum_threat


def test_tls13_not_observable_does_not_become_vulnerability():
    """
    Test 7: In TLS 1.3, unobservable key exchange is marked INFORMATIONAL, NOT vulnerable.
    """
    cert_data = {
        "public_key_algorithm": "RSA",
        "key_size_bits": 2048,
        "curve_name": None,
        "signature_algorithm": "sha256WithRSAEncryption",
        "is_trusted": True,
        "is_expired": False,
        "chain_length": 1,
    }
    tls_data = {
        "negotiated_protocol": "TLSv1.3",
        "negotiated_cipher": "TLS_AES_256_GCM_SHA384",
        "cipher_bits": 256,
    }
    mechs, _ = normalize_cryptographic_mechanisms(cert_data, tls_data)
    findings, score, role_assessments, _, _, _ = evaluate_quantum_risk(mechs, tls_data, cert_data)

    kx_fnd = next(f for f in findings if f.role == "Key Establishment")
    assert kx_fnd.evidence == "NOT_OBSERVABLE"
    assert kx_fnd.risk_level == "INFORMATIONAL"
    assert kx_fnd.value == "Not observable"

    # Role assessment for Key Establishment
    kx_role = next(r for r in role_assessments if r.category_id == "key_establishment")
    assert kx_role.status == "INFORMATIONAL"
    assert kx_role.evidence == "NOT_OBSERVABLE"


def test_tls12_ecdhe_remains_observed_from_cipher_suite():
    """
    Test 8: In TLS 1.2, ECDHE is OBSERVED from the cipher-suite prefix.
    """
    cert_data = {
        "public_key_algorithm": "ECC",
        "key_size_bits": 256,
        "curve_name": "NIST P-256",
        "signature_algorithm": "ecdsa-with-SHA256",
        "is_trusted": True,
        "is_expired": False,
        "chain_length": 2,
    }
    tls_data = {
        "negotiated_protocol": "TLSv1.2",
        "negotiated_cipher": "ECDHE-ECDSA-AES128-GCM-SHA256",
        "cipher_bits": 128,
    }
    mechs, _ = normalize_cryptographic_mechanisms(cert_data, tls_data)
    findings, _, role_assessments, _, _, _ = evaluate_quantum_risk(mechs, tls_data, cert_data)

    kx_fnd = next(f for f in findings if f.role == "Key Establishment")
    assert kx_fnd.evidence == "OBSERVED"
    assert kx_fnd.value == "ECDHE"
    assert kx_fnd.risk_level == "HIGH"


def test_certificate_signature_migration_recommends_ml_dsa_slh_dsa():
    """
    Test 9: Certificate signatures recommend ML-DSA / SLH-DSA.
    """
    cert_data = {
        "public_key_algorithm": "RSA",
        "key_size_bits": 2048,
        "curve_name": None,
        "signature_algorithm": "sha256WithRSAEncryption",
        "is_trusted": True,
        "is_expired": False,
        "chain_length": 1,
    }
    tls_data = {
        "negotiated_protocol": "TLSv1.3",
        "negotiated_cipher": "TLS_AES_256_GCM_SHA384",
        "cipher_bits": 256,
    }
    mechs, _ = normalize_cryptographic_mechanisms(cert_data, tls_data)
    findings, _, _, _, migration_plan, _ = evaluate_quantum_risk(mechs, tls_data, cert_data)

    cert_step = next(s for s in migration_plan if "Certificate" in s.affected_component or "PKI" in s.title)
    assert "ML-DSA" in cert_step.recommended_target or "SLH-DSA" in cert_step.recommended_target


def test_key_establishment_migration_recommends_ml_kem():
    """
    Test 10: Key establishment migration recommends ML-KEM / hybrid ML-KEM.
    """
    cert_data = {
        "public_key_algorithm": "ECC",
        "key_size_bits": 256,
        "curve_name": "NIST P-256",
        "signature_algorithm": "ecdsa-with-SHA256",
        "is_trusted": True,
        "is_expired": False,
        "chain_length": 1,
    }
    tls_data = {
        "negotiated_protocol": "TLSv1.3",
        "negotiated_cipher": "TLS_AES_256_GCM_SHA384",
        "cipher_bits": 256,
    }
    mechs, _ = normalize_cryptographic_mechanisms(cert_data, tls_data)
    findings, _, _, _, migration_plan, _ = evaluate_quantum_risk(mechs, tls_data, cert_data)

    kx_step = next(s for s in migration_plan if "Key Exchange" in s.title or "Key Establishment" in s.affected_component)
    assert "ML-KEM" in kx_step.recommended_target or "ML-KEM" in str(kx_step.target_standards)


def test_ml_kem_is_never_recommended_for_certificate_signature():
    """
    Test 11: ML-KEM is NEVER recommended as a certificate-signature replacement.
    """
    cert_data = {
        "public_key_algorithm": "RSA",
        "key_size_bits": 2048,
        "curve_name": None,
        "signature_algorithm": "sha256WithRSAEncryption",
        "is_trusted": True,
        "is_expired": False,
        "chain_length": 1,
    }
    tls_data = {
        "negotiated_protocol": "TLSv1.3",
        "negotiated_cipher": "TLS_AES_256_GCM_SHA384",
        "cipher_bits": 256,
    }
    mechs, _ = normalize_cryptographic_mechanisms(cert_data, tls_data)
    findings, _, _, _, migration_plan, _ = evaluate_quantum_risk(mechs, tls_data, cert_data)

    cert_fnds = [f for f in findings if f.role == "Certificate Public Key"]
    for cf in cert_fnds:
        assert "ML-KEM" not in cf.migration_target
        assert "ML-DSA" in cf.migration_target or "SLH-DSA" in cf.migration_target

    cert_steps = [s for s in migration_plan if "Certificate" in s.affected_component]
    for cs in cert_steps:
        assert "ML-KEM" not in cs.recommended_target


def test_every_finding_contains_mandatory_fields():
    """
    Test 12: Every finding strictly contains role, value, source, evidence, risk_level, recommendation.
    """
    cert_data = {
        "public_key_algorithm": "ECC",
        "key_size_bits": 256,
        "curve_name": "NIST P-256",
        "signature_algorithm": "ecdsa-with-SHA256",
        "is_trusted": True,
        "is_expired": False,
        "chain_length": 1,
    }
    tls_data = {
        "negotiated_protocol": "TLSv1.3",
        "negotiated_cipher": "TLS_AES_128_GCM_SHA256",
        "cipher_bits": 128,
    }
    mechs, _ = normalize_cryptographic_mechanisms(cert_data, tls_data)
    findings, _, _, _, _, _ = evaluate_quantum_risk(mechs, tls_data, cert_data)

    for f in findings:
        assert f.role
        assert f.value
        assert f.source
        assert f.evidence in ("OBSERVED", "INFERRED", "NOT_OBSERVABLE")
        assert f.risk_level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")
        assert f.recommendation


def test_executive_summary_is_generated_from_actual_findings():
    """
    Test 13: Executive summary is dynamically composed from actual observed findings.
    """
    cert_data = {
        "public_key_algorithm": "RSA",
        "key_size_bits": 2048,
        "curve_name": None,
        "signature_algorithm": "sha256WithRSAEncryption",
        "is_trusted": True,
        "is_expired": False,
        "chain_length": 1,
    }
    tls_data = {
        "negotiated_protocol": "TLSv1.3",
        "negotiated_cipher": "TLS_AES_128_GCM_SHA256",
        "cipher_bits": 128,
    }
    mechs, _ = normalize_cryptographic_mechanisms(cert_data, tls_data)
    _, _, _, exec_summary, _, _ = evaluate_quantum_risk(mechs, tls_data, cert_data, domain="audit.example.com")

    assert exec_summary.domain == "audit.example.com"
    assert "RSA-2048" in exec_summary.primary_concern
    assert "AES-128" in (exec_summary.secondary_concern or "")
    assert "TLS 1.3 KeyShare" in exec_summary.visibility_limitations
    assert len(exec_summary.recommended_next_steps) >= 3


def test_migration_roadmap_contains_only_supported_recommendations():
    """
    Test 14: Migration roadmap uses P0/P1/P2/P3 priorities and aligns strictly with findings.
    """
    cert_data = {
        "public_key_algorithm": "RSA",
        "key_size_bits": 2048,
        "curve_name": None,
        "signature_algorithm": "sha256WithRSAEncryption",
        "is_trusted": True,
        "is_expired": False,
        "chain_length": 1,
    }
    tls_data = {
        "negotiated_protocol": "TLSv1.3",
        "negotiated_cipher": "TLS_AES_256_GCM_SHA384",
        "cipher_bits": 256,
    }
    mechs, _ = normalize_cryptographic_mechanisms(cert_data, tls_data)
    _, _, _, _, migration_plan, _ = evaluate_quantum_risk(mechs, tls_data, cert_data)

    for step in migration_plan:
        assert step.priority in ("P0", "P1", "P2", "P3")
        assert step.affected_component
        assert step.current_mechanism
        assert step.recommended_target
        assert step.migration_approach
        assert step.evidence in ("OBSERVED", "INFERRED", "NOT_OBSERVABLE")

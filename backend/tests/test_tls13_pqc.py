"""Tests for TLS 1.3 Key-Exchange & Hybrid Post-Quantum Cryptography (PQC) Integration.
Phase 3B - Comprehensive Verification Suite
"""

import pytest
from unittest.mock import patch, MagicMock

from app.scanners.tls13_pqc import (
    find_openssl_executable,
    parse_group_components,
    parse_openssl_brief_output,
    observe_tls13_key_exchange,
    execute_s_client,
    HYBRID_GROUPS,
    CLASSICAL_GROUPS,
)
from app.schemas.scan import PqcKeyExchangeEvidence, NormalizedCryptoMechanism, QuantumFinding
from app.security.normalizer import normalize_cryptographic_mechanisms
from app.security.quantum_risk import evaluate_quantum_risk
from app.models.audit import AuditDomain, ObservabilityState, FindingSeverity
from app.services.crypto_audit_adapter import map_quantum_finding_to_audit_finding


# ==============================================================================
# 1. GROUP CATALOG & PARSER UNIT TESTS
# ==============================================================================

def test_parse_hybrid_group_components():
    """Verifies that all standard hybrid PQC groups are correctly deconstructed."""
    c, p, is_h = parse_group_components("X25519MLKEM768")
    assert is_h is True
    assert c == "X25519"
    assert p == "ML-KEM-768"

    c, p, is_h = parse_group_components("X448MLKEM1024")
    assert is_h is True
    assert c == "X448"
    assert p == "ML-KEM-1024"

    c, p, is_h = parse_group_components("SecP256r1MLKEM768")
    assert is_h is True
    assert c == "P-256"
    assert p == "ML-KEM-768"

    c, p, is_h = parse_group_components("SecP384r1MLKEM1024")
    assert is_h is True
    assert c == "P-384"
    assert p == "ML-KEM-1024"

    c, p, is_h = parse_group_components("x25519_mlkem768")
    assert is_h is True
    assert c == "X25519"
    assert p == "ML-KEM-768"


def test_parse_classical_group_components():
    """Verifies that standard classical curves are correctly identified as non-hybrid."""
    for curve in ["X25519", "P-256", "secp256r1", "P-384", "P-521", "X448"]:
        c, p, is_h = parse_group_components(curve)
        assert is_h is False
        assert p is None
        assert c is not None

    c, p, is_h = parse_group_components("FFDHE3072")
    assert is_h is False
    assert c == "FFDHE"
    assert p is None


def test_parse_empty_or_unobservable_group():
    """Verifies graceful handling of unobservable or empty group names."""
    for invalid in ["", "   ", "Not observable", "UNKNOWN", None]:
        c, p, is_h = parse_group_components(invalid)
        assert is_h is False
        assert c is None
        assert p is None


def test_parse_openssl_brief_output_success():
    """Verifies output parsing of OpenSSL s_client -brief output."""
    sample_output = (
        "CONNECTION ESTABLISHED\n"
        "Protocol version: TLSv1.3\n"
        "Ciphersuite: TLS_AES_256_GCM_SHA384\n"
        "Negotiated TLS1.3 group: X25519MLKEM768\n"
        "Peer certificate: CN = cloudflare.com\n"
    )
    parsed = parse_openssl_brief_output(sample_output)
    assert parsed["protocol"] == "TLSv1.3"
    assert parsed["ciphersuite"] == "TLS_AES_256_GCM_SHA384"
    assert parsed["negotiated_group"] == "X25519MLKEM768"
    assert parsed["is_handshake_failure"] is False


def test_parse_openssl_brief_output_temp_key():
    """Verifies extraction of classical curve from Peer Temp Key format."""
    sample_output = (
        "CONNECTION ESTABLISHED\n"
        "Protocol version: TLSv1.3\n"
        "Ciphersuite: TLS_CHACHA20_POLY1305_SHA256\n"
        "Peer Temp Key: X25519, 253 bits\n"
    )
    parsed = parse_openssl_brief_output(sample_output)
    assert parsed["negotiated_group"] == "X25519"
    assert parsed["is_handshake_failure"] is False


def test_parse_openssl_brief_output_handshake_failure():
    """Verifies detection of TLS handshake alerts (e.g. alert 40)."""
    sample_output = (
        "1400234024:error:10000410:SSL routines:OPENSSL_internal:SSLV3_ALERT_HANDSHAKE_FAILURE\n"
        ":handshake failure:alert handshake failure\n"
    )
    parsed = parse_openssl_brief_output(sample_output)
    assert parsed["is_handshake_failure"] is True


# ==============================================================================
# 2. EVIDENCE STATES & OBSERVATION LOGIC TESTS
# ==============================================================================

@patch("app.scanners.tls13_pqc.execute_s_client")
@patch("app.scanners.tls13_pqc.find_openssl_executable", return_value="C:\\fake\\openssl.exe")
def test_observe_tls13_hybrid_observed_passively(mock_find, mock_exec):
    """Case 1: Target defaults to hybrid X25519MLKEM768 without probing (OBSERVED)."""
    mock_exec.return_value = (
        0,
        "Protocol version: TLSv1.3\nCiphersuite: TLS_AES_256_GCM_SHA384\nNegotiated TLS1.3 group: X25519MLKEM768\n"
    )

    ev = observe_tls13_key_exchange(
        hostname="cloudflare.com",
        validated_ip="104.16.132.229",
        port=443,
        probe_pqc=False
    )

    assert ev.status == "OBSERVED"
    assert ev.is_hybrid is True
    assert ev.raw_group == "X25519MLKEM768"
    assert ev.classical_component == "X25519"
    assert ev.pqc_component == "ML-KEM-768"
    assert ev.probe_attempted is False
    assert mock_exec.call_count == 1  # exactly 1 call (passive)


@patch("app.scanners.tls13_pqc.execute_s_client")
@patch("app.scanners.tls13_pqc.find_openssl_executable", return_value="C:\\fake\\openssl.exe")
def test_observe_tls13_classical_only_observed(mock_find, mock_exec):
    """Case 2: Target defaults to X25519 and probe_pqc is False (CLASSICAL_ONLY_OBSERVED)."""
    mock_exec.return_value = (
        0,
        "Protocol version: TLSv1.3\nCiphersuite: TLS_AES_256_GCM_SHA384\nNegotiated TLS1.3 group: X25519\n"
    )

    ev = observe_tls13_key_exchange(
        hostname="wikipedia.org",
        validated_ip="208.80.154.224",
        port=443,
        probe_pqc=False
    )

    assert ev.status == "CLASSICAL_ONLY_OBSERVED"
    assert ev.is_hybrid is False
    assert ev.raw_group == "X25519"
    assert ev.classical_component == "X25519"
    assert ev.pqc_component is None
    assert ev.probe_attempted is False
    assert mock_exec.call_count == 1  # passive only


@patch("app.scanners.tls13_pqc.execute_s_client")
@patch("app.scanners.tls13_pqc.find_openssl_executable", return_value="C:\\fake\\openssl.exe")
def test_observe_tls13_capability_probed_accepted(mock_find, mock_exec):
    """Case 3: Target defaults to X25519, active probe requested, server accepts (CAPABILITY_PROBED)."""
    mock_exec.side_effect = [
        # Call 1 (passive default handshake)
        (0, "Protocol version: TLSv1.3\nNegotiated TLS1.3 group: X25519\n"),
        # Call 2 (active probe with -groups X25519MLKEM768)
        (0, "Protocol version: TLSv1.3\nNegotiated TLS1.3 group: X25519MLKEM768\n"),
    ]

    ev = observe_tls13_key_exchange(
        hostname="hybrid-server.com",
        validated_ip="93.184.216.34",
        port=443,
        probe_pqc=True
    )

    assert ev.status == "CAPABILITY_PROBED"
    assert ev.is_hybrid is True
    assert ev.raw_group == "X25519MLKEM768"
    assert ev.probe_attempted is True
    assert ev.probe_result == "ACCEPTED"
    assert mock_exec.call_count == 2  # exactly 1 passive + 1 probe


@patch("app.scanners.tls13_pqc.execute_s_client")
@patch("app.scanners.tls13_pqc.find_openssl_executable", return_value="C:\\fake\\openssl.exe")
def test_observe_tls13_probed_unsupported_rejected(mock_find, mock_exec):
    """Case 4: Target defaults to X25519, active probe requested, server rejects (PROBED_UNSUPPORTED)."""
    mock_exec.side_effect = [
        # Call 1 (passive default handshake)
        (0, "Protocol version: TLSv1.3\nNegotiated TLS1.3 group: X25519\n"),
        # Call 2 (active probe rejected with handshake failure)
        (1, "handshake failure: alert handshake failure\n"),
    ]

    ev = observe_tls13_key_exchange(
        hostname="wikipedia.org",
        validated_ip="208.80.154.224",
        port=443,
        probe_pqc=True
    )

    assert ev.status == "PROBED_UNSUPPORTED"
    assert ev.is_hybrid is False
    assert ev.raw_group == "X25519"
    assert ev.probe_attempted is True
    assert ev.probe_result == "REJECTED_UNSUPPORTED"
    assert mock_exec.call_count == 2


@patch("app.scanners.tls13_pqc.find_openssl_executable", return_value=None)
def test_observe_tls13_openssl_missing_not_observable(mock_find):
    """Case 5: OpenSSL missing from environment returns NOT_OBSERVABLE without error."""
    ev = observe_tls13_key_exchange(
        hostname="example.com",
        validated_ip="93.184.216.34",
        port=443
    )

    assert ev.status == "NOT_OBSERVABLE"
    assert ev.raw_group == "Not observable"
    assert ev.confidence == "NONE"
    assert ev.is_hybrid is False


@patch("app.scanners.tls13_pqc.execute_s_client")
@patch("app.scanners.tls13_pqc.find_openssl_executable", return_value="C:\\fake\\openssl.exe")
def test_observe_tls13_timeout_not_observable(mock_find, mock_exec):
    """Case 6: Subprocess timeout returns NOT_OBSERVABLE gracefully."""
    mock_exec.return_value = (-1, "TIMEOUT")

    ev = observe_tls13_key_exchange(
        hostname="example.com",
        validated_ip="93.184.216.34",
        port=443
    )

    assert ev.status == "NOT_OBSERVABLE"
    assert ev.raw_group == "Not observable"
    assert "timed out" in ev.details.lower()


# ==============================================================================
# 3. SUBPROCESS SECURITY INVARIANTS
# ==============================================================================

@patch("subprocess.run")
def test_execute_s_client_security_hardening(mock_subproc):
    """Verifies SSRF defense (direct IP), SNI preservation, shell=False, and input=b""."""
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = b"Protocol version: TLSv1.3\n"
    mock_proc.stderr = b""
    mock_subproc.return_value = mock_proc

    execute_s_client(
        openssl_bin="openssl",
        hostname="ebanking.bank.com",
        target_ip="198.51.100.10",
        port=8443,
        groups="X25519MLKEM768",
        timeout=7.5
    )

    assert mock_subproc.call_count == 1
    args, kwargs = mock_subproc.call_args

    cmd_list = args[0]
    # Connect MUST be target_ip:port (SSRF & DNS rebinding defense)
    assert "-connect" in cmd_list
    connect_idx = cmd_list.index("-connect")
    assert cmd_list[connect_idx + 1] == "198.51.100.10:8443"

    # Servername MUST be hostname (SNI preservation)
    assert "-servername" in cmd_list
    sni_idx = cmd_list.index("-servername")
    assert cmd_list[sni_idx + 1] == "ebanking.bank.com"

    # Groups flag
    assert "-groups" in cmd_list
    grp_idx = cmd_list.index("-groups")
    assert cmd_list[grp_idx + 1] == "X25519MLKEM768"

    # Hardening flags
    assert kwargs.get("shell") is False
    assert kwargs.get("input") == b""
    assert kwargs.get("timeout") == 7.5


# ==============================================================================
# 4. SINGLE FINDING & ZERO DOUBLE COUNTING INVARIANT
# ==============================================================================

def test_single_key_establishment_finding_hybrid():
    """Verifies exactly ONE finding is generated for hybrid key exchange with readiness=100."""
    cert_data = {
        "public_key_algorithm": "ECC",
        "key_size_bits": 256,
        "curve_name": "secp256r1",
        "signature_algorithm": "ecdsa-with-SHA256",
        "days_remaining": 90,
    }
    tls_data = {
        "negotiated_protocol": "TLSv1.3",
        "negotiated_cipher": "TLS_AES_256_GCM_SHA384",
        "cipher_bits": 256,
        "pqc_evidence": {
            "raw_group": "X25519MLKEM768",
            "status": "OBSERVED",
            "classical_component": "X25519",
            "pqc_component": "ML-KEM-768",
            "is_hybrid": True,
            "source": "OpenSSL TLS 1.3 KeyShare Handshake",
            "confidence": "HIGH",
        }
    }

    mechanisms, _ = normalize_cryptographic_mechanisms(cert_data, tls_data)
    findings, score, roles, exec_summary, plan, _ = evaluate_quantum_risk(
        mechanisms, tls_data, cert_data, domain="hybrid.example.com"
    )

    # Invariant: EXACTLY 1 key exchange finding
    kx_findings = [f for f in findings if f.category == "key_exchange"]
    assert len(kx_findings) == 1
    assert kx_findings[0].id == "FND-KX-PQC-01"
    assert kx_findings[0].risk_level == "INFORMATIONAL"
    assert kx_findings[0].evidence == "OBSERVED"
    assert "Hybrid Post-Quantum" in kx_findings[0].title

    # Readiness score for Key Establishment must be 100
    kx_role = next(r for r in roles if r.category_id == "key_establishment")
    assert kx_role.readiness_score == 100
    assert kx_role.status == "EXCELLENT"


def test_single_key_establishment_finding_classical_only():
    """Verifies exactly ONE finding is generated for CLASSICAL_ONLY_OBSERVED."""
    cert_data = {
        "public_key_algorithm": "RSA",
        "key_size_bits": 2048,
        "signature_algorithm": "sha256WithRSAEncryption",
        "days_remaining": 120,
    }
    tls_data = {
        "negotiated_protocol": "TLSv1.3",
        "negotiated_cipher": "TLS_AES_256_GCM_SHA384",
        "cipher_bits": 256,
        "pqc_evidence": {
            "raw_group": "X25519",
            "status": "CLASSICAL_ONLY_OBSERVED",
            "classical_component": "X25519",
            "pqc_component": None,
            "is_hybrid": False,
            "source": "OpenSSL TLS 1.3 KeyShare Handshake",
            "confidence": "HIGH",
        }
    }

    mechanisms, _ = normalize_cryptographic_mechanisms(cert_data, tls_data)
    findings, score, roles, exec_summary, plan, _ = evaluate_quantum_risk(
        mechanisms, tls_data, cert_data, domain="classical.example.com"
    )

    kx_findings = [f for f in findings if f.category == "key_exchange"]
    assert len(kx_findings) == 1
    assert kx_findings[0].id == "FND-KX-02"
    assert kx_findings[0].risk_level == "HIGH"
    assert kx_findings[0].evidence == "CLASSICAL_ONLY_OBSERVED"

    kx_role = next(r for r in roles if r.category_id == "key_establishment")
    assert kx_role.readiness_score == 50
    assert kx_role.status == "HIGH RISK"


def test_single_key_establishment_finding_probed_unsupported():
    """Verifies PROBED_UNSUPPORTED generates exactly ONE finding without double counting."""
    cert_data = {
        "public_key_algorithm": "RSA",
        "key_size_bits": 2048,
        "signature_algorithm": "sha256WithRSAEncryption",
        "days_remaining": 60,
    }
    tls_data = {
        "negotiated_protocol": "TLSv1.3",
        "negotiated_cipher": "TLS_AES_256_GCM_SHA384",
        "cipher_bits": 256,
        "pqc_evidence": {
            "raw_group": "X25519",
            "status": "PROBED_UNSUPPORTED",
            "classical_component": "X25519",
            "pqc_component": None,
            "is_hybrid": False,
            "source": "Active TLS 1.3 KeyShare Probe",
            "confidence": "HIGH",
        }
    }

    mechanisms, _ = normalize_cryptographic_mechanisms(cert_data, tls_data)
    findings, score, roles, exec_summary, plan, _ = evaluate_quantum_risk(
        mechanisms, tls_data, cert_data, domain="legacy.example.com"
    )

    kx_findings = [f for f in findings if f.category == "key_exchange"]
    assert len(kx_findings) == 1
    assert kx_findings[0].evidence == "PROBED_UNSUPPORTED"
    assert "Unsupported" in kx_findings[0].title
    assert kx_findings[0].risk_level == "HIGH"


def test_single_key_establishment_finding_not_observable():
    """Verifies NOT_OBSERVABLE generates exactly ONE finding and does NOT penalize target."""
    cert_data = {
        "public_key_algorithm": "RSA",
        "key_size_bits": 2048,
        "signature_algorithm": "sha256WithRSAEncryption",
        "days_remaining": 150,
    }
    tls_data = {
        "negotiated_protocol": "TLSv1.3",
        "negotiated_cipher": "TLS_AES_256_GCM_SHA384",
        "cipher_bits": 256,
        "pqc_evidence": {
            "raw_group": "Not observable",
            "status": "NOT_OBSERVABLE",
            "is_hybrid": False,
            "source": "Client TLS API",
            "confidence": "NONE",
        }
    }

    mechanisms, _ = normalize_cryptographic_mechanisms(cert_data, tls_data)
    findings, score, roles, exec_summary, plan, _ = evaluate_quantum_risk(
        mechanisms, tls_data, cert_data, domain="unobservable.example.com"
    )

    kx_findings = [f for f in findings if f.category == "key_exchange"]
    assert len(kx_findings) == 1
    assert kx_findings[0].id == "FND-KX-01"
    assert kx_findings[0].risk_level == "INFORMATIONAL"
    assert kx_findings[0].evidence == "NOT_OBSERVABLE"

    kx_role = next(r for r in roles if r.category_id == "key_establishment")
    assert kx_role.readiness_score == 70  # Neutral baseline, NOT 0 or 50


# ==============================================================================
# 5. AUDIT LAYER ADAPTER INTEGRATION TESTS
# ==============================================================================

def test_map_hybrid_finding_to_audit_layer():
    """Verifies that hybrid PQC finding maps to AuditFinding under QUANTUM_SECURITY and TLS Key Establishment."""
    q_finding = QuantumFinding(
        id="FND-KX-PQC-01",
        title="Hybrid Post-Quantum Key Exchange Active (X25519MLKEM768)",
        role="Key Establishment",
        value="X25519MLKEM768",
        source="OpenSSL TLS 1.3 KeyShare Handshake",
        evidence="CAPABILITY_PROBED",
        component="tls_key_exchange",
        algorithm="X25519MLKEM768",
        category="key_exchange",
        quantum_threat="Protected against Store Now, Decrypt Later (SNDL) via NIST FIPS 203 hybrid KEM",
        quantum_threat_vector="RESISTANT",
        risk_level="INFORMATIONAL",
        security_impact="Protected",
        reason="Hybrid",
        recommendation="Maintain",
        migration_target="NIST FIPS 203",
        priority="P3",
        priority_score=15,
        observability="CAPABILITY_PROBED",
    )

    audit_finding = map_quantum_finding_to_audit_finding(q_finding, asset_id="AST-BANK-001")

    assert audit_finding.asset_id == "AST-BANK-001"
    assert audit_finding.domain == AuditDomain.QUANTUM_SECURITY
    assert audit_finding.control == "TLS Key Establishment"
    assert audit_finding.observability == ObservabilityState.CAPABILITY_PROBED
    assert audit_finding.severity == FindingSeverity.INFORMATIONAL


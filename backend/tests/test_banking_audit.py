"""Unit and integration tests for Phase 0 - Banking Security Audit Architecture.

Tests:
- Banking asset model, asset type enum, criticality enum, data sensitivity enum,
  exposure enum, data lifetime enum, trust zone enum.
- Distinction between asset criticality (business context) and finding severity (technical risk).
- Unified AuditFinding model and AuditDomain classifications.
- ObservabilityState semantics: strict verification that NOT_OBSERVABLE does NOT assign vulnerability.
- Mapping of existing QuantumFindings into AuditFindings with preservation of cryptographic semantics.
- Zero Trust domain architecture (6 NIST SP 800-207 pillars).
- Multidimensional risk separation (quantum risk, classical risk, zero trust, asset criticality).
- POST /api/audit endpoint integration and contract verification.
- Preservation of scanner security hardening on /api/audit (SSRF, rate limiting).
"""

from unittest.mock import patch, MagicMock
import pytest
from starlette.testclient import TestClient

from app.main import app
from app.models.banking import (
    BankingAssetType,
    AssetCriticality,
    DataSensitivity,
    AssetExposure,
    DataLifetime,
    TrustZone,
    BankingAsset,
    infer_default_banking_asset,
)
from app.models.audit import (
    AuditDomain,
    FindingSeverity,
    RemediationPriority,
    ObservabilityState,
    AuditFinding,
    AuditSummary,
)
from app.models.zero_trust import (
    ZeroTrustPillar,
    ZeroTrustControlStatus,
    ZeroTrustControl,
    ZeroTrustAssessment,
    build_default_zero_trust_assessment,
)
from app.models.risk import RiskDimensions
from app.schemas.scan import QuantumFinding
from app.services.crypto_audit_adapter import (
    map_quantum_finding_to_audit_finding,
    map_findings_to_audit_layer,
    summarize_audit_findings,
    map_severity,
    map_priority,
    map_observability,
)
from app.security.rate_limiter import DEFAULT_RATE_LIMITER

client = TestClient(app)


# ============================================================================
# 1. BANKING DOMAIN ENUMS & ASSET MODEL TESTS
# ============================================================================

def test_banking_enums_values():
    """Verifies that all banking domain enums contain the required domain values."""
    # Asset types
    assert BankingAssetType.PUBLIC_WEBSITE == "PUBLIC_WEBSITE"
    assert BankingAssetType.WEB_BANKING == "WEB_BANKING"
    assert BankingAssetType.API_GATEWAY == "API_GATEWAY"
    assert BankingAssetType.PAYMENT_SERVICE == "PAYMENT_SERVICE"
    assert BankingAssetType.CUSTOMER_DATABASE == "CUSTOMER_DATABASE"

    # Asset Criticality (Business Context)
    assert [c.value for c in AssetCriticality] == ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

    # Data Sensitivity
    assert [s.value for s in DataSensitivity] == ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "HIGHLY_SENSITIVE"]

    # Exposure
    assert [e.value for e in AssetExposure] == ["INTERNET", "PARTNER", "INTERNAL", "RESTRICTED"]

    # Data Lifetime
    assert [l.value for l in DataLifetime] == ["SHORT", "MEDIUM", "LONG", "VERY_LONG"]

    # Trust Zones
    assert [z.value for z in TrustZone] == ["PUBLIC", "DMZ", "APPLICATION", "DATA", "ADMIN", "THIRD_PARTY"]


def test_banking_asset_creation():
    """Verifies creation and field validation of a BankingAsset instance."""
    asset = BankingAsset(
        id="ASSET-CHASE-01",
        name="Retail Online Banking Portal",
        asset_type=BankingAssetType.WEB_BANKING,
        description="Core customer banking interface",
        criticality=AssetCriticality.CRITICAL,
        data_sensitivity=DataSensitivity.HIGHLY_SENSITIVE,
        exposure=AssetExposure.INTERNET,
        data_lifetime=DataLifetime.VERY_LONG,
        trust_zone=TrustZone.DMZ,
        tags=["retail", "pci", "sox"],
    )

    assert asset.id == "ASSET-CHASE-01"
    assert asset.criticality == AssetCriticality.CRITICAL
    assert asset.trust_zone == TrustZone.DMZ
    assert "pci" in asset.tags


def test_infer_default_banking_asset():
    """Verifies realistic default banking asset inference from hostnames."""
    api_asset = infer_default_banking_asset("api.chase.com")
    assert api_asset.asset_type == BankingAssetType.API_GATEWAY
    assert api_asset.criticality == AssetCriticality.HIGH

    pay_asset = infer_default_banking_asset("payments.stripe.com")
    assert pay_asset.asset_type == BankingAssetType.PAYMENT_SERVICE
    assert pay_asset.criticality == AssetCriticality.CRITICAL
    assert pay_asset.data_sensitivity == DataSensitivity.HIGHLY_SENSITIVE

    web_asset = infer_default_banking_asset("ebanking.wellsfargo.com")
    assert web_asset.asset_type == BankingAssetType.WEB_BANKING
    assert web_asset.criticality == AssetCriticality.CRITICAL

    pub_asset = infer_default_banking_asset("about.google.com")
    assert pub_asset.asset_type == BankingAssetType.PUBLIC_WEBSITE
    assert pub_asset.criticality == AssetCriticality.MEDIUM


# ============================================================================
# 2. AUDIT FINDING & OBSERVABILITY SEMANTICS TESTS
# ============================================================================

def test_criticality_distinct_from_finding_severity():
    """
    Core Architecture Rule:
    Asset Criticality (business context) != Finding Severity (technical risk).
    """
    asset = BankingAsset(
        id="ASSET-DB-01",
        name="Payment DB",
        criticality=AssetCriticality.CRITICAL,
    )

    finding = AuditFinding(
        id="AUD-01",
        asset_id=asset.id,
        domain=AuditDomain.CLASSICAL_SECURITY,
        control="TLS Cipher Configuration",
        title="Informational Cipher Suite Announcement",
        severity=FindingSeverity.LOW,  # Low technical severity on a CRITICAL asset
        evidence="TLS_AES_256_GCM_SHA384",
        evidence_source="TLS Handshake",
        observability=ObservabilityState.OBSERVED,
        recommendation="Maintain current cipher configuration.",
        remediation_priority=RemediationPriority.P3,
    )

    assert asset.criticality == AssetCriticality.CRITICAL
    assert finding.severity == FindingSeverity.LOW
    assert asset.criticality.value != finding.severity.value


def test_not_observable_does_not_equal_vulnerable():
    """
    Core Architecture Rule:
    NOT_OBSERVABLE != VULNERABLE.
    Unobservable items must never be marked as HIGH or CRITICAL vulnerabilities.
    """
    # Test helper
    severity = map_severity("CRITICAL", ObservabilityState.NOT_OBSERVABLE)
    assert severity == FindingSeverity.INFORMATIONAL, "NOT_OBSERVABLE must map to INFORMATIONAL, never CRITICAL!"

    severity_high = map_severity("HIGH", ObservabilityState.NOT_OBSERVABLE)
    assert severity_high == FindingSeverity.INFORMATIONAL, "NOT_OBSERVABLE must map to INFORMATIONAL, never HIGH!"

    # Observed items can be CRITICAL or HIGH
    severity_observed = map_severity("CRITICAL", ObservabilityState.OBSERVED)
    assert severity_observed == FindingSeverity.CRITICAL


def test_audit_domain_classification():
    """Verifies that audit findings are classified into appropriate security domains."""
    domains = [d.value for d in AuditDomain]
    assert "CRYPTOGRAPHY" in domains
    assert "QUANTUM_SECURITY" in domains
    assert "ZERO_TRUST" in domains
    assert "CLASSICAL_SECURITY" in domains


# ============================================================================
# 3. MAPPING CRYPTO FINDINGS INTO AUDIT FINDINGS
# ============================================================================

def test_map_rsa_finding_to_audit_finding():
    """Verifies mapping of an RSA-2048 certificate finding into an AuditFinding."""
    mock_qf = QuantumFinding(
        id="FND-CERT-01",
        title="RSA-2048 Certificate Public Key Exposed",
        role="Certificate Public Key",
        value="RSA-2048",
        source="TLS Leaf Certificate",
        evidence="OBSERVED",
        component="certificate_public_key",
        algorithm="RSA",
        category="public_key",
        quantum_threat="Shor's algorithm (Integer Factorization)",
        risk_level="HIGH",
        security_impact="Shor's algorithm can factor 2048-bit RSA keys.",
        reason="Vulnerable to Shor's algorithm.",
        recommendation="Migrate to NIST FIPS 204 (ML-DSA).",
        migration_target="ML-DSA / SLH-DSA",
        priority="P1",
    )

    audit_finding = map_quantum_finding_to_audit_finding(mock_qf, "BANK-ASSET-001")

    assert audit_finding.id == "FND-CERT-01"
    assert audit_finding.asset_id == "BANK-ASSET-001"
    assert audit_finding.domain == AuditDomain.QUANTUM_SECURITY
    assert audit_finding.control == "Certificate Public Key"
    assert audit_finding.severity == FindingSeverity.HIGH
    assert audit_finding.evidence == "RSA-2048"
    assert audit_finding.observability == ObservabilityState.OBSERVED
    assert audit_finding.remediation_priority == RemediationPriority.P1
    assert "ML-DSA" in audit_finding.recommendation
    assert audit_finding.metadata["quantum_threat"] == "Shor's algorithm (Integer Factorization)"


def test_map_tls13_unobservable_keyshare_finding():
    """Verifies mapping of unobservable TLS 1.3 KeyShare group finding."""
    mock_qf = QuantumFinding(
        id="FND-KX-13",
        title="TLS 1.3 Key Exchange Unobservable Externally",
        role="Key Exchange",
        value="Not observable",
        source="TLS Handshake Negotiation",
        evidence="NOT_OBSERVABLE",
        component="tls_key_exchange",
        algorithm="Not observable",
        category="key_exchange",
        quantum_threat="Store Now, Decrypt Later (SNDL)",
        risk_level="INFORMATIONAL",
        recommendation="Verify internal KeyShare group configuration.",
        priority="P3",
    )

    audit_finding = map_quantum_finding_to_audit_finding(mock_qf, "BANK-ASSET-001")

    assert audit_finding.observability == ObservabilityState.NOT_OBSERVABLE
    assert audit_finding.severity == FindingSeverity.INFORMATIONAL
    assert audit_finding.evidence == "Not observable"
    assert audit_finding.remediation_priority == RemediationPriority.P3


def test_summarize_audit_findings():
    """Verifies audit summary metrics calculation across findings."""
    findings = [
        AuditFinding(
            id="A1", asset_id="AS1", domain=AuditDomain.QUANTUM_SECURITY,
            control="C1", title="T1", severity=FindingSeverity.HIGH,
            evidence="E1", evidence_source="S1", observability=ObservabilityState.OBSERVED,
            recommendation="R1", remediation_priority=RemediationPriority.P1
        ),
        AuditFinding(
            id="A2", asset_id="AS1", domain=AuditDomain.CLASSICAL_SECURITY,
            control="C2", title="T2", severity=FindingSeverity.MEDIUM,
            evidence="E2", evidence_source="S2", observability=ObservabilityState.OBSERVED,
            recommendation="R2", remediation_priority=RemediationPriority.P2
        ),
        AuditFinding(
            id="A3", asset_id="AS1", domain=AuditDomain.QUANTUM_SECURITY,
            control="C3", title="T3", severity=FindingSeverity.INFORMATIONAL,
            evidence="Not observable", evidence_source="S3", observability=ObservabilityState.NOT_OBSERVABLE,
            recommendation="R3", remediation_priority=RemediationPriority.P3
        ),
    ]

    summary = summarize_audit_findings(findings)
    assert summary.total_findings == 3
    assert summary.high_count == 1
    assert summary.medium_count == 1
    assert summary.informational_count == 1
    assert summary.critical_count == 0
    assert summary.observability_breakdown["OBSERVED"] == 2
    assert summary.observability_breakdown["NOT_OBSERVABLE"] == 1
    assert AuditDomain.QUANTUM_SECURITY in summary.domains_covered
    assert AuditDomain.CLASSICAL_SECURITY in summary.domains_covered


# ============================================================================
# 4. ZERO TRUST DOMAIN & RISK DIMENSIONS TESTS
# ============================================================================

def test_zero_trust_assessment_structure():
    """Verifies the Zero Trust assessment structure models all 6 NIST SP 800-207 pillars."""
    zt = build_default_zero_trust_assessment("BANK-ASSET-42", tls_version="TLSv1.3")

    assert zt.asset_id == "BANK-ASSET-42"
    assert zt.identity_control.pillar == ZeroTrustPillar.IDENTITY
    assert zt.context_control.pillar == ZeroTrustPillar.DEVICE_CONTEXT
    assert zt.resource_control.pillar == ZeroTrustPillar.RESOURCE
    assert zt.policy_control.pillar == ZeroTrustPillar.POLICY
    assert zt.least_privilege_control.pillar == ZeroTrustPillar.LEAST_PRIVILEGE
    assert zt.continuous_verification_control.pillar == ZeroTrustPillar.CONTINUOUS_VERIFICATION

    # Edge transport encryption is verified; internal controls are transparently unobservable externally
    assert zt.resource_control.status == ZeroTrustControlStatus.VERIFIED
    assert zt.resource_control.observability == ObservabilityState.OBSERVED
    assert zt.identity_control.status == ZeroTrustControlStatus.NOT_OBSERVABLE_EXTERNALLY
    assert zt.identity_control.observability == ObservabilityState.NOT_OBSERVABLE


def test_risk_dimensions_separation():
    """Verifies separation of Quantum Risk, Classical Risk, Zero Trust, and Asset Criticality."""
    risk = RiskDimensions(
        quantum_risk_score=28,
        quantum_readiness_score=72,
        classical_security_risk="LOW",
        zero_trust_posture="EDGE_ENCRYPTED_INTERNAL_UNKNOWN",
        asset_criticality=AssetCriticality.HIGH,
    )

    assert risk.quantum_readiness_score == 72
    assert risk.quantum_risk_score == 28
    assert risk.classical_security_risk == "LOW"
    assert risk.asset_criticality == AssetCriticality.HIGH


# ============================================================================
# 5. INTEGRATION TESTS: /api/audit ENDPOINT
# ============================================================================

def test_audit_endpoint_success():
    """Verifies POST /api/audit contract returns asset, audit, crypto, zero_trust, and risk."""
    DEFAULT_RATE_LIMITER.reset()

    mock_scan_return = {
        "target": {
            "domain": "ebanking.example.com",
            "port": 443,
            "resolved_ip": "93.184.216.34",
            "ip_version": "IPv4",
            "scan_timestamp": "2026-10-30T12:00:00Z",
            "connection_time_ms": 35.0,
        },
        "certificate": {
            "subject_cn": "ebanking.example.com",
            "subject_alt_names": ["ebanking.example.com"],
            "serial_number": "123456",
            "fingerprint_sha256": "AB:CD:EF:01",
            "not_valid_before": "2026-01-01T00:00:00Z",
            "not_valid_after": "2027-01-01T00:00:00Z",
            "days_remaining": 60,
            "is_expired": False,
            "public_key_algorithm": "RSA",
            "key_size_bits": 2048,
            "signature_algorithm": "sha256WithRSAEncryption",
            "chain_length": 1,
            "chain_certificates": [],
            "verification_status": "Trusted by system root CAs",
            "is_trusted": True,
        },
        "tls": {
            "negotiated_protocol": "TLSv1.3",
            "negotiated_cipher": "TLS_AES_256_GCM_SHA384",
            "cipher_bits": 256,
            "session_reused": False,
        }
    }

    with patch("app.services.assessment_service.TlsScanner.scan", return_value=mock_scan_return):
        response = client.post(
            "/api/audit",
            json={
                "domain": "ebanking.example.com",
                "asset_type": "WEB_BANKING",
                "criticality": "CRITICAL",
                "trust_zone": "DMZ",
                "tags": ["retail-core", "fintech"],
            }
        )

        assert response.status_code == 200
        data = response.json()

        # 1. Asset
        assert "asset" in data
        assert data["asset"]["name"] == "Online Banking Portal (ebanking.example.com)"
        assert data["asset"]["asset_type"] == "WEB_BANKING"
        assert data["asset"]["criticality"] == "CRITICAL"
        assert data["asset"]["trust_zone"] == "DMZ"

        # 2. Audit summary & findings
        assert "audit" in data
        assert data["audit"]["total_findings"] >= 1
        assert len(data["findings"]) >= 1
        assert data["findings"][0]["domain"] in ["QUANTUM_SECURITY", "CRYPTOGRAPHY", "CLASSICAL_SECURITY"]

        # 3. Zero Trust
        assert "zero_trust" in data
        assert data["zero_trust"]["resource_control"]["status"] == "VERIFIED"
        assert data["zero_trust"]["identity_control"]["status"] == "NOT_OBSERVABLE_EXTERNALLY"

        # 4. Multidimensional Risk
        assert "risk" in data
        assert data["risk"]["quantum_readiness_score"] >= 0
        assert data["risk"]["quantum_risk_score"] >= 0
        assert data["risk"]["asset_criticality"] == "CRITICAL"
        assert data["risk"]["classical_security_risk"] == "LOW"

    DEFAULT_RATE_LIMITER.reset()


def test_audit_endpoint_ssrf_protection():
    """Verifies that POST /api/audit enforces Phase 2C SSRF defenses."""
    DEFAULT_RATE_LIMITER.reset()
    response = client.post("/api/audit", json={"domain": "127.0.0.1"})
    assert response.status_code == 400
    data = response.json()
    assert data["error"] == "DOMAIN_VALIDATION_ERROR"
    assert "Direct IP addresses are prohibited" in data["detail"]


def test_scan_endpoint_enriches_audit_fields():
    """Verifies backward compatibility: /api/scan now returns banking_asset and audit_findings."""
    DEFAULT_RATE_LIMITER.reset()
    mock_scan_return = {
        "target": {
            "domain": "api.mockbank.org",
            "port": 443,
            "resolved_ip": "93.184.216.34",
            "ip_version": "IPv4",
            "scan_timestamp": "2026-10-30T12:00:00Z",
            "connection_time_ms": 30.0,
        },
        "certificate": {
            "subject_cn": "api.mockbank.org",
            "subject_alt_names": ["api.mockbank.org"],
            "serial_number": "12345",
            "fingerprint_sha256": "AB:CD:EF",
            "not_valid_before": "2026-01-01T00:00:00Z",
            "not_valid_after": "2027-01-01T00:00:00Z",
            "days_remaining": 60,
            "is_expired": False,
            "public_key_algorithm": "RSA",
            "key_size_bits": 2048,
            "signature_algorithm": "sha256WithRSAEncryption",
            "chain_length": 1,
            "chain_certificates": [],
            "verification_status": "Trusted",
            "is_trusted": True,
        },
        "tls": {
            "negotiated_protocol": "TLSv1.3",
            "negotiated_cipher": "TLS_AES_256_GCM_SHA384",
            "cipher_bits": 256,
            "session_reused": False,
        }
    }

    with patch("app.services.assessment_service.TlsScanner.scan", return_value=mock_scan_return):
        response = client.post("/api/scan", json={"domain": "api.mockbank.org"})
        assert response.status_code == 200
        data = response.json()

        # Check existing fields preserved
        assert data["scan_status"] == "SUCCESS"
        assert data["score"]["score"] >= 0

        # Check new Phase 0 fields present
        assert "banking_asset" in data and data["banking_asset"] is not None
        assert data["banking_asset"]["asset_type"] == "API_GATEWAY"
        assert "audit_findings" in data and len(data["audit_findings"]) > 0
        assert "zero_trust" in data and data["zero_trust"] is not None

    DEFAULT_RATE_LIMITER.reset()

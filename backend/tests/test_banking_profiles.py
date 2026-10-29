"""Unit and integration tests for Phase 4A - Banking System Profiles & Configuration Evidence Model.

Tests cover:
- Banking system types enum and Phase 4A system classifications.
- Multi-layer security architecture (SecurityLayer).
- Evidence provenance (EvidenceSource: EXTERNAL_SCAN, OPERATOR_DECLARED, CONFIGURATION_FILE, INFERRED).
- EvidenceGap model and standard gap types (enforcing NOT_OBSERVABLE != VULNERABLE).
- KeyProtectionChain model (Data Encryption -> Key Wrapping -> Key Storage -> Authentication).
- CryptoConfiguration normalized representation.
- BankingAsset / BankingSystemProfile validation and invariants.
- 5 synthetic banking profiles catalog and disclaimer.
- API endpoints: GET /api/banking/profiles and GET /api/banking/profiles/{id}.
- Asset association with live scans: observed TLS telemetry integrity preserved.
"""

from unittest.mock import patch, MagicMock
import pytest
from pydantic import ValidationError
from starlette.testclient import TestClient

from app.main import app
from app.models.banking import (
    BankingAsset,
    BankingAssetType,
    AssetCriticality,
    DataSensitivity,
    AssetExposure,
    DataLifetime,
    TrustZone,
    SecurityLayer,
    EvidenceSource,
    EvidenceGapType,
    EvidenceItem,
    EvidenceGap,
    CryptoConfiguration,
    KeyProtectionChain,
    BankingSystemProfile,
)
from app.models.audit import ObservabilityState
from app.models.profiles import (
    SYNTHETIC_BANKING_PROFILES,
    SYNTHETIC_DISCLAIMER,
    get_synthetic_banking_profiles,
    get_synthetic_profile_by_id,
)
from app.services.assessment_service import assess_domain
from app.security.rate_limiter import DEFAULT_RATE_LIMITER

client = TestClient(app)


# ============================================================================
# 1. ENUMS & CONSTANTS TESTS
# ============================================================================

def test_phase4a_banking_asset_types():
    """Verifies that all Phase 4A representative banking systems are defined."""
    expected_types = [
        "NET_BANKING_PORTAL",
        "MOBILE_BANKING_API",
        "PAYMENT_GATEWAY",
        "UPI_PAYMENT_SERVICE",
        "CARD_PROCESSING",
        "CORE_BANKING",
        "CUSTOMER_DATABASE",
        "PAYMENT_DATABASE",
        "INTER_BANK_GATEWAY",
        "ATM_NETWORK",
        "ADMIN_PORTAL",
        "AUTHENTICATION_SERVICE",
        "NOTIFICATION_SERVICE",
        "INTERNAL_SERVICE",
        "OTHER",
    ]
    for exp in expected_types:
        assert hasattr(BankingAssetType, exp), f"Missing BankingAssetType: {exp}"
        assert BankingAssetType[exp].value == exp


def test_security_layers_enum():
    """Verifies all normalized architecture security layers are present."""
    expected_layers = ["EDGE", "API_GATEWAY", "SERVICE_TO_SERVICE", "DATA_AND_KEYS", "ADMINISTRATIVE"]
    actual_layers = [layer.value for layer in SecurityLayer]
    assert sorted(actual_layers) == sorted(expected_layers)


def test_evidence_source_enum():
    """Verifies explicit evidence provenance classifications."""
    assert EvidenceSource.EXTERNAL_SCAN.value == "EXTERNAL_SCAN"
    assert EvidenceSource.OPERATOR_DECLARED.value == "OPERATOR_DECLARED"
    assert EvidenceSource.CONFIGURATION_FILE.value == "CONFIGURATION_FILE"
    assert EvidenceSource.INFERRED.value == "INFERRED"


def test_evidence_gap_types_enum():
    """Verifies standardized evidence gap types for internal controls."""
    expected_gaps = [
        "INTERNAL_MTLS",
        "HSM_USAGE",
        "KMS_USAGE",
        "KEY_ROTATION",
        "DATABASE_ENCRYPTION_AT_REST",
        "PRIVILEGED_ACCESS_POLICY",
        "MFA_POLICY",
        "SERVICE_IDENTITY",
        "LEAST_PRIVILEGE",
        "CONTINUOUS_VERIFICATION",
        "KEY_WRAPPING",
        "INTERNAL_CERTIFICATE_POLICY",
    ]
    for gap in expected_gaps:
        assert hasattr(EvidenceGapType, gap), f"Missing EvidenceGapType: {gap}"


# ============================================================================
# 2. MODEL VALIDATION & INVARIANTS
# ============================================================================

def test_banking_asset_validation_success():
    """Tests creating a valid BankingAsset with all Phase 4A fields."""
    asset = BankingAsset(
        id="TEST-ASSET-01",
        name="Test Ingress Gateway",
        asset_type=BankingAssetType.PAYMENT_GATEWAY,
        system_type=BankingAssetType.PAYMENT_GATEWAY,
        criticality=AssetCriticality.CRITICAL,
        data_sensitivity=DataSensitivity.HIGHLY_SENSITIVE,
        exposure=AssetExposure.INTERNET,
        data_lifetime=DataLifetime.VERY_LONG,
        trust_zone=TrustZone.DMZ,
        cryptography=CryptoConfiguration(
            tls_versions=["TLSv1.3"],
            cipher_suites=["TLS_AES_256_GCM_SHA384"],
            key_exchange="X25519MLKEM768",
            key_chain=KeyProtectionChain(
                data_encryption="AES-256-GCM",
                key_wrapping="ML-KEM-768",
                key_storage="HSM",
                authentication="ECDSA-P256",
            ),
        ),
        evidence_items=[
            EvidenceItem(
                id="EV-01",
                control="Transport Security",
                value="TLSv1.3",
                source=EvidenceSource.EXTERNAL_SCAN,
                observability=ObservabilityState.OBSERVED,
                layer=SecurityLayer.EDGE,
            )
        ],
        evidence_gaps=[
            EvidenceGap(
                gap_type=EvidenceGapType.HSM_USAGE,
                layer=SecurityLayer.DATA_AND_KEYS,
                control="HSM Key Isolation",
                description="Hardware security module cannot be validated externally",
                evidence_needed="HSM serial audit log or KMS key policy",
            )
        ],
    )

    assert asset.id == "TEST-ASSET-01"
    assert asset.asset_type == BankingAssetType.PAYMENT_GATEWAY
    assert asset.system_type == BankingAssetType.PAYMENT_GATEWAY
    assert len(asset.evidence_items) == 1
    assert len(asset.evidence_gaps) == 1
    assert SecurityLayer.EDGE in asset.layers
    assert asset.layers[SecurityLayer.EDGE][0].id == "EV-01"


def test_banking_asset_validation_invalid_enums():
    """Tests that invalid enum strings raise Pydantic ValidationErrors."""
    with pytest.raises(ValidationError):
        BankingAsset(id="FAIL-1", name="Fail", criticality="SUPER_CRITICAL")  # type: ignore

    with pytest.raises(ValidationError):
        BankingAsset(id="FAIL-2", name="Fail", data_sensitivity="ULTRA_SECRET")  # type: ignore

    with pytest.raises(ValidationError):
        BankingAsset(id="FAIL-3", name="Fail", exposure="EVERYWHERE")  # type: ignore

    with pytest.raises(ValidationError):
        BankingAsset(id="FAIL-4", name="Fail", data_lifetime="ETERNAL")  # type: ignore

    with pytest.raises(ValidationError):
        BankingAsset(id="FAIL-5", name="Fail", trust_zone="OUTER_SPACE")  # type: ignore


def test_invariant_not_observable_is_not_vulnerable():
    """
    CRITICAL INVARIANT:
    ObservabilityState.NOT_OBSERVABLE must NOT equal or imply a failure or vulnerability.
    Missing evidence is an evidence gap, not a failed control.
    """
    gap = EvidenceGap(
        gap_type=EvidenceGapType.INTERNAL_MTLS,
        layer=SecurityLayer.SERVICE_TO_SERVICE,
        control="Internal Pod mTLS",
        description="Internal pod communication is within VPC and not observable from public internet",
        evidence_needed="Mesh configuration export or Istio PeerAuthentication manifest",
        observability=ObservabilityState.NOT_OBSERVABLE,
        source=EvidenceSource.EXTERNAL_SCAN,
    )

    assert gap.observability == ObservabilityState.NOT_OBSERVABLE
    # Assert that this is NOT classified as a vulnerable or broken state
    assert gap.observability.value != "VULNERABLE"
    assert gap.observability.value != "FAILED"
    assert gap.observability.value != "DEGRADED"


def test_evidence_source_provenance_distinction():
    """
    Verifies that OPERATOR_DECLARED and CONFIGURATION_FILE evidence
    are strictly distinguished from EXTERNAL_SCAN.
    """
    scan_item = EvidenceItem(
        id="EV-SCAN",
        control="TLS Protocol",
        value="TLSv1.3",
        source=EvidenceSource.EXTERNAL_SCAN,
        observability=ObservabilityState.OBSERVED,
    )
    declared_item = EvidenceItem(
        id="EV-DECL",
        control="HSM Root Storage",
        value="Thales payShield 10K",
        source=EvidenceSource.OPERATOR_DECLARED,
        observability=ObservabilityState.OBSERVED,
    )
    config_item = EvidenceItem(
        id="EV-CONF",
        control="Database Encryption",
        value="Oracle TDE AES-256",
        source=EvidenceSource.CONFIGURATION_FILE,
        observability=ObservabilityState.OBSERVED,
    )

    assert scan_item.source == EvidenceSource.EXTERNAL_SCAN
    assert declared_item.source == EvidenceSource.OPERATOR_DECLARED
    assert config_item.source == EvidenceSource.CONFIGURATION_FILE
    assert scan_item.source != declared_item.source
    assert declared_item.source != config_item.source


def test_key_protection_chain_models():
    """Verifies KeyProtectionChain representation across various architectures."""
    # 1. Classical RSA wrapping
    chain_classical = KeyProtectionChain(
        data_encryption="AES-256-GCM",
        key_wrapping="RSA-2048",
        key_storage="HSM",
        authentication="RSA-2048",
    )
    assert chain_classical.data_encryption == "AES-256-GCM"
    assert chain_classical.key_wrapping == "RSA-2048"

    # 2. Post-Quantum hybrid chain
    chain_pqc = KeyProtectionChain(
        data_encryption="AES-256-GCM",
        key_wrapping="ML-KEM-768",
        key_storage="HSM",
        authentication="ML-DSA-65",
    )
    assert chain_pqc.key_wrapping == "ML-KEM-768"
    assert chain_pqc.authentication == "ML-DSA-65"

    # 3. Cloud KMS chain
    chain_kms = KeyProtectionChain(
        data_encryption="AES-256-CBC",
        key_wrapping="RSA-4096",
        key_storage="KMS",
        authentication="ECDSA-P384",
    )
    assert chain_kms.key_storage == "KMS"


# ============================================================================
# 3. SYNTHETIC BANKING PROFILES CATALOG TESTS
# ============================================================================

def test_synthetic_profiles_catalog_contents():
    """Verifies that all 5 required representative banking profiles exist with complete metadata."""
    profiles = get_synthetic_banking_profiles()
    assert len(profiles) == 5

    profile_ids = [p.id for p in profiles]
    expected_ids = [
        "BANK-PROF-PAYMENT-GATEWAY",
        "BANK-PROF-CORE-BANKING",
        "BANK-PROF-KYC-DB",
        "BANK-PROF-NET-BANKING",
        "BANK-PROF-ATM-NETWORK",
    ]
    for exp_id in expected_ids:
        assert exp_id in profile_ids, f"Missing profile {exp_id}"

    # Check disclaimer
    assert "synthetic" in SYNTHETIC_DISCLAIMER.lower()
    assert "not represent the actual architecture" in SYNTHETIC_DISCLAIMER.lower()


def test_synthetic_profiles_structural_completeness():
    """Verifies each profile has valid architecture layers, crypto config, evidence items, and evidence gaps."""
    for profile in SYNTHETIC_BANKING_PROFILES:
        assert profile.id
        assert profile.name
        assert profile.asset_type in BankingAssetType
        assert profile.system_type in BankingAssetType
        assert profile.criticality in AssetCriticality
        assert profile.data_sensitivity in DataSensitivity
        assert profile.exposure in AssetExposure
        assert profile.data_lifetime in DataLifetime
        assert profile.trust_zone in TrustZone

        # Must have cryptography configuration
        assert profile.cryptography is not None
        assert profile.cryptography.key_chain is not None

        # Must have at least 3 evidence items across layers
        assert len(profile.evidence_items) >= 3
        # Must have at least 1 evidence gap
        assert len(profile.evidence_gaps) >= 1
        # Layers dictionary must be populated
        assert len(profile.layers) > 0


def test_get_synthetic_profile_by_id():
    """Verifies lookup of synthetic profiles by ID."""
    prof = get_synthetic_profile_by_id("BANK-PROF-PAYMENT-GATEWAY")
    assert prof is not None
    assert prof.id == "BANK-PROF-PAYMENT-GATEWAY"
    assert prof.name == "Modern Payment Gateway"
    assert prof.criticality == AssetCriticality.CRITICAL

    prof_atm = get_synthetic_profile_by_id("BANK-PROF-ATM-NETWORK")
    assert prof_atm is not None
    assert prof_atm.system_type == BankingAssetType.ATM_NETWORK

    non_existent = get_synthetic_profile_by_id("NON-EXISTENT-ID")
    assert non_existent is None


# ============================================================================
# 4. API ENDPOINTS TESTS: /api/banking/profiles
# ============================================================================

def test_api_get_banking_profiles():
    """Tests GET /api/banking/profiles returns all 5 synthetic profiles."""
    DEFAULT_RATE_LIMITER.reset()
    response = client.get("/api/banking/profiles")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 5

    ids = [item["id"] for item in data]
    assert "BANK-PROF-PAYMENT-GATEWAY" in ids
    assert "BANK-PROF-CORE-BANKING" in ids
    assert "BANK-PROF-KYC-DB" in ids
    assert "BANK-PROF-NET-BANKING" in ids
    assert "BANK-PROF-ATM-NETWORK" in ids

    # Check schema fields on first profile
    first = data[0]
    assert "system_type" in first
    assert "criticality" in first
    assert "exposure" in first
    assert "data_sensitivity" in first
    assert "cryptography" in first
    assert "evidence_items" in first
    assert "evidence_gaps" in first


def test_api_get_banking_profile_by_id():
    """Tests GET /api/banking/profiles/{id} for both valid and invalid IDs."""
    DEFAULT_RATE_LIMITER.reset()
    response = client.get("/api/banking/profiles/BANK-PROF-PAYMENT-GATEWAY")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == "BANK-PROF-PAYMENT-GATEWAY"
    assert data["name"] == "Modern Payment Gateway"
    assert data["criticality"] == "CRITICAL"
    assert len(data["evidence_items"]) > 0
    assert len(data["evidence_gaps"]) > 0

    # Test 404 for non-existent profile
    DEFAULT_RATE_LIMITER.reset()
    resp_404 = client.get("/api/banking/profiles/DOES_NOT_EXIST_123")
    assert resp_404.status_code == 404
    assert "not found" in resp_404.json()["detail"].lower()


# ============================================================================
# 5. SCAN INTEGRATION WITH ASSET PROFILE (TELEMETRY PRESERVATION)
# ============================================================================

_MOCK_SCAN_RESULT = {
    "target": {
        "domain": "example.bank.com",
        "port": 443,
        "resolved_ip": "93.184.216.34",
        "ip_version": "IPv4",
        "scan_timestamp": "2026-10-30T12:00:00Z",
        "connection_time_ms": 35.0,
    },
    "certificate": {
        "subject_cn": "example.bank.com",
        "subject_alt_names": ["example.bank.com"],
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
        "negotiated_cipher": "TLS_AES_128_GCM_SHA256",
        "cipher_bits": 128,
        "session_reused": False,
    }
}


def test_assess_domain_with_asset_id_preserves_external_scan_facts():
    """
    CRITICAL TEST:
    Associating a live scan with a BankingSystemProfile must:
    1. Attach the asset profile context (criticality, sensitivity, system_type, layers).
    2. NOT overwrite the externally observed TLS telemetry with synthetic profile declarations.
    """
    with patch("app.services.assessment_service.TlsScanner.scan", return_value=_MOCK_SCAN_RESULT):
        # Assess domain associating with modern payment gateway profile
        result = assess_domain("example.bank.com", asset_id="BANK-PROF-PAYMENT-GATEWAY")

        assert result.banking_asset is not None
        assert result.banking_asset.id == "BANK-PROF-PAYMENT-GATEWAY"
        assert result.banking_asset.name == "Modern Payment Gateway"
        assert result.banking_asset.criticality == AssetCriticality.CRITICAL

        # Crucially, external scan facts remain what was observed (RSA-2048, TLS_AES_128_GCM_SHA256),
        # NOT what the synthetic profile declared (e.g. ECDSA-P256, X25519MLKEM768).
        assert result.tls.negotiated_cipher == "TLS_AES_128_GCM_SHA256"
        assert result.certificate.public_key_algorithm == "RSA"
        assert result.certificate.key_size_bits == 2048

        # The asset profile layers and evidence gaps should be present
        assert len(result.banking_asset.evidence_gaps) > 0
        assert len(result.banking_asset.layers) > 0


def test_assess_domain_with_unknown_asset_id_falls_back_gracefully():
    """Verifies that an unknown asset_id gracefully falls back to default domain inference."""
    with patch("app.services.assessment_service.TlsScanner.scan", return_value=_MOCK_SCAN_RESULT):
        result = assess_domain("example.bank.com", asset_id="UNKNOWN-ID-XYZ")

        assert result.banking_asset is not None
        # Falls back to default inference without failing
        assert "example.bank.com" in result.banking_asset.name

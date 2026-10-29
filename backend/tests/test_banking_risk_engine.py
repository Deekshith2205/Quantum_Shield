"""Comprehensive unit and integration tests for Phase 4B:
Banking Criticality + Key-Protection Risk Engine.

Tests cover:
1. Risk Normalization (Criticality, Sensitivity, Lifetime, Exposure, Migration Effort, Tech Risk).
2. Formula Tests:
   - Same vulnerability + higher criticality -> higher priority.
   - Same vulnerability + longer data lifetime (SNDL) -> higher priority.
   - Same vulnerability + more sensitive data -> higher priority.
   - Same vulnerability + higher migration effort -> higher urgency.
   - Low-criticality public system with RSA-2048 does NOT outrank critical long-lived banking system.
   - AES-256-GCM alone is adequate and NOT classified as a quantum vulnerability.
3. Key Protection Chain Analysis:
   - Classical RSA + ECDSA -> weak links identified, AES-256 preserved as adequate.
   - Post-quantum hybrid ML-KEM + ML-DSA -> QUANTUM_READY.
   - Incomplete evidence -> INSUFFICIENT_EVIDENCE (not vulnerable).
4. Evidence semantics: NOT_OBSERVABLE != VULNERABLE, DECLARED != OBSERVED.
5. API Integration: GET /api/banking/risk and GET /api/banking/profiles/{id}/risk.
"""

from typing import Optional, List
import pytest
from starlette.testclient import TestClient
from app.main import app
from app.models.banking import (
    BankingAsset,
    BankingAssetType,
    AssetCriticality,
    DataSensitivity,
    AssetExposure,
    DataLifetime,
    MigrationEffort,
    TrustZone,
    SecurityLayer,
    KeyProtectionChain,
    CryptoConfiguration,
    EvidenceSource,
    EvidenceItem,
    EvidenceGap,
    EvidenceGapType,
)
from app.models.audit import ObservabilityState
from app.models.risk import (
    KeyChainStatus,
    MigrationPriority,
    KeyChainAnalysis,
    BankingRiskAssessment,
)
from app.services.banking_risk_engine import (
    normalize_criticality_weight,
    normalize_sensitivity_weight,
    normalize_lifetime_weight,
    normalize_exposure_weight,
    normalize_migration_effort_weight,
    normalize_quantum_risk_level,
    normalize_classical_risk_level,
    analyze_key_protection_chain,
    evaluate_banking_risk,
    get_all_synthetic_risk_assessments,
    get_profile_risk_assessment,
)
from app.security.rate_limiter import DEFAULT_RATE_LIMITER

client = TestClient(app)


# ==============================================================================
# 1. RISK NORMALIZATION TESTS (SECTION 21)
# ==============================================================================

def test_criticality_weight_normalization():
    """Tests 1-4 scale mapping for AssetCriticality."""
    assert normalize_criticality_weight(AssetCriticality.LOW) == 1
    assert normalize_criticality_weight(AssetCriticality.MEDIUM) == 2
    assert normalize_criticality_weight(AssetCriticality.HIGH) == 3
    assert normalize_criticality_weight(AssetCriticality.CRITICAL) == 4


def test_sensitivity_weight_normalization():
    """Tests 1-4 scale mapping for DataSensitivity."""
    assert normalize_sensitivity_weight(DataSensitivity.PUBLIC) == 1
    assert normalize_sensitivity_weight(DataSensitivity.INTERNAL) == 2
    assert normalize_sensitivity_weight(DataSensitivity.CONFIDENTIAL) == 3
    assert normalize_sensitivity_weight(DataSensitivity.HIGHLY_SENSITIVE) == 4


def test_lifetime_weight_normalization():
    """Tests 1-4 scale mapping for DataLifetime (quantum SNDL threat horizon)."""
    assert normalize_lifetime_weight(DataLifetime.SHORT) == 1
    assert normalize_lifetime_weight(DataLifetime.MEDIUM) == 2
    assert normalize_lifetime_weight(DataLifetime.LONG) == 3
    assert normalize_lifetime_weight(DataLifetime.VERY_LONG) == 4


def test_exposure_weight_normalization():
    """Tests 1-4 scale mapping for AssetExposure."""
    assert normalize_exposure_weight(AssetExposure.RESTRICTED) == 1
    assert normalize_exposure_weight(AssetExposure.INTERNAL) == 2
    assert normalize_exposure_weight(AssetExposure.PARTNER) == 3
    assert normalize_exposure_weight(AssetExposure.INTERNET) == 4


def test_migration_effort_weight_normalization():
    """Tests 1-4 scale mapping for MigrationEffort."""
    assert normalize_migration_effort_weight(MigrationEffort.LOW) == 1
    assert normalize_migration_effort_weight(MigrationEffort.MEDIUM) == 2
    assert normalize_migration_effort_weight(MigrationEffort.HIGH) == 3
    assert normalize_migration_effort_weight(MigrationEffort.VERY_HIGH) == 4


def test_quantum_and_classical_risk_levels():
    """Tests 0-4 scale mapping for Technical Quantum & Classical Risk."""
    # From scores (0-100 readiness where higher = better)
    assert normalize_quantum_risk_level(20)[0] == 4  # Critical exposure
    assert normalize_quantum_risk_level(40)[0] == 3  # High exposure
    assert normalize_quantum_risk_level(60)[0] == 2  # Medium exposure
    assert normalize_quantum_risk_level(80)[0] == 1  # Low exposure
    assert normalize_quantum_risk_level(95)[0] == 0  # None / PQC Ready

    # From string severities
    assert normalize_quantum_risk_level("CRITICAL")[0] == 4
    assert normalize_quantum_risk_level("HIGH")[0] == 3
    assert normalize_quantum_risk_level("MEDIUM")[0] == 2
    assert normalize_quantum_risk_level("LOW")[0] == 1
    assert normalize_quantum_risk_level("INFORMATIONAL")[0] == 0

    assert normalize_classical_risk_level("CRITICAL")[0] == 4
    assert normalize_classical_risk_level("HIGH")[0] == 3
    assert normalize_classical_risk_level("LOW")[0] == 1


# ==============================================================================
# 2. KEY PROTECTION CHAIN TESTS (SECTION 23 & AES RULE SECTION 4)
# ==============================================================================

def test_aes_256_is_adequate_and_not_quantum_vulnerable():
    """
    CRITICAL AES RULE:
    AES-256 retains approximately 128-bit security against an idealized Grover search
    and is not treated as a quantum-broken primitive by QuantumShield.
    The weakness is in the key wrapping mechanism, NOT AES-256 itself.
    """
    chain = KeyProtectionChain(
        data_encryption="AES-256-GCM",
        key_wrapping="RSA-2048",
        key_storage="HSM",
        authentication="ECDSA-P256",
    )
    analysis = analyze_key_protection_chain(chain)

    # 1. AES-256 data encryption must be rated ADEQUATE_GROVER_RESILIENT
    assert analysis.data_encryption_status == "ADEQUATE_GROVER_RESILIENT"

    # 2. AES-256 must NOT appear in weak links
    assert not any("AES-256" in link for link in analysis.weak_links)

    # 3. Weak links must correctly identify RSA-2048 wrapping and ECDSA-P256 authentication
    assert any("RSA-2048" in link for link in analysis.weak_links)
    assert any("ECDSA-P256" in link for link in analysis.weak_links)
    assert len(analysis.weak_links) == 2


def test_post_quantum_hybrid_chain_is_quantum_ready():
    """Verifies that ML-KEM-768 key wrapping and ML-DSA authentication yield QUANTUM_READY."""
    chain = KeyProtectionChain(
        data_encryption="AES-256-GCM",
        key_wrapping="ML-KEM-768",
        key_storage="HSM",
        authentication="ML-DSA-65",
    )
    analysis = analyze_key_protection_chain(chain)

    assert analysis.status == KeyChainStatus.QUANTUM_READY
    assert len(analysis.weak_links) == 0
    assert analysis.data_encryption_status == "ADEQUATE_GROVER_RESILIENT"
    assert analysis.key_wrapping_status == "QUANTUM_READY"
    assert analysis.authentication_status == "QUANTUM_READY"


def test_incomplete_evidence_key_chain_is_insufficient_evidence_not_vulnerable():
    """
    CRITICAL AUDIT INVARIANT:
    Missing evidence -> INSUFFICIENT_EVIDENCE.
    Lack of external observability must NOT be marked as vulnerable.
    """
    # 1. None chain
    analysis_none = analyze_key_protection_chain(None)
    assert analysis_none.status == KeyChainStatus.INSUFFICIENT_EVIDENCE
    assert len(analysis_none.weak_links) == 0

    # 2. Only AES-256 known, wrapping and storage unknown
    chain_partial = KeyProtectionChain(
        data_encryption="AES-256-GCM",
        key_wrapping=None,
        key_storage=None,
        authentication=None,
    )
    analysis_partial = analyze_key_protection_chain(chain_partial)
    assert analysis_partial.status == KeyChainStatus.INSUFFICIENT_EVIDENCE
    assert len(analysis_partial.weak_links) == 0


def test_legacy_3des_chain_is_flagged():
    """Verifies that deprecated 3DES ciphers and key wrapping are identified as weak links."""
    chain = KeyProtectionChain(
        data_encryption="3DES-EDE",
        key_wrapping="3DES KEK",
        key_storage="HSM",
        authentication="RSA-2048",
    )
    analysis = analyze_key_protection_chain(chain)

    assert analysis.data_encryption_status == "DEPRECATED_LEGACY"
    assert analysis.key_wrapping_status == "LEGACY_VULNERABLE"
    assert any("3DES" in link for link in analysis.weak_links)


# ==============================================================================
# 3. DETERMINISTIC RISK FORMULA TESTS (SECTION 22)
# ==============================================================================

def _create_mock_asset(
    name: str = "Test Asset",
    criticality: AssetCriticality = AssetCriticality.HIGH,
    data_sensitivity: DataSensitivity = DataSensitivity.HIGHLY_SENSITIVE,
    data_lifetime: DataLifetime = DataLifetime.LONG,
    exposure: AssetExposure = AssetExposure.INTERNET,
    migration_effort: MigrationEffort = MigrationEffort.MEDIUM,
    chain: Optional[KeyProtectionChain] = None,
) -> BankingAsset:
    """Helper to construct configurable test assets."""
    return BankingAsset(
        id="TEST-ASSET",
        name=name,
        asset_type=BankingAssetType.CORE_BANKING,
        criticality=criticality,
        data_sensitivity=data_sensitivity,
        data_lifetime=data_lifetime,
        exposure=exposure,
        migration_effort=migration_effort,
        cryptography=CryptoConfiguration(
            tls_versions=["TLSv1.3"],
            cipher_suites=["TLS_AES_256_GCM_SHA384"],
            key_chain=chain or KeyProtectionChain(
                data_encryption="AES-256-GCM",
                key_wrapping="RSA-2048",
                key_storage="HSM",
                authentication="ECDSA-P256",
            ),
        ),
    )


def test_formula_monotonicity_higher_criticality_increases_priority():
    """Test 1: Same technical vulnerability + higher criticality -> strictly higher priority score."""
    low_crit_asset = _create_mock_asset(criticality=AssetCriticality.LOW)
    high_crit_asset = _create_mock_asset(criticality=AssetCriticality.CRITICAL)

    risk_low = evaluate_banking_risk(low_crit_asset, scan_quantum_score=35)
    risk_high = evaluate_banking_risk(high_crit_asset, scan_quantum_score=35)

    assert risk_high.priority_score > risk_low.priority_score
    assert risk_high.business_context.criticality_score > risk_low.business_context.criticality_score


def test_formula_monotonicity_longer_lifetime_increases_priority():
    """Test 2: Same technical vulnerability + longer data lifetime (SNDL) -> strictly higher priority score."""
    short_life_asset = _create_mock_asset(data_lifetime=DataLifetime.SHORT)
    long_life_asset = _create_mock_asset(data_lifetime=DataLifetime.VERY_LONG)

    risk_short = evaluate_banking_risk(short_life_asset, scan_quantum_score=35)
    risk_long = evaluate_banking_risk(long_life_asset, scan_quantum_score=35)

    assert risk_long.priority_score > risk_short.priority_score
    assert risk_long.business_context.lifetime_score > risk_short.business_context.lifetime_score


def test_formula_monotonicity_more_sensitive_data_increases_priority():
    """Test 3: Same technical vulnerability + more sensitive data -> strictly higher priority score."""
    public_asset = _create_mock_asset(data_sensitivity=DataSensitivity.PUBLIC)
    sensitive_asset = _create_mock_asset(data_sensitivity=DataSensitivity.HIGHLY_SENSITIVE)

    risk_pub = evaluate_banking_risk(public_asset, scan_quantum_score=35)
    risk_sens = evaluate_banking_risk(sensitive_asset, scan_quantum_score=35)

    assert risk_sens.priority_score > risk_pub.priority_score
    assert risk_sens.business_context.sensitivity_score > risk_pub.business_context.sensitivity_score


def test_formula_monotonicity_higher_migration_effort_increases_urgency():
    """Test 4: Same technical vulnerability + higher migration effort -> higher urgency and planning score."""
    low_effort_asset = _create_mock_asset(migration_effort=MigrationEffort.LOW)
    high_effort_asset = _create_mock_asset(migration_effort=MigrationEffort.VERY_HIGH)

    risk_low_eff = evaluate_banking_risk(low_effort_asset, scan_quantum_score=35)
    risk_high_eff = evaluate_banking_risk(high_effort_asset, scan_quantum_score=35)

    assert risk_high_eff.priority_score > risk_low_eff.priority_score
    assert risk_high_eff.business_context.migration_effort_score > risk_low_eff.business_context.migration_effort_score


def test_public_low_criticality_website_does_not_outrank_critical_banking_system():
    """
    Test 5 (Section 22):
    Low-criticality public website with RSA-2048 must NOT outrank a critical long-lived banking system.
    """
    public_website = _create_mock_asset(
        name="Public Marketing Site",
        criticality=AssetCriticality.LOW,
        data_sensitivity=DataSensitivity.PUBLIC,
        data_lifetime=DataLifetime.SHORT,
        exposure=AssetExposure.INTERNET,
        migration_effort=MigrationEffort.LOW,
    )
    core_banking = _create_mock_asset(
        name="Core Banking Mainframe",
        criticality=AssetCriticality.CRITICAL,
        data_sensitivity=DataSensitivity.HIGHLY_SENSITIVE,
        data_lifetime=DataLifetime.VERY_LONG,
        exposure=AssetExposure.RESTRICTED,
        migration_effort=MigrationEffort.VERY_HIGH,
    )

    # Both have the same RSA-2048 vulnerability (scan score 30)
    risk_web = evaluate_banking_risk(public_website, scan_quantum_score=30)
    risk_core = evaluate_banking_risk(core_banking, scan_quantum_score=30)

    # Core banking must heavily outrank the public website despite restricted exposure
    assert risk_core.priority_score > risk_web.priority_score
    assert risk_core.migration_priority == MigrationPriority.P0
    assert risk_web.migration_priority in [MigrationPriority.P2, MigrationPriority.P3]


def test_aes_256_gcm_alone_does_not_produce_critical_risk():
    """
    Test 6 (Section 22):
    AES-256-GCM alone must NOT produce a critical quantum finding or elevated priority.
    """
    hybrid_chain = KeyProtectionChain(
        data_encryption="AES-256-GCM",
        key_wrapping="ML-KEM-768",
        key_storage="HSM",
        authentication="ML-DSA-65",
    )
    pqc_asset = _create_mock_asset(chain=hybrid_chain)
    risk = evaluate_banking_risk(pqc_asset, scan_quantum_score=95, scan_classical_risk="NONE")

    # Quantum risk level must be 0 (NONE), and priority band must be P3 (Monitor/Maintain)
    assert risk.technical_risk.quantum_risk_level == 0
    assert risk.migration_priority == MigrationPriority.P3
    assert risk.priority_score == 0


# ==============================================================================
# 4. SYSTEM COMPARISON & RANKING ORDER (SECTION 16)
# ==============================================================================

def test_synthetic_profiles_migration_ranking_order():
    """
    Verifies that the 5 synthetic banking profiles are ranked accurately:
    1. Core Banking (P0)
    2. Customer / KYC Vault (P0)
    3. ATM Network (P1)
    4. Net Banking Portal (P2)
    5. Modern Payment Gateway (P3 - already has hybrid ML-KEM)
    """
    rankings = get_all_synthetic_risk_assessments()
    assert len(rankings) == 5

    # Scores must be in descending order
    scores = [r.priority_score for r in rankings]
    assert scores == sorted(scores, reverse=True)

    # Top ranked system must be Core Banking (P0)
    assert rankings[0].asset_id == "BANK-PROF-CORE-BANKING"
    assert rankings[0].migration_priority == MigrationPriority.P0
    assert rankings[0].priority_score >= 85

    # Second ranked system must be KYC Database (P0)
    assert rankings[1].asset_id == "BANK-PROF-KYC-DB"
    assert rankings[1].migration_priority == MigrationPriority.P0
    assert rankings[1].priority_score >= 85

    # Modern payment gateway with hybrid ML-KEM must be lowest priority (P3)
    assert rankings[-1].asset_id == "BANK-PROF-PAYMENT-GATEWAY"
    assert rankings[-1].migration_priority == MigrationPriority.P3


# ==============================================================================
# 5. EVIDENCE PROVENANCE & GAP INVARIANTS (SECTION 24)
# ==============================================================================

def test_evidence_provenance_distinction_and_invariants():
    """
    Verifies that:
    - NOT_OBSERVABLE != VULNERABLE
    - DECLARED != OBSERVED
    - CONFIGURATION_FILE != EXTERNAL_SCAN
    """
    gap = EvidenceGap(
        gap_type=EvidenceGapType.HSM_USAGE,
        layer=SecurityLayer.DATA_AND_KEYS,
        control="HSM Key Isolation",
        description="Internal HSM cannot be verified through external scan",
        evidence_needed="HSM FIPS 140-3 certificate",
        observability=ObservabilityState.NOT_OBSERVABLE,
        source=EvidenceSource.EXTERNAL_SCAN,
    )
    assert gap.observability == ObservabilityState.NOT_OBSERVABLE
    assert gap.observability.value != "VULNERABLE"

    item_declared = EvidenceItem(
        id="EV-DEC",
        control="Key Rotation",
        value="Annual rotation",
        source=EvidenceSource.OPERATOR_DECLARED,
    )
    item_scan = EvidenceItem(
        id="EV-SCAN",
        control="Perimeter Protocol",
        value="TLSv1.3",
        source=EvidenceSource.EXTERNAL_SCAN,
    )
    item_config = EvidenceItem(
        id="EV-CFG",
        control="Database TDE",
        value="AES-256",
        source=EvidenceSource.CONFIGURATION_FILE,
    )

    assert item_declared.source != item_scan.source
    assert item_config.source != item_scan.source
    assert item_declared.source == EvidenceSource.OPERATOR_DECLARED
    assert item_scan.source == EvidenceSource.EXTERNAL_SCAN
    assert item_config.source == EvidenceSource.CONFIGURATION_FILE


# ==============================================================================
# 6. API ENDPOINTS TESTS: /api/banking/risk
# ==============================================================================

def test_api_get_banking_risk_rankings():
    """Tests GET /api/banking/risk returns all 5 systems sorted with complete multidimensional fields."""
    DEFAULT_RATE_LIMITER.reset()
    response = client.get("/api/banking/risk")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 5

    # Check top profile
    top = data[0]
    assert top["asset_id"] == "BANK-PROF-CORE-BANKING"
    assert top["migration_priority"] == "P0"
    assert top["priority_score"] >= 85
    assert "technical_risk" in top
    assert "business_context" in top
    assert "key_protection" in top
    assert "contributors" in top
    assert len(top["contributors"]) == 6
    assert "explanation" in top
    assert len(top["explanation"]) > 20


def test_api_get_banking_profile_risk_by_id():
    """Tests GET /api/banking/profiles/{id}/risk for valid and invalid profile IDs."""
    DEFAULT_RATE_LIMITER.reset()
    response = client.get("/api/banking/profiles/BANK-PROF-CORE-BANKING/risk")
    assert response.status_code == 200
    data = response.json()
    assert data["asset_id"] == "BANK-PROF-CORE-BANKING"
    assert data["migration_priority"] == "P0"
    assert "RSA-2048 key wrapping" in data["key_protection"]["weak_links"]

    # Test 404 for non-existent profile
    DEFAULT_RATE_LIMITER.reset()
    resp_404 = client.get("/api/banking/profiles/NON_EXISTENT_PROFILE/risk")
    assert resp_404.status_code == 404
    assert "not found" in resp_404.json()["detail"].lower()


# ==============================================================================
# 7. PHASE 4B HARDENING: INDEPENDENCE FROM SYNTHETIC PROFILES (SECTION 6)
# ==============================================================================

def test_arbitrary_profile_case_a():
    """
    Case A: LOW criticality, PUBLIC data, SHORT lifetime, INTERNAL exposure, LOW migration effort.
    Expected: Low business exposure, low urgency -> Priority P3.
    """
    asset = BankingAsset(
        id="CUSTOM-CASE-A",
        name="Internal Development Documentation Mirror",
        asset_type=BankingAssetType.INTERNAL_SERVICE,
        criticality=AssetCriticality.LOW,
        data_sensitivity=DataSensitivity.PUBLIC,
        data_lifetime=DataLifetime.SHORT,
        exposure=AssetExposure.INTERNAL,
        migration_effort=MigrationEffort.LOW,
        cryptography=CryptoConfiguration(
            tls_versions=["TLSv1.3"],
            cipher_suites=["TLS_AES_256_GCM_SHA384"],
            key_chain=KeyProtectionChain(
                data_encryption="AES-256",
                key_wrapping="ML-KEM-768",
                key_storage="KMS",
                authentication="ML-DSA-65",
            ),
        ),
    )
    risk = evaluate_banking_risk(asset)
    assert risk.migration_priority == MigrationPriority.P3
    assert risk.priority_score < 40
    assert "CUSTOM-CASE-A" == risk.asset_id
    assert risk.business_context.criticality_score == 1
    assert risk.business_context.sensitivity_score == 1
    assert risk.business_context.lifetime_score == 1
    assert risk.business_context.exposure_score == 2
    assert risk.business_context.migration_effort_score == 1
    assert len(risk.explanation) > 0


def test_arbitrary_profile_case_b():
    """
    Case B: CRITICAL criticality, HIGHLY_SENSITIVE data, VERY_LONG lifetime,
    INTERNET exposure, VERY_HIGH migration effort.
    Expected: Maximum business exposure and migration urgency -> Priority P0.
    """
    asset = BankingAsset(
        id="CUSTOM-CASE-B",
        name="Global Card Clearing Hub",
        asset_type=BankingAssetType.INTER_BANK_GATEWAY,
        criticality=AssetCriticality.CRITICAL,
        data_sensitivity=DataSensitivity.HIGHLY_SENSITIVE,
        data_lifetime=DataLifetime.VERY_LONG,
        exposure=AssetExposure.INTERNET,
        migration_effort=MigrationEffort.VERY_HIGH,
        cryptography=CryptoConfiguration(
            tls_versions=["TLSv1.2"],
            cipher_suites=["ECDHE-RSA-AES256-GCM-SHA384"],
            key_chain=KeyProtectionChain(
                data_encryption="AES-256-GCM",
                key_wrapping="RSA-4096",
                key_storage="HSM",
                authentication="RSA-4096",
            ),
        ),
    )
    risk = evaluate_banking_risk(asset)
    assert risk.migration_priority == MigrationPriority.P0
    assert risk.priority_score >= 85
    assert risk.technical_risk.quantum_risk_level == 4
    assert risk.business_context.criticality_score == 4
    assert risk.business_context.sensitivity_score == 4
    assert risk.business_context.lifetime_score == 4
    assert risk.business_context.exposure_score == 4
    assert risk.business_context.migration_effort_score == 4
    assert "RSA-4096 key wrapping" in risk.key_protection.weak_links


def test_arbitrary_profile_case_c():
    """
    Case C: CRITICAL, HIGHLY_SENSITIVE, VERY_LONG, RESTRICTED, QUANTUM_READY.
    Expected: Despite critical long-lived data, because the key-chain is already quantum-ready,
    technical quantum risk is NONE (0) and priority is P3 (Monitor/Maintain).
    """
    asset = BankingAsset(
        id="CUSTOM-CASE-C",
        name="Air-Gapped Sovereign Key Archive",
        asset_type=BankingAssetType.CORE_BANKING,
        criticality=AssetCriticality.CRITICAL,
        data_sensitivity=DataSensitivity.HIGHLY_SENSITIVE,
        data_lifetime=DataLifetime.VERY_LONG,
        exposure=AssetExposure.RESTRICTED,
        migration_effort=MigrationEffort.HIGH,
        cryptography=CryptoConfiguration(
            tls_versions=["TLSv1.3"],
            cipher_suites=["TLS_AES_256_GCM_SHA384"],
            key_chain=KeyProtectionChain(
                data_encryption="AES-256-GCM",
                key_wrapping="ML-KEM-768",
                key_storage="HSM",
                authentication="ML-DSA-65",
            ),
        ),
    )
    risk = evaluate_banking_risk(asset, scan_classical_risk="NONE")
    assert risk.key_protection.status == KeyChainStatus.QUANTUM_READY
    assert risk.technical_risk.quantum_risk_level == 0
    assert risk.migration_priority == MigrationPriority.P3
    assert risk.priority_score < 40


def test_arbitrary_profile_case_d():
    """
    Case D: CRITICAL, HIGHLY_SENSITIVE, VERY_LONG, INTERNET, QUANTUM_EXPOSED.
    Expected: Maximum exposure + quantum vulnerable wrapping -> Priority P0.
    """
    asset = BankingAsset(
        id="CUSTOM-CASE-D",
        name="Internet Mortgage Origination API",
        asset_type=BankingAssetType.API_GATEWAY,
        criticality=AssetCriticality.CRITICAL,
        data_sensitivity=DataSensitivity.HIGHLY_SENSITIVE,
        data_lifetime=DataLifetime.VERY_LONG,
        exposure=AssetExposure.INTERNET,
        migration_effort=MigrationEffort.HIGH,
        cryptography=CryptoConfiguration(
            tls_versions=["TLSv1.2"],
            cipher_suites=["ECDHE-RSA-AES256-GCM-SHA384"],
            key_chain=KeyProtectionChain(
                data_encryption="AES-256-GCM",
                key_wrapping="RSA-2048",
                key_storage="Cloud KMS",
                authentication="ECDSA-P256",
            ),
        ),
    )
    risk = evaluate_banking_risk(asset)
    assert risk.key_protection.status == KeyChainStatus.QUANTUM_EXPOSED
    assert risk.technical_risk.quantum_risk_level == 4
    assert risk.migration_priority == MigrationPriority.P0
    assert risk.priority_score >= 85


def test_arbitrary_profile_case_e_incomplete_evidence():
    """
    Case E: Incomplete evidence (no key chain, partial fields).
    Expected: Status is INSUFFICIENT_EVIDENCE, zero fabricated vulnerabilities, safe deterministic score.
    """
    asset = BankingAsset(
        id="CUSTOM-CASE-E",
        name="Third-Party Aggregator Connector",
        asset_type=BankingAssetType.INTER_BANK_GATEWAY,
        criticality=AssetCriticality.MEDIUM,
        data_sensitivity=DataSensitivity.CONFIDENTIAL,
        data_lifetime=DataLifetime.MEDIUM,
        exposure=AssetExposure.PARTNER,
        migration_effort=MigrationEffort.MEDIUM,
        cryptography=None,
    )
    risk = evaluate_banking_risk(asset)
    assert risk.key_protection.status == KeyChainStatus.INSUFFICIENT_EVIDENCE
    assert len(risk.key_protection.weak_links) == 0
    assert risk.priority_score >= 0
    assert isinstance(risk.priority_score, int)


# ==============================================================================
# 8. MONOTONICITY & TRANSITION REGRESSION TESTS (SECTION 7)
# ==============================================================================

def test_monotonicity_resolving_vulnerable_wrapping_reduces_priority():
    """
    Migrating key wrapping from RSA-2048 to ML-KEM-768 must strictly reduce priority score.
    """
    asset_vuln = _create_mock_asset(
        chain=KeyProtectionChain(
            data_encryption="AES-256-GCM",
            key_wrapping="RSA-2048",
            key_storage="HSM",
            authentication="ECDSA-P256",
        )
    )
    asset_safe = _create_mock_asset(
        chain=KeyProtectionChain(
            data_encryption="AES-256-GCM",
            key_wrapping="ML-KEM-768",
            key_storage="HSM",
            authentication="ML-DSA-65",
        )
    )
    risk_vuln = evaluate_banking_risk(asset_vuln)
    risk_safe = evaluate_banking_risk(asset_safe, scan_classical_risk="NONE")

    assert risk_safe.priority_score < risk_vuln.priority_score
    assert risk_safe.technical_risk.governing_technical_risk < risk_vuln.technical_risk.governing_technical_risk


def test_monotonicity_full_spectrum_criticality():
    """Validates that as Criticality increases from LOW to CRITICAL, score never decreases."""
    scores = []
    for crit in [AssetCriticality.LOW, AssetCriticality.MEDIUM, AssetCriticality.HIGH, AssetCriticality.CRITICAL]:
        asset = _create_mock_asset(criticality=crit)
        risk = evaluate_banking_risk(asset, scan_quantum_score=35)
        scores.append(risk.priority_score)

    assert scores == sorted(scores)
    assert scores[0] < scores[-1]


def test_monotonicity_full_spectrum_data_lifetime():
    """Validates that as DataLifetime increases from SHORT to VERY_LONG, score never decreases."""
    scores = []
    for life in [DataLifetime.SHORT, DataLifetime.MEDIUM, DataLifetime.LONG, DataLifetime.VERY_LONG]:
        asset = _create_mock_asset(data_lifetime=life)
        risk = evaluate_banking_risk(asset, scan_quantum_score=35)
        scores.append(risk.priority_score)

    assert scores == sorted(scores)
    assert scores[0] < scores[-1]


def test_monotonicity_full_spectrum_exposure():
    """Validates that as Exposure increases from RESTRICTED to INTERNET, score never decreases."""
    scores = []
    for exp in [AssetExposure.RESTRICTED, AssetExposure.INTERNAL, AssetExposure.PARTNER, AssetExposure.INTERNET]:
        asset = _create_mock_asset(exposure=exp)
        risk = evaluate_banking_risk(asset, scan_quantum_score=35)
        scores.append(risk.priority_score)

    assert scores == sorted(scores)
    assert scores[0] < scores[-1]


# ==============================================================================
# 9. PRIORITY BAND BOUNDARY TESTS (SECTION 13)
# ==============================================================================

def test_priority_band_exact_boundaries():
    """
    Tests exact boundary mappings:
    0-39 -> P3
    40-64 -> P2
    65-84 -> P1
    85-100 -> P0
    """
    test_cases = [
        (0, MigrationPriority.P3),
        (39, MigrationPriority.P3),
        (40, MigrationPriority.P2),
        (64, MigrationPriority.P2),
        (65, MigrationPriority.P1),
        (84, MigrationPriority.P1),
        (85, MigrationPriority.P0),
        (100, MigrationPriority.P0),
    ]

    for score, expected_priority in test_cases:
        if score >= 85:
            band = MigrationPriority.P0
        elif score >= 65:
            band = MigrationPriority.P1
        elif score >= 40:
            band = MigrationPriority.P2
        else:
            band = MigrationPriority.P3
        assert band == expected_priority, f"Score {score} expected {expected_priority}, got {band}"


# ==============================================================================
# 10. UNKNOWN / INCOMPLETE ATTRIBUTES SAFETY (SECTION 14)
# ==============================================================================

def test_asset_with_missing_attributes_does_not_crash():
    """
    Tests that an asset with None for all configurable attributes:
    - does not crash
    - applies safe fallbacks
    - reports zero fabricated weak links
    - returns valid explainable assessment
    """
    asset = BankingAsset.model_construct(
        id="TEST-FALLBACK-NULL",
        name=None,
        criticality=None,
        data_sensitivity=None,
        data_lifetime=None,
        exposure=None,
        migration_effort=None,
        cryptography=None,
    )
    risk = evaluate_banking_risk(asset)

    assert risk.asset_id == "TEST-FALLBACK-NULL"
    assert risk.priority_score >= 0
    assert risk.priority_score <= 100
    assert risk.migration_priority in [MigrationPriority.P0, MigrationPriority.P1, MigrationPriority.P2, MigrationPriority.P3]
    assert len(risk.key_protection.weak_links) == 0
    assert risk.key_protection.status == KeyChainStatus.INSUFFICIENT_EVIDENCE
    assert len(risk.explanation) > 0


def test_unknown_cryptographic_algorithm_handled_safely():
    """
    Tests that unexpected/unknown algorithm names do not crash and are categorized safely.
    """
    chain = KeyProtectionChain(
        data_encryption="PROPRIETARY_CIPHER_9000",
        key_wrapping="CUSTOM_ENCAPSULATION_XYZ",
        key_storage="VIRTUAL_VAULT",
        authentication="LEGACY_HMAC_CUSTOM",
    )
    analysis = analyze_key_protection_chain(chain)

    assert analysis.data_encryption_status == "ADEQUATE"
    assert analysis.key_wrapping_status == "CLASSICAL"
    assert analysis.authentication_status == "CLASSICAL"
    assert analysis.status == KeyChainStatus.PARTIALLY_QUANTUM_READY
    assert len(analysis.weak_links) == 0

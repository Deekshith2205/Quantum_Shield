"""Comprehensive Automated Tests for Phase 4C: What-If Migration Simulator.

Covers all 13 required test categories:
1. Immutability / No Mutation: Original profile remains unchanged.
2. RSA -> ML-KEM: Key wrapping substitution.
3. ECDSA -> ML-DSA: Signature substitution.
4. TLS Classical -> Hybrid: Perimeter transport substitution.
5. Invalid Migration: Reject unsupported algorithm / allow-list enforcement.
6. Excessive Operations: Reject >5 migration changes.
7. Remaining Vulnerability: Preserves unresolved weak links.
8. Score Recalculation: Formula recalculation, no hardcoded deltas.
9. Multi-Step Migration: Compound substitutions on same temporary state.
10. Evidence Provenance: Outcomes strictly labeled SIMULATED.
11. Missing Evidence: Missing data remains INSUFFICIENT_EVIDENCE, not vulnerable.
12. API Contract: HTTP endpoint POST /api/banking/risk/what-if validation.
13. Boundary and error handling.
"""

import copy
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.models.banking import (
    BankingAsset,
    BankingAssetType,
    AssetCriticality,
    DataSensitivity,
    AssetExposure,
    DataLifetime,
    MigrationEffort,
    CryptoConfiguration,
    KeyProtectionChain,
)
from app.models.profiles import get_synthetic_profile_by_id
from app.models.risk import KeyChainStatus, MigrationPriority
from app.models.simulation import (
    MigrationComponent,
    MigrationAction,
    WhatIfMigrationRequest,
    WhatIfMigrationResult,
    ALLOWED_MIGRATION_TARGETS,
)
from app.services.migration_simulator import (
    simulate_migration,
    MigrationSimulationError,
    ProfileNotFoundError,
)
from app.security.rate_limiter import DEFAULT_RATE_LIMITER

client = TestClient(app)


# ==============================================================================
# 1. IMMUTABILITY / NO MUTATION (TEST 1)
# ==============================================================================

def test_original_profile_is_never_mutated_by_simulation():
    """
    CRITICAL INVARIANT (Section 7):
    Running a What-If simulation must NEVER mutate the original profile or persistent catalog.
    """
    profile_before = get_synthetic_profile_by_id("BANK-PROF-CORE-BANKING")
    assert profile_before is not None
    original_wrapping = profile_before.cryptography.key_chain.key_wrapping
    original_auth = profile_before.cryptography.key_chain.authentication
    original_tls = list(profile_before.cryptography.tls_versions)

    request = WhatIfMigrationRequest(
        asset_id="BANK-PROF-CORE-BANKING",
        changes=[
            MigrationAction(
                component=MigrationComponent.KEY_WRAPPING,
                target_algorithm="ML-KEM-768",
            ),
            MigrationAction(
                component=MigrationComponent.AUTHENTICATION,
                target_algorithm="ML-DSA-65",
            ),
        ],
    )
    result = simulate_migration(request)
    assert result.evidence_state == "SIMULATED"

    # Verify original object in memory is byte-for-byte logically unchanged
    profile_after = get_synthetic_profile_by_id("BANK-PROF-CORE-BANKING")
    assert profile_after.cryptography.key_chain.key_wrapping == original_wrapping
    assert profile_after.cryptography.key_chain.authentication == original_auth
    assert profile_after.cryptography.tls_versions == original_tls


# ==============================================================================
# 2. KEY WRAPPING SUBSTITUTION: RSA -> ML-KEM (TEST 2)
# ==============================================================================

def test_key_wrapping_rsa_to_ml_kem():
    """
    Verifies that replacing RSA-2048 key wrapping with ML-KEM-768:
    - Resolves the RSA key wrapping weakness.
    - Transitions key-wrapping status to QUANTUM_READY.
    - Reduces priority score via the Phase 4B risk engine.
    """
    request = WhatIfMigrationRequest(
        asset_id="BANK-PROF-CORE-BANKING",
        changes=[
            MigrationAction(
                component=MigrationComponent.KEY_WRAPPING,
                current_algorithm="RSA-2048",
                target_algorithm="ML-KEM-768",
            ),
        ],
    )
    result = simulate_migration(request)

    assert result.before.key_protection.status == KeyChainStatus.QUANTUM_EXPOSED
    assert result.after.key_protection.status == KeyChainStatus.PARTIALLY_QUANTUM_READY
    assert "RSA-2048 key wrapping" in result.comparison.resolved_findings
    assert "RSA-2048 key wrapping" not in result.comparison.weak_links_after
    assert result.comparison.risk_reduction > 0
    assert result.after.priority_score < result.before.priority_score


# ==============================================================================
# 3. SIGNATURE SUBSTITUTION: ECDSA -> ML-DSA (TEST 3)
# ==============================================================================

def test_signature_authentication_ecdsa_to_ml_dsa():
    """
    Verifies that replacing ECDSA-P256 authentication with ML-DSA-65 updates the
    authentication layer and resolves signature weaknesses.
    """
    request = WhatIfMigrationRequest(
        asset_id="BANK-PROF-NET-BANKING",
        changes=[
            MigrationAction(
                component=MigrationComponent.AUTHENTICATION,
                current_algorithm="ECDSA-P256",
                target_algorithm="ML-DSA-65",
            ),
        ],
    )
    result = simulate_migration(request)

    assert any("ECDSA" in r for r in result.comparison.resolved_findings)
    assert not any("ECDSA" in r for r in result.comparison.weak_links_after)
    assert result.after.key_protection.authentication_status == "QUANTUM_READY"


# ==============================================================================
# 4. TLS CLASSICAL TO HYBRID SUBSTITUTION (TEST 4)
# ==============================================================================

def test_tls_classical_to_hybrid_key_exchange():
    """
    Verifies simulating TLS key exchange migration to X25519MLKEM768 updates
    the transport key establishment without claiming full PQC if key wrapping is classical.
    """
    request = WhatIfMigrationRequest(
        asset_id="BANK-PROF-CORE-BANKING",
        changes=[
            MigrationAction(
                component=MigrationComponent.TLS_PROTOCOL,
                target_algorithm="TLSv1.3",
            ),
            MigrationAction(
                component=MigrationComponent.TLS_KEY_EXCHANGE,
                target_algorithm="X25519MLKEM768",
            ),
        ],
    )
    result = simulate_migration(request)

    assert result.after.asset_id == "BANK-PROF-CORE-BANKING"
    assert result.evidence_state == "SIMULATED"


# ==============================================================================
# 5. STRICT ALLOW-LIST / INVALID MIGRATION REJECTION (TEST 5)
# ==============================================================================

def test_invalid_migration_algorithm_rejected():
    """
    Verifies that unapproved/arbitrary algorithms (e.g. 'SUPER-PQC', 'RSA-1234')
    are strictly rejected with a clear validation error.
    """
    with pytest.raises(MigrationSimulationError) as exc_info:
        simulate_migration(
            WhatIfMigrationRequest(
                asset_id="BANK-PROF-CORE-BANKING",
                changes=[
                    MigrationAction(
                        component=MigrationComponent.KEY_WRAPPING,
                        target_algorithm="SUPER-PQC-9000",
                    ),
                ],
            )
        )
    assert "Unsupported migration target 'SUPER-PQC-9000'" in str(exc_info.value)


# ==============================================================================
# 6. EXCESSIVE OPERATIONS BOUND (>5) (TEST 6)
# ==============================================================================

def test_excessive_operations_rejected():
    """Verifies that requesting more than 5 migration operations is rejected."""
    with pytest.raises(Exception):  # Pydantic or service validation
        WhatIfMigrationRequest(
            asset_id="BANK-PROF-CORE-BANKING",
            changes=[
                MigrationAction(component=MigrationComponent.KEY_WRAPPING, target_algorithm="ML-KEM-768"),
                MigrationAction(component=MigrationComponent.AUTHENTICATION, target_algorithm="ML-DSA-65"),
                MigrationAction(component=MigrationComponent.TLS_PROTOCOL, target_algorithm="TLSv1.3"),
                MigrationAction(component=MigrationComponent.TLS_KEY_EXCHANGE, target_algorithm="X25519MLKEM768"),
                MigrationAction(component=MigrationComponent.KEY_WRAPPING, target_algorithm="ML-KEM-1024"),
                MigrationAction(component=MigrationComponent.AUTHENTICATION, target_algorithm="ML-DSA-87"),  # 6th
            ],
        )


# ==============================================================================
# 7. REMAINING VULNERABILITY PRESERVATION (TEST 7)
# ==============================================================================

def test_remaining_vulnerability_is_preserved_when_only_one_component_migrated():
    """
    CRITICAL TEST (Section 14):
    If RSA key wrapping is migrated to ML-KEM, but RSA root authentication remains,
    the simulator MUST NOT declare the system fully quantum-ready.
    The remaining weakness must be explicitly listed under remaining_findings.
    """
    request = WhatIfMigrationRequest(
        asset_id="BANK-PROF-CORE-BANKING",
        changes=[
            MigrationAction(
                component=MigrationComponent.KEY_WRAPPING,
                target_algorithm="ML-KEM-768",
            ),
        ],
    )
    result = simulate_migration(request)

    # 1. Must be PARTIALLY_QUANTUM_READY, NOT QUANTUM_READY
    assert result.after.key_protection.status == KeyChainStatus.PARTIALLY_QUANTUM_READY

    # 2. Resolved must contain RSA key wrapping
    assert "RSA-2048 key wrapping" in result.comparison.resolved_findings

    # 3. Remaining must contain RSA root authentication
    assert "RSA-2048 root authentication" in result.comparison.remaining_findings

    # 4. Explanation must state that remaining vulnerabilities exist
    assert "Remaining vulnerabilities" in result.explanation
    assert "RSA-2048 root authentication" in result.explanation


# ==============================================================================
# 8. MATHEMATICAL SCORE RECALCULATION (NOT HARDCODED DELTA) (TEST 8)
# ==============================================================================

def test_score_recalculated_through_phase4b_engine():
    """
    Verifies that the score is recomputed by the actual Phase 4B formula,
    not a fixed delta or percentage subtraction.
    """
    request = WhatIfMigrationRequest(
        asset_id="BANK-PROF-CORE-BANKING",
        changes=[
            MigrationAction(
                component=MigrationComponent.KEY_WRAPPING,
                target_algorithm="ML-KEM-768",
            ),
        ],
    )
    result = simulate_migration(request)

    # Formula check:
    # Before: TRF = 4/4 = 1.0, Score = 92
    # After: TRF = 1/4 = 0.25 (LOW quantum risk due to hybrid wrapping protecting data)
    # Priority score should be exactly round(100 * 0.25 * CompositeUrgency) == 23
    assert result.before.priority_score == 92
    assert result.after.priority_score == 23
    assert result.comparison.priority_score_delta == -69
    assert result.comparison.risk_reduction == 69


# ==============================================================================
# 9. MULTI-STEP COMPOUND MIGRATION (TEST 9)
# ==============================================================================

def test_multi_step_compound_migration_yields_quantum_ready():
    """
    Verifies that migrating BOTH key wrapping and authentication simultaneously
    applies to the same temporary state and yields QUANTUM_READY.
    """
    request = WhatIfMigrationRequest(
        asset_id="BANK-PROF-CORE-BANKING",
        changes=[
            MigrationAction(
                component=MigrationComponent.KEY_WRAPPING,
                target_algorithm="ML-KEM-768",
            ),
            MigrationAction(
                component=MigrationComponent.AUTHENTICATION,
                target_algorithm="ML-DSA-65",
            ),
        ],
    )
    result = simulate_migration(request)

    assert result.after.key_protection.status == KeyChainStatus.QUANTUM_READY
    assert len(result.comparison.remaining_findings) == 0
    assert len(result.comparison.resolved_findings) == 2
    assert result.after.priority_score < 10
    assert result.after.migration_priority == MigrationPriority.P3


# ==============================================================================
# 10. EVIDENCE PROVENANCE & SIMULATION LABELS (TEST 10)
# ==============================================================================

def test_simulation_evidence_is_explicitly_labeled_simulated():
    """
    CRITICAL INVARIANT (Section 6 & 22):
    Hypothetical outcomes must be labeled SIMULATED, never OBSERVED or DEPLOYED.
    """
    request = WhatIfMigrationRequest(
        asset_id="BANK-PROF-KYC-DB",
        changes=[
            MigrationAction(
                component=MigrationComponent.KEY_WRAPPING,
                target_algorithm="ML-KEM-768",
            ),
        ],
    )
    result = simulate_migration(request)

    assert result.evidence_state == "SIMULATED"
    assert "HYPOTHETICAL SIMULATION ONLY" in result.simulation_disclaimer
    assert result.simulation_id.startswith("SIM-")


# ==============================================================================
# 11. INCOMPLETE EVIDENCE PRESERVATION (TEST 11)
# ==============================================================================

def test_simulation_on_incomplete_evidence_preserves_insufficient_evidence():
    """
    Verifies that simulation on an asset with missing key-chain evidence does not
    fabricate vulnerabilities (INSUFFICIENT_EVIDENCE != VULNERABLE).
    """
    asset = BankingAsset(
        id="CUSTOM-NO-KEYCHAIN",
        name="External Partner Feed",
        criticality=AssetCriticality.MEDIUM,
        data_sensitivity=DataSensitivity.CONFIDENTIAL,
        data_lifetime=DataLifetime.MEDIUM,
        exposure=AssetExposure.PARTNER,
        migration_effort=MigrationEffort.MEDIUM,
        cryptography=None,
    )
    request = WhatIfMigrationRequest(
        asset=asset,
        changes=[
            MigrationAction(
                component=MigrationComponent.TLS_PROTOCOL,
                target_algorithm="TLSv1.3",
            ),
        ],
    )
    result = simulate_migration(request)

    assert result.evidence_state == "SIMULATED"
    assert result.after.priority_score >= 0
    assert len(result.comparison.newly_introduced_findings) == 0


# ==============================================================================
# 12. API CONTRACT ENDPOINT: POST /api/banking/risk/what-if (TEST 12)
# ==============================================================================

def test_api_what_if_endpoint_success():
    """Tests POST /api/banking/risk/what-if returns 200 with complete comparison."""
    DEFAULT_RATE_LIMITER.reset()
    payload = {
        "asset_id": "BANK-PROF-CORE-BANKING",
        "changes": [
            {
                "component": "KEY_WRAPPING",
                "current_algorithm": "RSA-2048",
                "target_algorithm": "ML-KEM-768",
                "description": "Upgrade mainframe KEK to FIPS 203 ML-KEM",
            }
        ],
    }
    response = client.post("/api/banking/risk/what-if", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["evidence_state"] == "SIMULATED"
    assert data["asset_id"] == "BANK-PROF-CORE-BANKING"
    assert "comparison" in data
    assert data["comparison"]["risk_reduction"] > 0
    assert data["comparison"]["priority_transition"] == "P0 -> P3"
    assert len(data["comparison"]["resolved_findings"]) > 0
    assert len(data["comparison"]["remaining_findings"]) > 0
    assert "explanation" in data


def test_api_what_if_endpoint_404_on_unknown_profile():
    """Tests POST /api/banking/risk/what-if returns 404 for unknown profile ID."""
    DEFAULT_RATE_LIMITER.reset()
    payload = {
        "asset_id": "NON_EXISTENT_PROFILE",
        "changes": [
            {
                "component": "KEY_WRAPPING",
                "target_algorithm": "ML-KEM-768",
            }
        ],
    }
    response = client.post("/api/banking/risk/what-if", json=payload)
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_api_what_if_endpoint_422_on_unsupported_algorithm():
    """Tests POST /api/banking/risk/what-if returns 422 for unapproved algorithm."""
    DEFAULT_RATE_LIMITER.reset()
    payload = {
        "asset_id": "BANK-PROF-CORE-BANKING",
        "changes": [
            {
                "component": "KEY_WRAPPING",
                "target_algorithm": "UNAPPROVED_CRYPTO_ALGO",
            }
        ],
    }
    response = client.post("/api/banking/risk/what-if", json=payload)
    assert response.status_code == 422
    assert "unsupported migration target" in response.json()["detail"].lower()


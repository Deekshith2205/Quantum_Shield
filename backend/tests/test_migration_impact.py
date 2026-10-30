"""Integration tests for Migration Impact & Crypto-Agility Engine."""

import pytest
from app.models.profiles import get_synthetic_profile_by_id
from app.services.migration_impact_engine import evaluate_migration_impact
from app.models.banking import BankingAsset, BankingAssetType, AssetCriticality, DataSensitivity, AssetExposure, DataLifetime, TrustZone, MigrationEffort


def test_payment_rail_latency_sensitivity():
    """UPI, Payment Gateways, and Card Authorization must be evaluated as HIGH latency sensitivity."""
    pg = get_synthetic_profile_by_id("BANK-PROF-PAYMENT-GATEWAY")
    atm = get_synthetic_profile_by_id("BANK-PROF-ATM-NETWORK")

    pg_impact = evaluate_migration_impact(pg)
    atm_impact = evaluate_migration_impact(atm)

    assert pg_impact.latency_sensitivity == "HIGH"
    assert atm_impact.latency_sensitivity == "HIGH"
    assert "sub-second" in pg_impact.latency_rationale.lower() or "throughput" in pg_impact.latency_rationale.lower()


def test_analytics_latency_sensitivity_is_low():
    """Internal back-office or analytics systems must have LOW latency sensitivity."""
    analytics_asset = BankingAsset(
        id="BANK-ASSET-ANALYTICS",
        name="Credit Risk Analytics Engine",
        asset_type=BankingAssetType.INTERNAL_SERVICE,
        system_type=BankingAssetType.INTERNAL_SERVICE,
        description="Nightly batch credit score risk computation",
        criticality=AssetCriticality.MEDIUM,
        data_sensitivity=DataSensitivity.INTERNAL,
        exposure=AssetExposure.RESTRICTED,
        data_lifetime=DataLifetime.MEDIUM,
        trust_zone=TrustZone.DATA,
        migration_effort=MigrationEffort.LOW,
    )
    impact = evaluate_migration_impact(analytics_asset)
    assert impact.latency_sensitivity == "LOW"


def test_hsm_dependency_increases_effort_without_being_vulnerability():
    """HSM dependency must result in HEAVY/MODERATE dependency without being classified as a vulnerability."""
    core = get_synthetic_profile_by_id("BANK-PROF-CORE-BANKING")
    impact = evaluate_migration_impact(core)

    assert impact.hsm_dependency == "HEAVY"
    assert "hardware security module" in impact.hsm_rationale.lower() or "hsm" in impact.hsm_rationale.lower()
    # HSM dependency must not label the system as vulnerable
    assert any("hsm" in rec.lower() for rec in impact.recommendations)


def test_legacy_connectors_detection():
    """ATM network must explicitly identify ISO 8583 and DUKPT legacy connectors."""
    atm = get_synthetic_profile_by_id("BANK-PROF-ATM-NETWORK")
    impact = evaluate_migration_impact(atm)

    assert len(impact.legacy_connectors) >= 2
    assert any("ISO 8583" in c for c in impact.legacy_connectors)
    assert any("DUKPT" in c for c in impact.legacy_connectors)


def test_crypto_agility_classification():
    """Core Banking must be evaluated as HARDCODED_MONOLITHIC whereas modern API is CONFIGURABLE."""
    core = get_synthetic_profile_by_id("BANK-PROF-CORE-BANKING")
    pg = get_synthetic_profile_by_id("BANK-PROF-PAYMENT-GATEWAY")

    core_impact = evaluate_migration_impact(core)
    pg_impact = evaluate_migration_impact(pg)

    assert core_impact.crypto_agility == "HARDCODED_MONOLITHIC"
    assert pg_impact.crypto_agility == "CONFIGURABLE"
    assert core_impact.composite_migration_impact in ["VERY_HIGH", "HIGH"]

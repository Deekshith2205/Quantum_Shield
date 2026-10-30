"""Deterministic Migration Impact & Crypto-Agility Engine.
Evaluates:
- Latency sensitivity (UPI/Cards/ATM vs Analytics)
- PQC size overhead (ML-KEM-768 ciphertext/key sizes, ML-DSA signature growth)
- HSM dependencies (firmware cycles & vendor readiness)
- Legacy protocols and fixed connectors
- Crypto-agility (hardcoded single primitive vs configurable algorithm engine)
"""

from typing import Dict, Any, List
from app.models.banking import BankingAsset, BankingAssetType, AssetCriticality
from app.models.migration_impact import MigrationImpactAssessment


def evaluate_migration_impact(asset: BankingAsset) -> MigrationImpactAssessment:
    """
    Computes a deterministic migration impact evaluation for a banking asset.
    """
    system_type = asset.system_type or asset.asset_type
    key_mgmt = asset.key_management or {}
    crypto = asset.cryptography
    chain = crypto.key_chain if crypto else None

    # 1. Latency Sensitivity
    if system_type in [
        BankingAssetType.PAYMENT_GATEWAY,
        BankingAssetType.UPI_PAYMENT_SERVICE,
        BankingAssetType.CARD_PROCESSING,
        BankingAssetType.ATM_NETWORK,
    ]:
        lat_sens = "HIGH"
        lat_rat = (
            "High-throughput transactional rail with strict sub-second SLA (< 200ms). "
            "Additional handshake round-trips or computation overhead directly risk transaction timeouts."
        )
    elif system_type in [BankingAssetType.NET_BANKING_PORTAL, BankingAssetType.MOBILE_BANKING_API, BankingAssetType.CORE_BANKING]:
        lat_sens = "MEDIUM"
        lat_rat = "Interactive user session and account inquiry rail; tolerant of standard TLS negotiation latency (50-100ms overhead)."
    else:
        lat_sens = "LOW"
        lat_rat = "Asynchronous, batch, or back-office analytics system; highly tolerant of post-quantum cryptographic computation delays."

    # 2. PQC Size Impact
    # ML-KEM-768: 1184B public key, 1088B ciphertext. ML-DSA-65: 1952B public key, 3309B signature.
    if lat_sens == "HIGH" or system_type in [BankingAssetType.ATM_NETWORK, BankingAssetType.CARD_PROCESSING]:
        pqc_size = "HIGH"
        pqc_rat = (
            "Network payload fragmentation risk on constrained ISO 8583 packet buffers and low-bandwidth POS/ATM links "
            "due to ML-DSA signature expansion (3.3 KB vs 256 bytes for ECDSA)."
        )
    elif system_type in [BankingAssetType.NET_BANKING_PORTAL, BankingAssetType.MOBILE_BANKING_API]:
        pqc_size = "MEDIUM"
        pqc_rat = "Handshake packet expansion across mobile cellular connections requires dual-record TLS frame tuning."
    else:
        pqc_size = "LOW"
        pqc_rat = "High-speed internal datacenter interconnects easily absorb PQC public key and ciphertext payload sizes."

    # 3. HSM Dependency
    storage_type = str(key_mgmt.get("storage_type", "")).upper()
    appliance = str(key_mgmt.get("appliance", "") or (crypto.kms_or_hsm if crypto else "")).upper()
    if "HSM" in storage_type or "HSM" in appliance or "PAYSHIELD" in appliance or "LUNA" in appliance:
        hsm_dep = "HEAVY"
        hsm_rat = (
            "Hardware Security Module (HSM) is deeply integrated for root key isolation. Migration depends strictly on "
            "vendor firmware certification (FIPS 140-3) supporting NIST FIPS 203/204 algorithms."
        )
    elif "KMS" in storage_type or "KMS" in appliance or "CLOUD" in storage_type:
        hsm_dep = "MODERATE"
        hsm_rat = "Cloud Key Management Service (KMS) handles key derivation. Migration tracks cloud provider PQC service roadmap."
    else:
        hsm_dep = "MINIMAL"
        hsm_rat = "Software-based key management allows rapid software library replacement without hardware vendor dependencies."

    # 4. Legacy Connectors
    legacy_conn = []
    if system_type == BankingAssetType.ATM_NETWORK:
        legacy_conn.append("ISO 8583 Financial Transaction Message Format")
        legacy_conn.append("DUKPT Base Derivation Key (BDK) Infrastructure")
        legacy_conn.append("Proprietary Terminal Hardware Cryptographic Coprocessors")
    elif system_type == BankingAssetType.CORE_BANKING:
        legacy_conn.append("Mainframe SNA / TCP Batch Settlement Connectors")
        legacy_conn.append("Fixed-Length Binary General Ledger Feeds")
    elif system_type == BankingAssetType.CUSTOMER_DATABASE:
        legacy_conn.append("Database Transparent Data Encryption (TDE) Column Filters")

    # 5. Crypto-Agility
    if system_type in [BankingAssetType.CORE_BANKING, BankingAssetType.ATM_NETWORK]:
        agility = "HARDCODED_MONOLITHIC"
        agil_rat = "Cryptographic primitives are deeply embedded in monolithic transaction routines; algorithm swap requires core redeployments."
    elif system_type in [BankingAssetType.CUSTOMER_DATABASE, BankingAssetType.NET_BANKING_PORTAL]:
        agility = "MODERATE"
        agil_rat = "Configuration-based TLS and key wrappers allow algorithm substitution via infrastructure changes with minimal code refactoring."
    else:
        agility = "CONFIGURABLE"
        agil_rat = "Pluggable provider architecture allows rapid cipher suite and hybrid group updates without modifying business logic."

    # 6. Composite Migration Impact
    if agility == "HARDCODED_MONOLITHIC" or (hsm_dep == "HEAVY" and lat_sens == "HIGH"):
        comp_impact = "VERY_HIGH"
    elif hsm_dep == "HEAVY" or lat_sens == "HIGH" or len(legacy_conn) > 0:
        comp_impact = "HIGH"
    elif lat_sens == "MEDIUM" or pqc_size == "MEDIUM":
        comp_impact = "MEDIUM"
    else:
        comp_impact = "LOW"

    # Prescriptive Recommendations
    recs = []
    if hsm_dep == "HEAVY":
        recs.append("Coordinate with HSM vendor for firmware roadmaps supporting FIPS 203 ML-KEM-768 hardware offloading.")
    if agility == "HARDCODED_MONOLITHIC":
        recs.append("Implement an abstracted cryptographic abstraction layer (Crypto-Service Provider) before algorithm migration.")
    if pqc_size == "HIGH":
        recs.append("Benchmark MTU and network segmentation to avoid packet fragmentation on high-overhead PQC certificates.")
    if len(legacy_conn) > 0:
        recs.append(f"Deploy modern protocol bridge proxies to isolate {legacy_conn[0]} from perimeter quantum risk.")

    return MigrationImpactAssessment(
        system_id=asset.id,
        latency_sensitivity=lat_sens,
        latency_rationale=lat_rat,
        pqc_size_impact=pqc_size,
        pqc_size_rationale=pqc_rat,
        hsm_dependency=hsm_dep,
        hsm_rationale=hsm_rat,
        legacy_connectors=legacy_conn,
        crypto_agility=agility,
        crypto_agility_rationale=agil_rat,
        composite_migration_impact=comp_impact,
        recommendations=recs,
    )

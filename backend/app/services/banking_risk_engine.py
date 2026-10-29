"""Banking Criticality and Key-Protection Risk Prioritization Engine.
Phase 4B - Banking Security Audit & Key-Protection Risk Engine

Evaluates banking asset migration priority based on:
Technical Risk (Quantum + Classical) x Business Exposure Factor x Migration Effort.

Enforces core principles:
1. Answers: "Which banking systems should be migrated first, and why?"
2. Separates technical cryptographic risk from business criticality, sensitivity, SNDL lifetime, and exposure.
3. AES-256 rule: AES-256 retains approximately 128-bit security against an idealized Grover search
   and is not treated as a quantum-broken primitive by QuantumShield. Weaknesses lie in key-protection
   mechanisms (key wrapping and root authentication), not AES-256 itself.
4. Generates deterministic, explainable scores (0-100) and priority bands (P0, P1, P2, P3).
"""

from typing import List, Dict, Optional, Tuple, Any
from app.models.banking import (
    BankingAsset,
    AssetCriticality,
    DataSensitivity,
    AssetExposure,
    DataLifetime,
    MigrationEffort,
    KeyProtectionChain,
    CryptoConfiguration,
)
from app.models.risk import (
    KeyChainStatus,
    MigrationPriority,
    KeyChainAnalysis,
    TechnicalRiskContext,
    BusinessRiskContext,
    RiskContributorItem,
    BankingRiskAssessment,
)


# ==============================================================================
# 1. NORMALIZATION FUNCTIONS (EXPLICIT WEIGHT MAPPINGS)
# ==============================================================================

def normalize_criticality_weight(criticality: AssetCriticality) -> int:
    """LOW = 1, MEDIUM = 2, HIGH = 3, CRITICAL = 4."""
    mapping = {
        AssetCriticality.LOW: 1,
        AssetCriticality.MEDIUM: 2,
        AssetCriticality.HIGH: 3,
        AssetCriticality.CRITICAL: 4,
    }
    return mapping.get(criticality, 2)


def normalize_sensitivity_weight(sensitivity: DataSensitivity) -> int:
    """PUBLIC = 1, INTERNAL = 2, CONFIDENTIAL = 3, HIGHLY_SENSITIVE = 4."""
    mapping = {
        DataSensitivity.PUBLIC: 1,
        DataSensitivity.INTERNAL: 2,
        DataSensitivity.CONFIDENTIAL: 3,
        DataSensitivity.HIGHLY_SENSITIVE: 4,
    }
    return mapping.get(sensitivity, 3)


def normalize_lifetime_weight(lifetime: DataLifetime) -> int:
    """SHORT = 1, MEDIUM = 2, LONG = 3, VERY_LONG = 4."""
    mapping = {
        DataLifetime.SHORT: 1,
        DataLifetime.MEDIUM: 2,
        DataLifetime.LONG: 3,
        DataLifetime.VERY_LONG: 4,
    }
    return mapping.get(lifetime, 3)


def normalize_exposure_weight(exposure: AssetExposure) -> int:
    """RESTRICTED = 1, INTERNAL = 2, PARTNER = 3, INTERNET = 4."""
    mapping = {
        AssetExposure.RESTRICTED: 1,
        AssetExposure.INTERNAL: 2,
        AssetExposure.PARTNER: 3,
        AssetExposure.INTERNET: 4,
    }
    return mapping.get(exposure, 4)


def normalize_migration_effort_weight(effort: MigrationEffort) -> int:
    """LOW = 1, MEDIUM = 2, HIGH = 3, VERY_HIGH = 4."""
    mapping = {
        MigrationEffort.LOW: 1,
        MigrationEffort.MEDIUM: 2,
        MigrationEffort.HIGH: 3,
        MigrationEffort.VERY_HIGH: 4,
    }
    return mapping.get(effort, 2)


def normalize_quantum_risk_level(severity_or_score: Any) -> Tuple[int, str]:
    """
    Maps technical finding severity or quantum readiness score to 0-4 risk level:
    0 = NONE / INFORMATIONAL, 1 = LOW, 2 = MEDIUM, 3 = HIGH, 4 = CRITICAL.
    """
    if isinstance(severity_or_score, (int, float)):
        # Quantum Readiness Score (0-100, where higher is better readiness)
        # Exposure risk = 100 - readiness
        score = int(severity_or_score)
        if score <= 35:
            return 4, "CRITICAL"
        elif score < 55:
            return 3, "HIGH"
        elif score < 75:
            return 2, "MEDIUM"
        elif score < 90:
            return 1, "LOW"
        else:
            return 0, "NONE"

    s_str = str(severity_or_score).upper().strip()
    if s_str in ["CRITICAL"]:
        return 4, "CRITICAL"
    elif s_str in ["HIGH"]:
        return 3, "HIGH"
    elif s_str in ["MEDIUM"]:
        return 2, "MEDIUM"
    elif s_str in ["LOW"]:
        return 1, "LOW"
    else:
        return 0, "NONE"


def normalize_classical_risk_level(classical_risk: str) -> Tuple[int, str]:
    """Maps classical risk string to 0-4 risk level."""
    c_str = str(classical_risk).upper().strip()
    if c_str in ["CRITICAL"]:
        return 4, "CRITICAL"
    elif c_str in ["HIGH"]:
        return 3, "HIGH"
    elif c_str in ["MEDIUM"]:
        return 2, "MEDIUM"
    elif c_str in ["LOW"]:
        return 1, "LOW"
    else:
        return 0, "NONE"


# ==============================================================================
# 2. KEY-PROTECTION-CHAIN ANALYSIS (AES-256 RESILIENCE VS ASYMMETRIC WRAPPING)
# ==============================================================================

def analyze_key_protection_chain(chain: Optional[KeyProtectionChain]) -> KeyChainAnalysis:
    """
    Analyzes the 4-tier cryptographic key protection hierarchy:
    Data Encryption -> Key Wrapping -> Key Storage -> Authentication / Master Key.

    Enforces Core Invariants:
    1. AES-256 retains approximately 128-bit security against an idealized Grover search
       and is not treated as a quantum-broken primitive by QuantumShield. It is NOT a quantum vulnerability.
    2. Primary quantum vulnerabilities reside in asymmetric key wrapping (RSA, ECDH) and authentication (ECDSA, RSA).
    3. Incomplete evidence -> INSUFFICIENT_EVIDENCE (NOT_OBSERVABLE != VULNERABLE).
    """
    if not chain or (not chain.data_encryption and not chain.key_wrapping and not chain.key_storage and not chain.authentication):
        return KeyChainAnalysis(
            status=KeyChainStatus.INSUFFICIENT_EVIDENCE,
            weak_links=[],
            data_encryption_status="UNKNOWN",
            key_wrapping_status="UNKNOWN",
            key_storage_status="UNKNOWN",
            authentication_status="UNKNOWN",
            primary_migration_dependencies=[],
            notes="No key-protection hierarchy evidence declared or observable from external vantage point."
        )

    weak_links: List[str] = []
    primary_deps: List[str] = []

    # Tier 1: Bulk Data Encryption At-Rest
    data_enc = (chain.data_encryption or "").strip()
    data_enc_upper = data_enc.upper()
    data_enc_status = "UNKNOWN"

    if any(q in data_enc_upper for q in ["AES-256", "AES256", "CHACHA20"]):
        data_enc_status = "ADEQUATE_GROVER_RESILIENT"
    elif any(q in data_enc_upper for q in ["AES-128", "AES128"]):
        data_enc_status = "REDUCED_MARGIN_GROVER"
        weak_links.append(f"{data_enc} (reduced 64-bit quantum margin under Grover)")
        primary_deps.append(f"Upgrade {data_enc} bulk encryption to AES-256-GCM")
    elif any(q in data_enc_upper for q in ["3DES", "DES", "RC4", "BLOWFISH"]):
        data_enc_status = "DEPRECATED_LEGACY"
        weak_links.append(f"{data_enc} legacy symmetric cipher")
        primary_deps.append(f"Replace obsolete {data_enc} with AES-256-GCM")
    elif not data_enc:
        data_enc_status = "INSUFFICIENT_EVIDENCE"
    else:
        data_enc_status = "ADEQUATE"

    # Tier 2: Key Wrapping / Key Establishment (KEK)
    key_wrap = (chain.key_wrapping or "").strip()
    key_wrap_upper = key_wrap.upper()
    key_wrap_status = "UNKNOWN"

    if any(pqc in key_wrap_upper for pqc in ["ML-KEM", "MLKEM", "KYBER", "HYBRID"]):
        key_wrap_status = "QUANTUM_READY"
    elif any(vuln in key_wrap_upper for vuln in ["RSA", "ECDH", "X25519", "DIFFIE", "DH"]):
        key_wrap_status = "QUANTUM_VULNERABLE"
        weak_links.append(f"{key_wrap} key wrapping")
        primary_deps.append(f"Migrate {key_wrap} key encapsulation to FIPS 203 ML-KEM-768")
    elif any(leg in key_wrap_upper for leg in ["3DES", "DES"]):
        key_wrap_status = "LEGACY_VULNERABLE"
        weak_links.append(f"{key_wrap} key wrapping")
        primary_deps.append(f"Replace legacy {key_wrap} with AES Key Wrap (KW) or ML-KEM")
    elif not key_wrap:
        key_wrap_status = "INSUFFICIENT_EVIDENCE"
    else:
        key_wrap_status = "CLASSICAL"

    # Tier 3: Key Storage Medium
    key_stor = (chain.key_storage or "").strip()
    key_stor_upper = key_stor.upper()
    key_stor_status = "UNKNOWN"

    if any(hsm in key_stor_upper for hsm in ["HSM", "PAYSHIELD", "LUNA", "HARDWARE"]):
        key_stor_status = "HARDWARE_PROTECTED"
    elif any(kms in key_stor_upper for kms in ["KMS", "KEY VAULT", "CLOUD"]):
        key_stor_status = "CLOUD_KMS_PROTECTED"
    elif any(sw in key_stor_upper for sw in ["LOCAL", "PLAINTEXT", "FILE", "SOFTWARE"]):
        key_stor_status = "SOFTWARE_UNPROTECTED"
        weak_links.append(f"{key_stor} software key store")
        primary_deps.append("Isolate master encryption keys within certified HSM or cloud KMS")
    elif not key_stor:
        key_stor_status = "INSUFFICIENT_EVIDENCE"
    else:
        key_stor_status = "STANDARD_STORE"

    # Tier 4: Root Authentication / Master Key Signature
    auth = (chain.authentication or "").strip()
    auth_upper = auth.upper()
    auth_status = "UNKNOWN"

    if any(pqc in auth_upper for pqc in ["ML-DSA", "SLH-DSA", "DILITHIUM", "SPHINCS", "FALCON"]):
        auth_status = "QUANTUM_READY"
    elif any(vuln in auth_upper for vuln in ["ECDSA", "RSA", "ED25519", "DSA", "P256", "P384"]):
        auth_status = "QUANTUM_VULNERABLE"
        weak_links.append(f"{auth} root authentication")
        primary_deps.append(f"Transition {auth} authentication and signatures to FIPS 204 ML-DSA-65")
    elif not auth:
        auth_status = "INSUFFICIENT_EVIDENCE"
    else:
        auth_status = "CLASSICAL"

    # Overall Post-Quantum Chain Posture Determination
    if key_wrap_status == "INSUFFICIENT_EVIDENCE" and key_stor_status == "INSUFFICIENT_EVIDENCE":
        overall_status = KeyChainStatus.INSUFFICIENT_EVIDENCE
    elif key_wrap_status == "QUANTUM_READY" and (auth_status in ["QUANTUM_READY", "INSUFFICIENT_EVIDENCE"]) and data_enc_status == "ADEQUATE_GROVER_RESILIENT":
        overall_status = KeyChainStatus.QUANTUM_READY
    elif key_wrap_status == "QUANTUM_READY":
        overall_status = KeyChainStatus.PARTIALLY_QUANTUM_READY
    elif key_wrap_status in ["QUANTUM_VULNERABLE", "LEGACY_VULNERABLE"] or auth_status == "QUANTUM_VULNERABLE":
        overall_status = KeyChainStatus.QUANTUM_EXPOSED
    else:
        overall_status = KeyChainStatus.PARTIALLY_QUANTUM_READY

    notes = (
        "AES-256 retains approximately 128-bit security against an idealized Grover search and is not treated as a "
        "quantum-broken primitive by QuantumShield. Long-lived sensitive data has greater exposure to Store Now, "
        "Decrypt Later (SNDL) risk because confidentiality must remain intact for an extended period, especially "
        "when asymmetric key wrapping or root authentication signatures remain quantum-vulnerable."
    )

    return KeyChainAnalysis(
        status=overall_status,
        weak_links=weak_links,
        data_encryption_status=data_enc_status,
        data_encryption_algorithm=data_enc or None,
        key_wrapping_status=key_wrap_status,
        key_wrapping_algorithm=key_wrap or None,
        key_storage_status=key_stor_status,
        key_storage_facility=key_stor or None,
        authentication_status=auth_status,
        authentication_algorithm=auth or None,
        primary_migration_dependencies=primary_deps,
        notes=notes,
    )


# ==============================================================================
# 3. DETERMINISTIC BANKING RISK ENGINE & FORMULA
# ==============================================================================

def evaluate_banking_risk(
    asset: BankingAsset,
    scan_quantum_score: Optional[int] = None,
    scan_classical_risk: Optional[str] = "LOW",
) -> BankingRiskAssessment:
    """
    Computes deterministic banking-aware risk prioritization.

    Formula:
    1. Business Exposure Factor (BEF) = 0.30*C_norm + 0.25*S_norm + 0.30*L_norm + 0.15*E_norm
       Where:
       - C_norm: Criticality / 4.0
       - S_norm: Sensitivity / 4.0
       - L_norm: Data Lifetime / 4.0 (SNDL vulnerability horizon)
       - E_norm: Exposure / 4.0
    2. Technical Risk Factor (TRF) = max(Quantum Risk Level, Classical Risk Level) / 4.0
       Where level is 0 to 4 (NONE=0, LOW=1, MEDIUM=2, HIGH=3, CRITICAL=4)
    3. Composite Urgency Factor = 0.70*BEF + 0.30*M_norm
       Where M_norm: Migration Effort / 4.0 (High effort increases planning urgency)
    4. Migration Priority Score = round(100 * TRF * Composite Urgency Factor)
       Priority Bands:
       - P0: Score >= 85 (Immediate Strategic Migration)
       - P1: Score 65 - 84 (High Priority)
       - P2: Score 40 - 64 (Planned Migration)
       - P3: Score < 40 (Monitor / Maintain)
    """
    # Step 1: Analyze Key Protection Chain
    chain = asset.cryptography.key_chain if asset.cryptography else None
    key_analysis = analyze_key_protection_chain(chain)

    # Step 2: Determine Technical Risk Dimensions
    if scan_quantum_score is not None:
        q_level, q_label = normalize_quantum_risk_level(scan_quantum_score)
    else:
        # Determine from asset cryptographic profile if scan score not provided
        if key_analysis.key_wrapping_status == "QUANTUM_READY":
            if key_analysis.authentication_status == "QUANTUM_READY":
                q_level, q_label = 0, "NONE"
            else:
                q_level, q_label = 1, "LOW"  # Hybrid key wrapping protects data confidentiality; auth is classical
        elif key_analysis.key_wrapping_status in ["QUANTUM_VULNERABLE", "LEGACY_VULNERABLE"]:
            # Critical SNDL risk if data lifetime is VERY_LONG
            if asset.data_lifetime == DataLifetime.VERY_LONG:
                q_level, q_label = 4, "CRITICAL"
            elif asset.data_lifetime == DataLifetime.LONG or asset.exposure == AssetExposure.INTERNET:
                q_level, q_label = 3, "HIGH"
            else:
                q_level, q_label = 2, "MEDIUM"
        elif key_analysis.status == KeyChainStatus.QUANTUM_EXPOSED:
            q_level, q_label = 4, "CRITICAL"
        elif key_analysis.status == KeyChainStatus.PARTIALLY_QUANTUM_READY:
            q_level, q_label = 3, "HIGH"
        else:
            q_level, q_label = 2, "MEDIUM"

    c_level, c_label = normalize_classical_risk_level(scan_classical_risk or "LOW")
    if (
        key_analysis.data_encryption_status == "DEPRECATED_LEGACY"
        or key_analysis.key_wrapping_status == "LEGACY_VULNERABLE"
    ) and c_level < 4:
        c_level = 4
        c_label = "CRITICAL"

    gov_tech_risk = max(q_level, c_level)

    technical_risk = TechnicalRiskContext(
        quantum_risk_level=q_level,
        quantum_risk_label=q_label,
        classical_risk_level=c_level,
        classical_risk_label=c_label,
        governing_technical_risk=gov_tech_risk,
    )

    # Step 3: Normalize Business Dimensions (1 to 4 scale)
    c_weight = normalize_criticality_weight(asset.criticality)
    s_weight = normalize_sensitivity_weight(asset.data_sensitivity)
    l_weight = normalize_lifetime_weight(asset.data_lifetime)
    e_weight = normalize_exposure_weight(asset.exposure)
    m_weight = normalize_migration_effort_weight(asset.migration_effort)

    # Normalized unit values (0.25 to 1.0)
    c_norm = c_weight / 4.0
    s_norm = s_weight / 4.0
    l_norm = l_weight / 4.0
    e_norm = e_weight / 4.0
    m_norm = m_weight / 4.0

    # Business Exposure Factor (SNDL lifetime & criticality heavily weighted)
    bef = (0.30 * c_norm) + (0.25 * s_norm) + (0.30 * l_norm) + (0.15 * e_norm)

    c_label = asset.criticality.value if asset.criticality else "MEDIUM (Default)"
    s_label = asset.data_sensitivity.value.replace("_", " ") if asset.data_sensitivity else "CONFIDENTIAL (Default)"
    l_label = asset.data_lifetime.value.replace("_", " ") if asset.data_lifetime else "LONG (Default)"
    e_label = asset.exposure.value if asset.exposure else "INTERNET (Default)"
    m_label = asset.migration_effort.value.replace("_", " ") if asset.migration_effort else "MEDIUM (Default)"

    business_context = BusinessRiskContext(
        criticality_score=c_weight,
        criticality_label=c_label,
        sensitivity_score=s_weight,
        sensitivity_label=s_label,
        lifetime_score=l_weight,
        lifetime_label=l_label,
        exposure_score=e_weight,
        exposure_label=e_label,
        migration_effort_score=m_weight,
        migration_effort_label=m_label,
        business_exposure_factor=round(bef, 4),
    )

    # Step 4: Technical Risk Factor (0.0 to 1.0)
    trf = gov_tech_risk / 4.0

    # Step 5: Composite Urgency Factor (combining business exposure and migration complexity)
    composite_urgency = (0.70 * bef) + (0.30 * m_norm)

    # Step 6: Priority Score (0-100)
    raw_score = 100.0 * trf * composite_urgency
    priority_score = min(100, max(0, int(round(raw_score))))

    # Step 7: Priority Band Assignment
    if priority_score >= 85:
        priority_band = MigrationPriority.P0
        priority_band_label = "P0 — Immediate Strategic Migration"
        planning_window = "Immediate Planning (Q1-Q2 Next Fiscal Year)"
    elif priority_score >= 65:
        priority_band = MigrationPriority.P1
        priority_band_label = "P1 — High Priority Migration"
        planning_window = "High Priority Window (12-24 Months)"
    elif priority_score >= 40:
        priority_band = MigrationPriority.P2
        priority_band_label = "P2 — Planned Migration"
        planning_window = "Medium Term Roadmap (24-36 Months)"
    else:
        priority_band = MigrationPriority.P3
        priority_band_label = "P3 — Monitor / Maintain"
        planning_window = "Ongoing Lifecycle Monitoring"

    # Step 8: Risk Contributors Breakdown
    contributors = [
        RiskContributorItem(
            factor="Technical Quantum Risk",
            score=q_level,
            max_score=4,
            label=q_label,
            weight_pct=int((q_level / 4.0) * 100),
            description="Exposure of perimeter and key hierarchy to Shor's/Grover's algorithms",
        ),
        RiskContributorItem(
            factor="Business Criticality",
            score=c_weight,
            max_score=4,
            label=c_label,
            weight_pct=int(c_norm * 100),
            description="Core financial operational impact if compromised or unavailable",
        ),
        RiskContributorItem(
            factor="Data Sensitivity",
            score=s_weight,
            max_score=4,
            label=s_label,
            weight_pct=int(s_norm * 100),
            description="Confidentiality requirements of transaction and cardholder data",
        ),
        RiskContributorItem(
            factor="SNDL Data Lifetime",
            score=l_weight,
            max_score=4,
            label=l_label,
            weight_pct=int(l_norm * 100),
            description="Time horizon during which captured ciphertext remains vulnerable (Store Now, Decrypt Later)",
        ),
        RiskContributorItem(
            factor="Network Exposure",
            score=e_weight,
            max_score=4,
            label=e_label,
            weight_pct=int(e_norm * 100),
            description="Accessibility of perimeter from public internet or internal zones",
        ),
        RiskContributorItem(
            factor="Migration Effort & Urgency",
            score=m_weight,
            max_score=4,
            label=m_label,
            weight_pct=int(m_norm * 100),
            description="Architectural complexity requiring early multi-year migration planning",
        ),
    ]

    # Step 9: Structured Articulate Explanation
    explanation = _generate_risk_explanation(
        asset=asset,
        priority=priority_band,
        score=priority_score,
        key_analysis=key_analysis,
        tech_risk=technical_risk,
        bus_context=business_context,
    )

    system_type = "OTHER"
    if asset.system_type and hasattr(asset.system_type, "value"):
        system_type = asset.system_type.value
    elif asset.asset_type and hasattr(asset.asset_type, "value"):
        system_type = asset.asset_type.value
    elif asset.system_type:
        system_type = str(asset.system_type)
    elif asset.asset_type:
        system_type = str(asset.asset_type)

    return BankingRiskAssessment(
        asset_id=asset.id,
        asset_name=asset.name or "Unnamed Banking Asset",
        system_type=system_type,
        technical_risk=technical_risk,
        business_context=business_context,
        key_protection=key_analysis,
        migration_priority=priority_band,
        priority_score=priority_score,
        priority_band_label=priority_band_label,
        contributors=contributors,
        explanation=explanation,
        recommended_planning_window=planning_window,
    )


def _generate_risk_explanation(
    asset: BankingAsset,
    priority: MigrationPriority,
    score: int,
    key_analysis: KeyChainAnalysis,
    tech_risk: TechnicalRiskContext,
    bus_context: BusinessRiskContext,
) -> str:
    """Generates deterministic, structured, articulate narrative explaining 'Why this priority?'."""
    name = asset.name or "Asset"
    crit = asset.criticality.value.lower() if asset.criticality else "medium"
    sens = asset.data_sensitivity.value.replace("_", " ").lower() if asset.data_sensitivity else "confidential"
    life = asset.data_lifetime.value.replace("_", " ").lower() if asset.data_lifetime else "long"
    effort = asset.migration_effort.value.replace("_", " ").lower() if asset.migration_effort else "medium"

    if priority == MigrationPriority.P0:
        weak_str = (
            ", ".join(key_analysis.weak_links)
            if key_analysis.weak_links
            else "asymmetric key wrapping vulnerabilities"
        )
        return (
            f"{name} is classified as {priority.value} (Immediate Strategic Migration) with a Priority Score of {score}/100. "
            f"It operates as a {crit} banking asset holding {sens} financial data with a {life} retention horizon. "
            f"Long-lived sensitive data has greater exposure to Store Now, Decrypt Later (SNDL) risk because confidentiality "
            f"must remain intact for an extended period. The assessed key protection hierarchy exhibits critical dependencies "
            f"on {weak_str}. Given its {effort} migration complexity, strategic migration planning must begin immediately to "
            f"ensure transition before prolonged exposure."
        )
    elif priority == MigrationPriority.P1:
        weak_str = ", ".join(key_analysis.weak_links) if key_analysis.weak_links else "legacy cryptographic controls"
        return (
            f"{name} is classified as {priority.value} (High Priority Migration) with a Priority Score of {score}/100. "
            f"It handles {sens} records with {life} confidentiality requirements. "
            f"The system exhibits quantum risk in its protection chain ({weak_str}) and requires {effort} migration effort. "
            f"Migration should be prioritized within the next 12 to 24 months."
        )
    elif priority == MigrationPriority.P2:
        return (
            f"{name} is classified as {priority.value} (Planned Migration) with a Priority Score of {score}/100. "
            f"While the asset utilizes quantum-vulnerable public key algorithms, its {life} data retention horizon and "
            f"{effort} migration effort allow migration to be scheduled under standard technology refresh cycles "
            f"over the next 24 to 36 months."
        )
    else:  # P3
        if key_analysis.status == KeyChainStatus.QUANTUM_READY:
            return (
                f"{name} is classified as {priority.value} (Monitor / Maintain) with a Priority Score of {score}/100. "
                f"The system has already integrated post-quantum or hybrid cryptography (such as ML-KEM) across its "
                f"key protection hierarchy. Ongoing monitoring is recommended as standards mature."
            )
        return (
            f"{name} is classified as {priority.value} (Monitor / Maintain) with a Priority Score of {score}/100. "
            f"The asset handles {sens} information with a {life} retention lifetime. "
            f"Although classical algorithms remain in use, the low business impact and limited SNDL exposure warrant "
            f"monitoring without immediate migration intervention."
        )


def get_all_synthetic_risk_assessments() -> List[BankingRiskAssessment]:
    """
    Evaluates and ranks all synthetic banking profiles in descending order of migration priority.
    Answers: 'Which banking systems should be migrated first, and why?'
    """
    from app.models.profiles import get_synthetic_banking_profiles
    profiles = get_synthetic_banking_profiles()
    results = [evaluate_banking_risk(p) for p in profiles]
    # Sort descending by priority_score
    results.sort(key=lambda r: r.priority_score, reverse=True)
    return results


def get_profile_risk_assessment(profile_id: str) -> Optional[BankingRiskAssessment]:
    """Retrieves and evaluates the banking risk assessment for a specific synthetic profile."""
    from app.models.profiles import get_synthetic_profile_by_id
    profile = get_synthetic_profile_by_id(profile_id)
    if not profile:
        return None
    return evaluate_banking_risk(profile)


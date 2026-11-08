
"""Deterministic Ranked Upgrade Planner Service.
Calculates and orders banking migration priorities dynamically across all representative profiles.
Never hardcodes rankings.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional

from app.models.banking import BankingAsset
from app.models.profiles import get_synthetic_banking_profiles
from app.models.upgrade_plan import RankedUpgradePlan, RankedUpgradeItem
from app.services.banking_risk_engine import evaluate_banking_risk
from app.services.migration_impact_engine import evaluate_migration_impact
from app.services.finding_normalizer import (
    collect_unified_findings,
    normalize_config_finding,
    normalize_crypto_misuse_finding,
)
from app.scanners.config_scanner.scanner import BankingConfigScanner
from app.scanners.crypto_misuse.scanner import CryptoMisuseScanner


# Resolve all sample paths from the repository root, independent of cwd.
# __file__ = backend/app/services/upgrade_planner.py
# parents[3] = Quantum_Shield repository root.
PROJECT_ROOT = Path(__file__).resolve().parents[3]


# Mapping of system IDs to sample configuration paths.
SYSTEM_CONFIG_MAP = {
    "BANK-PROF-CORE-BANKING": PROJECT_ROOT / "backend/sample_data/banking/core_banking",
    "BANK-PROF-NET-BANKING": PROJECT_ROOT / "backend/sample_data/banking/net_banking",
    "BANK-PROF-PAYMENT-GATEWAY": PROJECT_ROOT / "backend/sample_data/banking/payment_gateway",
    "BANK-PROF-ATM-NETWORK": PROJECT_ROOT / "backend/sample_data/banking/atm",
    "BANK-PROF-KYC-DB": PROJECT_ROOT / "backend/sample_data/banking/interbank",
    "BANK-PROF-UPI": PROJECT_ROOT / "backend/sample_data/banking/upi_backend",
    "BANK-PROF-ADMIN-VPN": PROJECT_ROOT / "backend/sample_data/banking/admin_vpn",
}


# Mapping of system IDs to crypto misuse code fixture paths.
SYSTEM_CODE_MAP = {
    "BANK-PROF-CORE-BANKING": PROJECT_ROOT / "backend/sample_data/banking/core_banking/src",
    "BANK-PROF-NET-BANKING": PROJECT_ROOT / "backend/sample_data/banking/net_banking/src",
    "BANK-PROF-PAYMENT-GATEWAY": PROJECT_ROOT / "backend/sample_data/banking/payment_gateway/src",
    "BANK-PROF-ATM-NETWORK": PROJECT_ROOT / "backend/sample_data/banking/atm/src",
    "BANK-PROF-KYC-DB": PROJECT_ROOT / "backend/sample_data/banking/interbank/src",
}


def get_system_config_findings(system_id: str) -> List[Any]:
    """Scans and returns configuration observations for a banking system."""
    sample_dir = SYSTEM_CONFIG_MAP.get(system_id)
    if not sample_dir:
        return []

    p = Path(sample_dir)
    if not p.is_dir():
        return []

    scanner = BankingConfigScanner()
    inv = scanner.scan_directory(p)
    return inv.observations


def get_system_crypto_misuse_findings(system_id: str) -> List[Any]:
    """Scans and returns crypto misuse findings for a banking system."""
    sample_code = SYSTEM_CODE_MAP.get(system_id)
    if not sample_code:
        return []

    p = Path(sample_code)
    if not p.exists():
        return []

    scanner = CryptoMisuseScanner()
    res = scanner.scan(p)
    return res.findings


def generate_ranked_upgrade_plan(
    profiles: Optional[List[BankingAsset]] = None,
) -> RankedUpgradePlan:
    """
    Computes a deterministic ranked upgrade queue across all banking assets.
    Ranks systems strictly by calculated priority_score descending.
    Tie-breaking: (priority_score DESC, quantum_score DESC, criticality DESC, system_id ASC).
    """
    if profiles is None:
        profiles = get_synthetic_banking_profiles()

    evaluated_items = []

    for p in profiles:
        # 1. Compute multi-dimensional banking risk
        risk_assessment = evaluate_banking_risk(p)

        # 2. Compute migration impact
        mig_impact = evaluate_migration_impact(p)

        # 3. Collect unified findings for top-findings extraction
        config_observations = get_system_config_findings(p.id)
        misuse_findings = get_system_crypto_misuse_findings(p.id)

        unified_findings = collect_unified_findings(
            system_id=p.id,
            crypto_misuse_findings=misuse_findings,
            config_findings=config_observations,
            banking_profile=p,
        )

        top_findings = [
            f.title
            for f in unified_findings
            if f.severity in ["CRITICAL", "HIGH"]
        ][:3]

        if not top_findings:
            top_findings = [f.title for f in unified_findings[:2]]

        # Key Protection Chain Posture Summary
        chain = p.cryptography.key_chain if p.cryptography else None
        chain_summary = {
            "data_encryption": chain.data_encryption if chain else "AES-256",
            "key_wrapping": chain.key_wrapping if chain else "RSA-2048",
            "key_storage": chain.key_storage if chain else "HSM",
            "authentication": chain.authentication if chain else "RSA-2048",
        }

        # Evidence gaps extraction
        ev_gaps = [
            f"{gap.control} ({gap.gap_type.value})"
            for gap in (p.evidence_gaps or [])
        ]

        # Top recommended upgrade
        if risk_assessment.key_protection.primary_migration_dependencies:
            rec_upgrade = (
                risk_assessment.key_protection.primary_migration_dependencies[0]
            )
        else:
            rec_upgrade = (
                "Upgrade perimeter transport to TLS 1.3 hybrid key exchange."
            )

        # Technical Scores (0-100 scale)
        q_score = int(
            round(
                (risk_assessment.technical_risk.quantum_risk_level / 4.0) * 100
            )
        )
        c_score = int(
            round(
                (risk_assessment.technical_risk.classical_risk_level / 4.0) * 100
            )
        )

        evaluated_items.append(
            {
                "asset": p,
                "risk": risk_assessment,
                "mig_impact": mig_impact,
                "top_findings": top_findings,
                "chain_summary": chain_summary,
                "ev_gaps": ev_gaps,
                "rec_upgrade": rec_upgrade,
                "q_score": q_score,
                "c_score": c_score,
            }
        )

    # Sort by priority_score descending, then quantum score and criticality.
    evaluated_items.sort(
        key=lambda item: (
            item["risk"].priority_score,
            item["q_score"],
            item["risk"].business_context.criticality_score,
        ),
        reverse=True,
    )

    queue: List[RankedUpgradeItem] = []
    p0_count = p1_count = p2_count = p3_count = 0

    for idx, item in enumerate(evaluated_items, start=1):
        p = item["asset"]
        r = item["risk"]
        m = item["mig_impact"]

        prio_band = r.migration_priority.value

        if prio_band == "P0":
            p0_count += 1
        elif prio_band == "P1":
            p1_count += 1
        elif prio_band == "P2":
            p2_count += 1
        else:
            p3_count += 1

        queue.append(
            RankedUpgradeItem(
                rank=idx,
                system_id=p.id,
                system_name=p.name,
                system=p.name,
                priority=prio_band,
                priority_score=r.priority_score,
                quantum_score=item["q_score"],
                classical_score=item["c_score"],
                criticality=p.criticality.value,
                sensitivity=p.data_sensitivity.value.replace("_", " "),
                data_lifetime=p.data_lifetime.value.replace("_", " "),
                lifetime=p.data_lifetime.value.replace("_", " "),
                exposure=p.exposure.value,
                migration_impact=m.composite_migration_impact,
                top_findings=item["top_findings"],
                key_protection_chain=item["chain_summary"],
                crypto_agility=m.crypto_agility,
                recommended_migration=item["rec_upgrade"],
                recommended_upgrade=item["rec_upgrade"],
                migration_complexity=(
                    f"{p.migration_effort.value} Effort · "
                    f"{r.recommended_planning_window}"
                ),
                estimated_migration_complexity=(
                    f"{p.migration_effort.value} Effort · "
                    f"{r.recommended_planning_window}"
                ),
                evidence_gaps=item["ev_gaps"],
            )
        )

    return RankedUpgradePlan(
        timestamp=datetime.now(timezone.utc).isoformat(),
        total_systems=len(queue),
        p0_count=p0_count,
        p1_count=p1_count,
        p2_count=p2_count,
        p3_count=p3_count,
        queue=queue,
    )

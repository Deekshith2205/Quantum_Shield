"""What-If Post-Quantum Migration Simulation Service.
Phase 4C - Deterministic What-If Migration Simulator for Banking Cryptography.

Executes hypothetical cryptographic substitutions against a temporary copy of a BankingAsset.
Recomputes key-protection posture, technical risk, business urgency, and priority score
using the exact Phase 4B risk engine.
Never mutates the original asset or persistent state.
All outcomes are explicitly marked as SIMULATED.
"""

import copy
import uuid
from typing import List, Dict, Optional, Tuple, Any
from app.models.banking import (
    BankingAsset,
    CryptoConfiguration,
    KeyProtectionChain,
)
from app.models.profiles import get_synthetic_profile_by_id
from app.models.risk import (
    BankingRiskAssessment,
    KeyChainStatus,
    MigrationPriority,
)
from app.models.simulation import (
    MigrationComponent,
    MigrationAction,
    ALLOWED_MIGRATION_TARGETS,
    WhatIfMigrationComparison,
    WhatIfMigrationRequest,
    WhatIfMigrationResult,
)
from app.services.banking_risk_engine import evaluate_banking_risk


class MigrationSimulationError(ValueError):
    """Raised when a simulation request fails validation."""
    pass


class ProfileNotFoundError(KeyError):
    """Raised when the specified profile ID is not found in the synthetic catalog."""
    pass


def validate_migration_request(request: WhatIfMigrationRequest) -> BankingAsset:
    """
    Validates a simulation request and returns the resolved baseline asset.
    Enforces allow-lists, operation bounds (1 to 5), and asset existence.
    """
    # 1. Operation count bounds
    if not request.changes or len(request.changes) < 1:
        raise MigrationSimulationError("At least one migration operation must be specified.")
    if len(request.changes) > 5:
        raise MigrationSimulationError(
            f"Maximum 5 migration operations allowed per simulation request; received {len(request.changes)}."
        )

    # 2. Strict allow-list validation per operation
    for idx, action in enumerate(request.changes):
        if action.component not in ALLOWED_MIGRATION_TARGETS:
            raise MigrationSimulationError(
                f"Operation #{idx + 1}: Unsupported component '{action.component}'. "
                f"Valid components are: {[c.value for c in MigrationComponent]}."
            )
        allowed_targets = ALLOWED_MIGRATION_TARGETS[action.component]
        if action.target_algorithm not in allowed_targets:
            raise MigrationSimulationError(
                f"Operation #{idx + 1}: Unsupported migration target '{action.target_algorithm}' "
                f"for component '{action.component.value}'. "
                f"Supported targets are: {allowed_targets}."
            )

    # 3. Resolve baseline asset
    if request.asset_id:
        profile = get_synthetic_profile_by_id(request.asset_id)
        if not profile:
            raise ProfileNotFoundError(f"Banking profile '{request.asset_id}' not found in synthetic catalog.")
        base_asset = profile
    elif request.asset:
        base_asset = request.asset
    else:
        raise MigrationSimulationError("Either 'asset_id' or 'asset' must be provided in simulation request.")

    return base_asset


def apply_hypothetical_substitutions(
    asset: BankingAsset,
    operations: List[MigrationAction],
) -> BankingAsset:
    """
    Applies the allow-listed hypothetical substitutions to a deep copy of the asset.
    Ensures the original asset remains strictly immutable.
    """
    simulated_asset = copy.deepcopy(asset)

    # Ensure cryptography and key_chain structures exist
    if not simulated_asset.cryptography:
        simulated_asset.cryptography = CryptoConfiguration(
            tls_versions=["TLSv1.3"],
            cipher_suites=[],
            certificates=[],
            key_chain=KeyProtectionChain(
                data_encryption="AES-256",
            ),
        )
    elif not simulated_asset.cryptography.key_chain:
        simulated_asset.cryptography.key_chain = KeyProtectionChain(
            data_encryption=simulated_asset.cryptography.data_encryption_algorithm or "AES-256",
        )

    key_chain = simulated_asset.cryptography.key_chain

    for action in operations:
        if action.component == MigrationComponent.KEY_WRAPPING:
            key_chain.key_wrapping = action.target_algorithm
            simulated_asset.cryptography.key_wrapping_algorithm = action.target_algorithm

        elif action.component == MigrationComponent.AUTHENTICATION:
            key_chain.authentication = action.target_algorithm
            simulated_asset.cryptography.signature_algorithm = action.target_algorithm

        elif action.component == MigrationComponent.TLS_PROTOCOL:
            simulated_asset.cryptography.tls_versions = [action.target_algorithm]

        elif action.component == MigrationComponent.TLS_KEY_EXCHANGE:
            simulated_asset.cryptography.key_exchange = action.target_algorithm

    return simulated_asset


def _generate_simulation_explanation(
    asset_name: str,
    operations: List[MigrationAction],
    before: BankingRiskAssessment,
    after: BankingRiskAssessment,
    resolved: List[str],
    remaining: List[str],
    delta: int,
) -> str:
    """
    Generates an articulate, deterministic explanation of the simulated migration outcome.
    Explicitly distinguishes resolved components from remaining risks.
    """
    ops_summary = ", ".join(f"{op.component.value} -> {op.target_algorithm}" for op in operations)

    lines = [
        f"Hypothetical simulation for {asset_name} modeling: {ops_summary}.",
    ]

    if delta > 0:
        lines.append(
            f"Simulation indicates a priority score reduction of {delta} points "
            f"({before.priority_score} -> {after.priority_score}), transitioning priority from "
            f"{before.migration_priority.value} to {after.migration_priority.value}."
        )
    elif delta == 0:
        lines.append(
            f"Modeled substitutions resulted in no net priority score change "
            f"({before.priority_score} -> {after.priority_score}, remaining {after.migration_priority.value})."
        )
    else:
        lines.append(
            f"Modeled substitutions resulted in a score delta of {delta} points "
            f"({before.priority_score} -> {after.priority_score})."
        )

    if resolved:
        lines.append(f"Resolved vulnerabilities: {', '.join(resolved)}.")

    if remaining:
        lines.append(
            f"Remaining vulnerabilities: {', '.join(remaining)}. "
            f"The presence of remaining quantum-vulnerable components prevents the system from achieving "
            f"a fully quantum-ready posture. Additional migration of the remaining dependencies is recommended."
        )
    elif after.key_protection.status == KeyChainStatus.QUANTUM_READY:
        lines.append(
            "All identified key-chain vulnerabilities have been modeled as migrated. "
            "The resulting key protection hierarchy achieves QUANTUM_READY posture."
        )

    lines.append(
        "Note: This is a mathematical simulation of hypothetical cryptographic changes and does not "
        "represent deployed production configurations."
    )

    return " ".join(lines)


def simulate_migration(request: WhatIfMigrationRequest) -> WhatIfMigrationResult:
    """
    Executes a deterministic What-If Post-Quantum Migration Simulation.

    Flow:
    1. Validate request and resolve baseline asset.
    2. Deep copy baseline asset (guaranteeing immutability).
    3. Evaluate baseline risk using Phase 4B risk engine.
    4. Apply hypothetical substitutions to deep-copied asset.
    5. Recompute key-chain posture and risk using Phase 4B risk engine.
    6. Compute delta, resolved findings, and remaining findings.
    7. Generate structured narrative and comparison.
    8. Return WhatIfMigrationResult with evidence_state=SIMULATED.
    """
    # 1. Validation & Resolution
    base_asset = validate_migration_request(request)

    # 2. Evaluate Baseline Risk
    before = evaluate_banking_risk(
        base_asset,
        scan_quantum_score=request.scan_quantum_score,
        scan_classical_risk="LOW",
    )

    # 3. Apply Hypothetical Substitutions (Immutably)
    simulated_asset = apply_hypothetical_substitutions(base_asset, request.changes)

    # 4. Recompute Simulated Risk via Phase 4B Engine
    # If TLS key exchange was simulated to a PQC hybrid, the simulated transport no longer exhibits
    # the baseline classical scan score; evaluate directly from modeled cryptographic configuration.
    transport_migrated = any(
        action.component in (MigrationComponent.TLS_KEY_EXCHANGE, MigrationComponent.TLS_PROTOCOL)
        for action in request.changes
    )
    simulated_scan_score = None if transport_migrated else request.scan_quantum_score

    after = evaluate_banking_risk(
        simulated_asset,
        scan_quantum_score=simulated_scan_score,
        scan_classical_risk="NONE" if after_is_fully_pqc(simulated_asset) else "LOW",
    )

    # 5. Delta & Finding Analysis
    score_delta = after.priority_score - before.priority_score
    risk_reduction = before.priority_score - after.priority_score

    weak_links_before = before.key_protection.weak_links
    weak_links_after = after.key_protection.weak_links

    resolved_findings = [w for w in weak_links_before if w not in weak_links_after]
    remaining_findings = [w for w in weak_links_after]
    newly_introduced = [w for w in weak_links_after if w not in weak_links_before]

    comparison = WhatIfMigrationComparison(
        priority_score_before=before.priority_score,
        priority_score_after=after.priority_score,
        priority_score_delta=score_delta,
        risk_reduction=max(0, risk_reduction),
        priority_band_before=before.migration_priority,
        priority_band_after=after.migration_priority,
        priority_transition=f"{before.migration_priority.value} -> {after.migration_priority.value}",
        key_chain_status_before=before.key_protection.status,
        key_chain_status_after=after.key_protection.status,
        key_chain_transition=f"{before.key_protection.status.value} -> {after.key_protection.status.value}",
        technical_risk_before=before.technical_risk,
        technical_risk_after=after.technical_risk,
        weak_links_before=weak_links_before,
        weak_links_after=weak_links_after,
        resolved_findings=resolved_findings,
        remaining_findings=remaining_findings,
        newly_introduced_findings=newly_introduced,
    )

    # 6. Structured Explanation
    explanation = _generate_simulation_explanation(
        asset_name=base_asset.name or "Asset",
        operations=request.changes,
        before=before,
        after=after,
        resolved=resolved_findings,
        remaining=remaining_findings,
        delta=risk_reduction,
    )

    sim_id = f"SIM-{uuid.uuid4().hex[:8].upper()}"

    return WhatIfMigrationResult(
        simulation_id=sim_id,
        asset_id=base_asset.id,
        asset_name=base_asset.name or "Unnamed Asset",
        evidence_state="SIMULATED",
        simulation_disclaimer=(
            "HYPOTHETICAL SIMULATION ONLY: This simulation models theoretical risk reduction "
            "and does not represent deployed cryptographic changes."
        ),
        operations=request.changes,
        before=before,
        after=after,
        comparison=comparison,
        explanation=explanation,
    )


def after_is_fully_pqc(asset: BankingAsset) -> bool:
    """Helper checking if all key chain components in the simulated asset are PQC."""
    if not asset.cryptography or not asset.cryptography.key_chain:
        return False
    kc = asset.cryptography.key_chain
    wrap_pqc = any(p in (kc.key_wrapping or "").upper() for p in ["ML-KEM", "MLKEM", "KYBER"])
    auth_pqc = any(p in (kc.authentication or "").upper() for p in ["ML-DSA", "SLH-DSA", "DILITHIUM"])
    return wrap_pqc and auth_pqc


"""What-If Post-Quantum Migration Simulator Models.
Phase 4C - Deterministic What-If Migration Simulator for Banking Cryptography.

Defines the structured request, supported migration operations, and comparison models.
All simulation results are strictly labeled as SIMULATED and never modify persistent state.
"""

from enum import Enum
from typing import List, Dict, Optional, Any
from datetime import datetime, timezone
import uuid
from pydantic import BaseModel, Field
from app.models.banking import BankingAsset
from app.models.risk import (
    BankingRiskAssessment,
    KeyChainStatus,
    MigrationPriority,
    TechnicalRiskContext,
)


class MigrationComponent(str, Enum):
    """Cryptographic component layer targeted for hypothetical migration."""
    KEY_WRAPPING = "KEY_WRAPPING"
    AUTHENTICATION = "AUTHENTICATION"
    TLS_PROTOCOL = "TLS_PROTOCOL"
    TLS_KEY_EXCHANGE = "TLS_KEY_EXCHANGE"


# Strict allow-list of supported post-quantum and hybrid migration targets
ALLOWED_MIGRATION_TARGETS: Dict[MigrationComponent, List[str]] = {
    MigrationComponent.KEY_WRAPPING: [
        "ML-KEM-768",
        "ML-KEM-1024",
        "X25519MLKEM768",
        "AES-256-KW",
    ],
    MigrationComponent.AUTHENTICATION: [
        "ML-DSA-65",
        "ML-DSA-87",
        "SLH-DSA-128s",
        "SLH-DSA-128f",
        "ML-DSA",
    ],
    MigrationComponent.TLS_PROTOCOL: [
        "TLSv1.3",
    ],
    MigrationComponent.TLS_KEY_EXCHANGE: [
        "X25519MLKEM768",
        "X448MLKEM1024",
        "SecP256r1MLKEM768",
        "X25519",
    ],
}


class MigrationAction(BaseModel):
    """A single hypothetical substitution of a cryptographic mechanism."""
    component: MigrationComponent = Field(..., description="Target architectural component to migrate")
    current_algorithm: Optional[str] = Field(default=None, description="Current algorithm being replaced")
    target_algorithm: str = Field(..., description="Target replacement algorithm from supported allow-list")
    description: Optional[str] = Field(default=None, description="Optional rationale or context for substitution")


class WhatIfMigrationComparison(BaseModel):
    """Detailed delta analysis comparing baseline assessment to simulated hypothetical state."""
    priority_score_before: int = Field(..., description="Baseline priority score (0-100)")
    priority_score_after: int = Field(..., description="Simulated priority score (0-100)")
    priority_score_delta: int = Field(..., description="Score change (after - before; negative indicates reduction)")
    risk_reduction: int = Field(..., description="Absolute risk reduction (before - after; positive indicates improvement)")
    priority_band_before: MigrationPriority
    priority_band_after: MigrationPriority
    priority_transition: str = Field(..., description="Display string e.g. 'P0 -> P2'")
    key_chain_status_before: KeyChainStatus
    key_chain_status_after: KeyChainStatus
    key_chain_transition: str = Field(..., description="Display string e.g. 'QUANTUM_EXPOSED -> PARTIALLY_QUANTUM_READY'")
    technical_risk_before: TechnicalRiskContext
    technical_risk_after: TechnicalRiskContext
    weak_links_before: List[str]
    weak_links_after: List[str]
    resolved_findings: List[str] = Field(default_factory=list, description="Weaknesses removed by this simulation")
    remaining_findings: List[str] = Field(default_factory=list, description="Weaknesses that remain unresolved")
    newly_introduced_findings: List[str] = Field(default_factory=list, description="Any new issues introduced")


class WhatIfMigrationRequest(BaseModel):
    """
    Request model for What-If Migration Simulation.
    Accepts either an asset_id referring to a synthetic profile or a custom BankingAsset.
    Enforces a strict upper bound of 5 migration operations.
    """
    asset_id: Optional[str] = Field(default=None, description="Profile ID from synthetic banking catalog")
    asset: Optional[BankingAsset] = Field(default=None, description="Custom banking asset definition (if not using asset_id)")
    scan_quantum_score: Optional[int] = Field(default=None, description="Optional baseline scan readiness score (0-100)")
    changes: List[MigrationAction] = Field(
        ...,
        min_length=1,
        max_length=5,
        description="1 to 5 hypothetical migration operations to apply"
    )


class WhatIfMigrationResult(BaseModel):
    """
    Structured outcome of What-If Migration Simulation.
    Clearly demarcated as SIMULATED to prevent conflation with live observed reality.
    """
    simulation_id: str = Field(..., description="Unique transient simulation identifier")
    asset_id: str
    asset_name: str
    evidence_state: str = Field(default="SIMULATED", description="Always SIMULATED; never OBSERVED or DEPLOYED")
    simulation_disclaimer: str = Field(
        default="HYPOTHETICAL SIMULATION ONLY: This simulation models theoretical risk reduction and does not represent deployed cryptographic changes."
    )
    operations: List[MigrationAction]
    before: BankingRiskAssessment
    after: BankingRiskAssessment
    comparison: WhatIfMigrationComparison
    explanation: str = Field(..., description="Narrative summary of simulation findings, resolved items, and remaining risks")
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


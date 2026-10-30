"""Machine-readable Assessment Report Models.
Comprehensive JSON and audit report structure covering all required enterprise audit sections.
"""

from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field
from app.models.findings import NormalizedFinding
from app.models.upgrade_plan import RankedUpgradePlan
from app.models.migration_impact import MigrationImpactAssessment
from app.models.audit_chain import AuditRecord


class CompleteAssessmentReport(BaseModel):
    """
    Complete machine-readable assessment report conforming to Section 19 requirements.
    Sections:
    1. metadata
    2. executive_summary
    3. system
    4. quantum_posture
    5. classical_posture
    6. priority
    7. priority_factors
    8. findings
    9. key_protection_chain
    10. crypto_agility
    11. migration_impact
    12. ranked_upgrade_plan
    13. cbom
    14. evidence_gaps
    15. observability
    16. what_if
    17. audit
    """
    metadata: Dict[str, Any] = Field(..., description="Report metadata (ID, timestamp, engine, version)")
    report_metadata: Dict[str, Any] = Field(..., description="Alias for metadata")
    executive_summary: Dict[str, Any] = Field(..., description="Executive CISO-level verdict, primary concerns, action window")
    system: Dict[str, Any] = Field(..., description="Target banking system context, asset type, criticality")
    system_metadata: Dict[str, Any] = Field(..., description="Alias for system")
    quantum_posture: Dict[str, Any] = Field(..., description="Technical quantum score, SNDL exposure, lattice readiness")
    classical_posture: Dict[str, Any] = Field(..., description="Classical cryptographic weaknesses, legacy ciphers, weak hashing")
    priority: Dict[str, Any] = Field(..., description="Priority score (0-100), band (P0-P3), and composite urgency")
    priority_factors: Dict[str, Any] = Field(..., description="Factor breakdown: BEF, TRF, Criticality, Sensitivity, Lifetime, Exposure, Migration")
    findings: List[NormalizedFinding] = Field(..., description="Normalized findings from all verification layers")
    key_protection_chain: Dict[str, Any] = Field(..., description="4-tier key hierarchy evaluation and weak links")
    crypto_agility: Dict[str, Any] = Field(..., description="Algorithm decoupling and parameter agility assessment")
    migration_impact: MigrationImpactAssessment = Field(..., description="Latency, PQC size, HSM, and connector evaluation")
    ranked_upgrade_plan: RankedUpgradePlan = Field(..., description="Ranked upgrade queue across banking systems")
    cbom: Dict[str, Any] = Field(..., description="CycloneDX Cryptographic Bill of Materials")
    evidence_gaps: List[Dict[str, Any]] = Field(..., description="Structured observability gaps (NOT_OBSERVABLE != VULNERABLE)")
    observability: Dict[str, Any] = Field(..., description="Verified boundary scope: observed vs declared vs not observable")
    what_if: Optional[Dict[str, Any]] = Field(default=None, description="Pre-computed or recent simulation impact results")
    what_if_results: Optional[Dict[str, Any]] = Field(default=None, description="Alias for what_if")
    audit: AuditRecord = Field(..., description="Tamper-evident cryptographic audit hash record")
    audit_metadata: AuditRecord = Field(..., description="Alias for audit")

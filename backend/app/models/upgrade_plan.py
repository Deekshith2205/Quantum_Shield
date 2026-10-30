"""Ranked Upgrade Plan Models.
Deterministic prioritized migration roadmap across representative banking systems.
"""

from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field


class RankedUpgradeItem(BaseModel):
    """Single prioritized banking system in the ranked upgrade queue."""
    rank: int = Field(..., description="Deterministic priority rank (1 = highest priority)")
    system_id: str = Field(..., description="Target banking system ID")
    system_name: str = Field(..., description="Target banking system human-readable name")
    system: str = Field(..., description="Alias for system_name")
    priority: str = Field(..., description="Priority band: P0, P1, P2, P3")
    priority_score: int = Field(..., description="Deterministic priority score (0-100)")
    quantum_score: int = Field(..., description="Technical quantum vulnerability score (0-100)")
    classical_score: int = Field(..., description="Technical classical vulnerability score (0-100)")
    criticality: str = Field(..., description="Business criticality level")
    sensitivity: str = Field(..., description="Data sensitivity level")
    data_lifetime: str = Field(..., description="Store Now, Decrypt Later (SNDL) retention horizon")
    lifetime: str = Field(..., description="Alias for data_lifetime")
    exposure: str = Field(..., description="Network exposure boundary")
    migration_impact: str = Field(..., description="Migration impact category (VERY_HIGH, HIGH, MEDIUM, LOW)")
    top_findings: List[str] = Field(default_factory=list, description="Top 3 most urgent vulnerabilities or weaknesses")
    key_protection_chain: Dict[str, str] = Field(default_factory=dict, description="Summary of the 4-tier key protection chain")
    crypto_agility: str = Field(default="NOT_OBSERVABLE", description="Crypto agility classification")
    evidence_gaps: List[str] = Field(default_factory=list, description="Structured observability gaps requiring internal manifests")
    recommended_migration: str = Field(..., description="Primary actionable migration intervention")
    recommended_upgrade: str = Field(..., description="Alias for recommended_migration")
    migration_complexity: str = Field(..., description="Effort and dependency timeline")
    estimated_migration_complexity: str = Field(..., description="Alias for migration_complexity")


class RankedUpgradePlan(BaseModel):
    """Complete ranked post-quantum migration queue across all modeled banking systems."""
    timestamp: str = Field(..., description="ISO 8601 generation timestamp")
    total_systems: int = Field(..., description="Total banking systems evaluated")
    p0_count: int = Field(..., description="Systems requiring immediate strategic migration")
    p1_count: int = Field(..., description="Systems in high priority window")
    p2_count: int = Field(..., description="Systems in planned medium term window")
    p3_count: int = Field(..., description="Systems in lifecycle monitoring")
    queue: List[RankedUpgradeItem] = Field(..., description="Ranked systems ordered by priority score descending")

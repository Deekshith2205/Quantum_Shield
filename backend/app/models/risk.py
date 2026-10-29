"""Multidimensional risk separation model.
Phase 0 & Phase 4B - Banking Security Audit & Key-Protection Risk Engine

Explicitly distinguishes:
- Quantum Exposure Risk (Shor/Grover cryptanalysis)
- Classical Security Risk (cert validity, deprecated algorithms, expired certs)
- Zero Trust Risk (perimeter vs continuous verification)
- Asset Criticality & Business Context (criticality, sensitivity, SNDL lifetime, exposure, migration effort)
- Key Protection Chain analysis (Data Encryption -> Key Wrapping -> Key Storage -> Authentication)
- Deterministic Migration Prioritization (P0, P1, P2, P3; 0-100 score)
"""

from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
from app.models.banking import (
    AssetCriticality,
    DataSensitivity,
    AssetExposure,
    DataLifetime,
    MigrationEffort,
)


class RiskDimensions(BaseModel):
    """
    Separates independent risk dimensions to prevent collapsing business context
    into raw technical finding scores. (Phase 0 baseline)
    """
    quantum_risk_score: int = Field(
        ...,
        ge=0,
        le=100,
        description="Quantum exposure risk score (100 - readiness_score; higher = higher exposure)"
    )
    quantum_readiness_score: int = Field(
        ...,
        ge=0,
        le=100,
        description="Quantum readiness score (0-100; higher = better readiness)"
    )
    classical_security_risk: str = Field(
        default="LOW",
        description="Classical TLS and PKI integrity risk: CRITICAL, HIGH, MEDIUM, LOW"
    )
    zero_trust_posture: str = Field(
        default="EDGE_ENCRYPTED_INTERNAL_UNKNOWN",
        description="Zero Trust operational posture"
    )
    asset_criticality: AssetCriticality = Field(
        ...,
        description="Business criticality of the asset (CRITICAL, HIGH, MEDIUM, LOW)"
    )
    description: str = Field(
        default="Multidimensional banking risk evaluation separating technical findings from asset context.",
        description="Risk dimension narrative summary"
    )


# ==============================================================================
# PHASE 4B: KEY-PROTECTION CHAIN & BANKING CRITICALITY RISK MODELS
# ==============================================================================

class KeyChainStatus(str, Enum):
    """Normalized cryptographic key hierarchy posture."""
    QUANTUM_READY = "QUANTUM_READY"
    PARTIALLY_QUANTUM_READY = "PARTIALLY_QUANTUM_READY"
    QUANTUM_EXPOSED = "QUANTUM_EXPOSED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class MigrationPriority(str, Enum):
    """
    Deterministic migration prioritization bands for banking infrastructure.
    Reflects migration urgency, NOT probability of compromise.
    """
    P0 = "P0"  # Immediate Strategic Migration (Score >= 85)
    P1 = "P1"  # High Priority Migration (Score 65-84)
    P2 = "P2"  # Planned Migration (Score 40-64)
    P3 = "P3"  # Monitor / Maintain (Score < 40)


class KeyChainAnalysis(BaseModel):
    """
    Structural analysis of the 4-tier cryptographic key hierarchy:
    Data Encryption -> Key Wrapping -> Key Storage -> Authentication / Master Key.
    Enforces the core rule: AES-256 is adequate; weak links lie in key wrapping and authentication.
    """
    status: KeyChainStatus = Field(..., description="Overall post-quantum posture of key hierarchy")
    weak_links: List[str] = Field(default_factory=list, description="Specific components vulnerable to cryptanalysis")
    data_encryption_status: str = Field(default="ADEQUATE_GROVER_RESILIENT")
    data_encryption_algorithm: Optional[str] = Field(default=None)
    key_wrapping_status: str = Field(default="UNKNOWN")
    key_wrapping_algorithm: Optional[str] = Field(default=None)
    key_storage_status: str = Field(default="UNKNOWN")
    key_storage_facility: Optional[str] = Field(default=None)
    authentication_status: str = Field(default="UNKNOWN")
    authentication_algorithm: Optional[str] = Field(default=None)
    primary_migration_dependencies: List[str] = Field(default_factory=list)
    notes: str = Field(default="")


class TechnicalRiskContext(BaseModel):
    """Normalized technical cryptographic and classical vulnerabilities (0-4 scale)."""
    quantum_risk_level: int = Field(..., ge=0, le=4, description="0=NONE, 1=LOW, 2=MEDIUM, 3=HIGH, 4=CRITICAL")
    quantum_risk_label: str = Field(..., description="NONE, LOW, MEDIUM, HIGH, CRITICAL")
    classical_risk_level: int = Field(..., ge=0, le=4)
    classical_risk_label: str = Field(...)
    governing_technical_risk: int = Field(..., ge=0, le=4, description="max(quantum, classical)")


class BusinessRiskContext(BaseModel):
    """Normalized business exposure dimensions (1-4 scale)."""
    criticality_score: int = Field(..., ge=1, le=4, description="LOW=1, MEDIUM=2, HIGH=3, CRITICAL=4")
    criticality_label: str
    sensitivity_score: int = Field(..., ge=1, le=4, description="PUBLIC=1, INTERNAL=2, CONFIDENTIAL=3, HIGHLY_SENSITIVE=4")
    sensitivity_label: str
    lifetime_score: int = Field(..., ge=1, le=4, description="SHORT=1, MEDIUM=2, LONG=3, VERY_LONG=4")
    lifetime_label: str
    exposure_score: int = Field(..., ge=1, le=4, description="RESTRICTED=1, INTERNAL=2, PARTNER=3, INTERNET=4")
    exposure_label: str
    migration_effort_score: int = Field(..., ge=1, le=4, description="LOW=1, MEDIUM=2, HIGH=3, VERY_HIGH=4")
    migration_effort_label: str
    business_exposure_factor: float = Field(..., ge=0.0, le=1.0, description="Normalized composite business factor (0.0-1.0)")


class RiskContributorItem(BaseModel):
    """Structured breakdown item showing individual factor contribution to priority."""
    factor: str = Field(..., description="Name of contributor: Quantum Risk, Criticality, etc.")
    score: int = Field(..., ge=0, le=4, description="Score on 0-4 or 1-4 scale")
    max_score: int = Field(default=4)
    label: str = Field(..., description="Display label (e.g. CRITICAL, VERY LONG)")
    weight_pct: int = Field(..., description="Percentage representation for visual UI bar")
    description: str = Field(default="", description="Contextual note")


class BankingRiskAssessment(BaseModel):
    """
    Complete Banking-Aware Risk & Migration Prioritization Result.
    Answers: Which banking systems should be migrated first, and why?
    """
    asset_id: str
    asset_name: str
    system_type: str
    technical_risk: TechnicalRiskContext
    business_context: BusinessRiskContext
    key_protection: KeyChainAnalysis
    migration_priority: MigrationPriority
    priority_score: int = Field(..., ge=0, le=100, description="Deterministic 0-100 migration priority score")
    priority_band_label: str = Field(..., description="Immediate Strategic Migration, High Priority, etc.")
    contributors: List[RiskContributorItem] = Field(default_factory=list)
    explanation: str = Field(..., description="Articulate, deterministic 'Why this priority?' narrative")
    recommended_planning_window: str = Field(..., description="e.g. Q1-Q2 Next Fiscal Year")
    created_at: Optional[str] = None

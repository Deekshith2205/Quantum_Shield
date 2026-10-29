"""Multidimensional risk separation model.
Phase 0 - Banking Security Audit Architecture

Explicitly distinguishes:
- Quantum Exposure Risk (Shor/Grover cryptanalysis)
- Classical Security Risk (cert validity, deprecated algorithms, expired certs)
- Zero Trust Risk (perimeter vs continuous verification)
- Asset Criticality (business context)
"""

from enum import Enum
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field
from app.models.banking import AssetCriticality


class RiskDimensions(BaseModel):
    """
    Separates independent risk dimensions to prevent collapsing business context
    into raw technical finding scores.
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


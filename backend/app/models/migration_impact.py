"""Migration Impact & Crypto-Agility Models.
Evaluates latency sensitivity, PQC size impact, HSM dependency, legacy connectors, and crypto-agility.
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class MigrationImpactAssessment(BaseModel):
    """
    Structured, explainable evaluation of real migration complexity and performance factors.
    """
    system_id: str = Field(..., description="Target banking system ID")
    latency_sensitivity: str = Field(..., description="HIGH (e.g. UPI/ATM/Cards), MEDIUM, or LOW")
    latency_rationale: str = Field(..., description="Operational rationale for latency classification")
    pqc_size_impact: str = Field(..., description="Qualitative category: HIGH, MEDIUM, or LOW packet overhead")
    pqc_size_rationale: str = Field(..., description="Impact of ML-KEM-768 (1184B) and ML-DSA-65 (3309B) public keys & signatures")
    hsm_dependency: str = Field(..., description="HEAVY (Physical Appliance), MODERATE (Cloud KMS), or MINIMAL (Software)")
    hsm_rationale: str = Field(..., description="Firmware and hardware upgrade dependencies")
    legacy_connectors: List[str] = Field(default_factory=list, description="Legacy protocols, fixed APIs, or proprietary bridges")
    crypto_agility: str = Field(..., description="CONFIGURABLE, MODERATE, or HARDCODED_MONOLITHIC")
    crypto_agility_rationale: str = Field(..., description="Degree of cryptographic flexibility without code redeployments")
    composite_migration_impact: str = Field(..., description="VERY_HIGH, HIGH, MEDIUM, or LOW")
    recommendations: List[str] = Field(default_factory=list, description="Architectural migration recommendations")

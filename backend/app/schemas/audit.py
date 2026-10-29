"""Pydantic schemas for the Banking Security Audit API contracts.
Phase 0 - Banking Security Audit Architecture
"""

from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

from app.models.banking import (
    BankingAsset,
    BankingAssetType,
    AssetCriticality,
    DataSensitivity,
    AssetExposure,
    TrustZone,
)
from app.models.audit import AuditFinding, AuditSummary
from app.models.zero_trust import ZeroTrustAssessment
from app.models.risk import RiskDimensions, BankingRiskAssessment
from app.schemas.scan import ScanResponse


class AuditRequest(BaseModel):
    """Request payload for a banking security audit."""
    domain: str = Field(..., description="Target banking hostname / FQDN (e.g. ebanking.chase.com)")
    port: int = Field(default=443, ge=1, le=65535, description="Port number (defaults to 443)")
    probe_pqc: bool = Field(default=False, description="Whether to probe for hybrid post-quantum key exchange support")
    asset_id: Optional[str] = Field(default=None, description="Pre-configured synthetic profile or existing banking asset ID")
    asset_name: Optional[str] = Field(default=None, description="Custom asset name (e.g. Retail Core Gateway)")
    asset_type: Optional[BankingAssetType] = Field(default=None, description="Asset functional type")
    criticality: Optional[AssetCriticality] = Field(default=None, description="Business criticality override")
    data_sensitivity: Optional[DataSensitivity] = Field(default=None, description="Data sensitivity override")
    exposure: Optional[AssetExposure] = Field(default=None, description="Network exposure override")
    trust_zone: Optional[TrustZone] = Field(default=None, description="Trust zone override")
    tags: List[str] = Field(default_factory=list, description="Categorization tags")


class AuditResponse(BaseModel):
    """Unified Banking Security Audit Response."""
    asset: BankingAsset = Field(..., description="Target banking asset business model")
    audit: AuditSummary = Field(..., description="Aggregated audit summary metrics")
    findings: List[AuditFinding] = Field(..., description="Normalized evidence-backed audit findings")
    crypto: ScanResponse = Field(..., description="Underlying passive TLS post-quantum assessment")
    zero_trust: ZeroTrustAssessment = Field(..., description="NIST SP 800-207 Zero Trust pillar assessment")
    risk: RiskDimensions = Field(..., description="Multidimensional risk and criticality breakdown")
    banking_risk: Optional[BankingRiskAssessment] = Field(default=None, description="Banking criticality and key protection risk assessment")


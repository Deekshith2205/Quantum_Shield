"""Normalized Finding Data Model.
Phase 4 Integration Layer - Unified representation across TLS, Crypto Misuse, Configuration, and Profile declarations.
"""

from typing import Optional, Dict, Any
from pydantic import BaseModel, Field


class NormalizedFinding(BaseModel):
    """
    Unified normalized finding conforming to Phase 4 integration criteria.
    Preserves rule_id, title, value, role, source, source_file, source_line,
    evidence_status, severity, risk, message, recommendation, system_id, asset_id, layer, and metadata.
    """
    rule_id: str = Field(..., description="Unique rule or vulnerability identifier")
    title: str = Field(..., description="Finding title")
    value: str = Field(..., description="Observed or declared value")
    role: str = Field(..., description="Cryptographic or architectural role")
    source: str = Field(..., description="Origin of verification data (EXTERNAL_SCAN, CONFIGURATION_FILE, CODE_ANALYSIS, OPERATOR_DECLARED, INFERRED)")
    source_file: Optional[str] = Field(default=None, description="Source file path where finding was detected")
    source_line: Optional[int] = Field(default=None, description="Line number where finding was detected")
    evidence_status: str = Field(..., description="Evidence state (OBSERVED, INFERRED, NOT_OBSERVABLE, CAPABILITY_PROBED, CLASSICAL_ONLY_OBSERVED, PROBED_UNSUPPORTED)")
    severity: str = Field(..., description="Finding severity (CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL)")
    risk: str = Field(..., description="Risk domain (QUANTUM, CLASSICAL, BOTH)")
    message: str = Field(..., description="Detailed narrative explanation")
    recommendation: str = Field(..., description="Prescriptive remediation guidance")

    # Optional contextual attributes
    system_id: Optional[str] = Field(default=None, description="Associated banking system identifier")
    asset_id: Optional[str] = Field(default=None, description="Target asset identifier")
    layer: Optional[str] = Field(default=None, description="Architecture layer (EDGE, API_GATEWAY, SERVICE_TO_SERVICE, DATA_AND_KEYS, ADMINISTRATIVE)")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Supplementary technical metadata")

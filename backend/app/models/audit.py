"""Generic Audit Layer model and evidence semantics.
Phase 0 - Banking Security Audit Architecture
"""

from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class AuditDomain(str, Enum):
    CRYPTOGRAPHY = "CRYPTOGRAPHY"
    QUANTUM_SECURITY = "QUANTUM_SECURITY"
    ZERO_TRUST = "ZERO_TRUST"
    IDENTITY = "IDENTITY"
    ACCESS_CONTROL = "ACCESS_CONTROL"
    NETWORK_SECURITY = "NETWORK_SECURITY"
    CONFIGURATION = "CONFIGURATION"
    CLASSICAL_SECURITY = "CLASSICAL_SECURITY"


class FindingSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class RemediationPriority(str, Enum):
    P0 = "P0"  # Immediate Remediation
    P1 = "P1"  # High Priority
    P2 = "P2"  # Medium Priority
    P3 = "P3"  # Low Priority / Monitor


class ObservabilityState(str, Enum):
    """
    Evidence observability classification.
    CRITICAL INVARIANT: NOT_OBSERVABLE != VULNERABLE.
    Never assign a vulnerability merely because a cryptographic or architectural
    property cannot be observed externally.
    """
    OBSERVED = "OBSERVED"
    NOT_OBSERVABLE = "NOT_OBSERVABLE"
    CAPABILITY_PROBED = "CAPABILITY_PROBED"
    PROBED_UNSUPPORTED = "PROBED_UNSUPPORTED"
    CLASSICAL_ONLY_OBSERVED = "CLASSICAL_ONLY_OBSERVED"


class AuditFinding(BaseModel):
    """
    Unified Evidence-Backed Audit Finding.
    Answers: What did we find? Where? What domain? What control?
    How do we know? How serious is it? What should be done?
    """
    id: str = Field(..., description="Unique finding identifier")
    asset_id: str = Field(..., description="Associated banking asset ID")
    domain: AuditDomain = Field(..., description="Audit security domain")
    control: str = Field(..., description="Security control or requirement being audited")
    title: str = Field(..., description="Concise finding headline")
    severity: FindingSeverity = Field(..., description="Technical severity of the security observation")
    evidence: str = Field(..., description="Observed cryptographic or architectural value")
    evidence_source: str = Field(..., description="Origin of verification data (e.g. Leaf Certificate, TLS Handshake)")
    observability: ObservabilityState = Field(..., description="Classification of evidence observability")
    impact: str = Field(default="", description="Technical and business impact on banking operations")
    recommendation: str = Field(..., description="Actionable technical remediation guidance")
    remediation_priority: RemediationPriority = Field(..., description="Remediation urgency (P0 to P3)")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Supplementary technical metadata")


class AuditSummary(BaseModel):
    """Aggregated audit statistics across domains and severities."""
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    informational_count: int
    domains_covered: List[AuditDomain]
    observability_breakdown: Dict[str, int]


"""Audit Hash Chain Data Models.
Provides cryptographic tamper evidence and verifiable integrity chains for assessments.
"""

from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field


class AuditRecord(BaseModel):
    """
    Immutable audit ledger record linking an assessment to a cryptographic hash chain.
    """
    record_id: str = Field(..., description="Unique record UUID or identifier")
    assessment_id: str = Field(..., description="Target assessment or system identifier")
    assessment_hash: str = Field(..., description="SHA-256 hash of canonicalized assessment payload")
    previous_hash: str = Field(..., description="SHA-256 hash of previous audit record ('0'*64 for genesis)")
    current_hash: str = Field(..., description="SHA-256 hash of (canonical_assessment + previous_hash)")
    timestamp: str = Field(..., description="ISO 8601 generation timestamp")
    schema_version: str = Field(default="1.0.0", description="Audit schema version")
    canonical_payload: Optional[str] = Field(default=None, description="Canonical JSON string of assessment payload")


class AuditVerificationResult(BaseModel):
    """Result of verifying a single audit record or chain."""
    valid: bool = Field(..., description="True if cryptographic verification succeeded")
    record_id: Optional[str] = Field(default=None, description="Record identifier verified")
    error: Optional[str] = Field(default=None, description="Reason for validation failure if invalid")
    records_checked: int = Field(default=1, description="Number of chained records verified")
    details: Dict[str, Any] = Field(default_factory=dict, description="Supplementary diagnostic metadata")

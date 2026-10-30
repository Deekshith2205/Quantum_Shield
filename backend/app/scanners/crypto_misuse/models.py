"""Data models for QuantumShield Crypto-Misuse Scanner.
Subsystem: Backend Crypto-Misuse Static Analysis.
"""

from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, model_validator


class EvidenceStatus(str, Enum):
    """
    Evidence observability status.
    CRITICAL INVARIANT: NOT_OBSERVABLE != VULNERABLE.
    Never treat NOT_OBSERVABLE as a security vulnerability.
    """
    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    NOT_OBSERVABLE = "NOT_OBSERVABLE"


class FindingSeverity(str, Enum):
    """Standard vulnerability severity ratings."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class CryptoRole(str, Enum):
    """
    Cryptographic role classification explaining WHY the construct matters.
    Reuses terminology compatible with QuantumShield's key-protection architecture.
    """
    BULK_ENCRYPTION = "BULK_ENCRYPTION"
    KEY_ESTABLISHMENT = "KEY_ESTABLISHMENT"
    KEY_WRAPPING = "KEY_WRAPPING"
    DIGITAL_SIGNATURE = "DIGITAL_SIGNATURE"
    PASSWORD_HASHING = "PASSWORD_HASHING"
    RANDOMNESS = "RANDOMNESS"
    CERTIFICATE_VALIDATION = "CERTIFICATE_VALIDATION"
    NONCE_IV = "NONCE_IV"
    AUTHENTICATION = "AUTHENTICATION"
    SECRET_STORAGE = "SECRET_STORAGE"
    CRYPTO_AGILITY = "CRYPTO_AGILITY"
    KEY = "KEY"
    SECRET = "SECRET"
    CREDENTIAL = "CREDENTIAL"
    HASH = "HASH"
    NONCE = "NONCE"
    IV = "IV"


class RiskCategory(str, Enum):
    """
    Deterministic risk category distinguishing quantum exposure from classical flaws.
    Prevents mixing classical implementation bugs into quantum threat metrics.
    """
    QUANTUM_SECURITY = "QUANTUM_SECURITY"
    CLASSICAL_SECURITY = "CLASSICAL_SECURITY"
    CRYPTO_AGILITY = "CRYPTO_AGILITY"
    SECRET_EXPOSURE = "SECRET_EXPOSURE"
    IMPLEMENTATION_SECURITY = "IMPLEMENTATION_SECURITY"


class ConfidenceLevel(str, Enum):
    """Confidence level of static detection."""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class SupportedLanguage(str, Enum):
    """Supported source code languages."""
    PYTHON = "python"
    JAVA = "java"
    JAVASCRIPT = "javascript"
    PHP = "php"
    UNKNOWN = "unknown"


class MisuseFinding(BaseModel):
    """
    Evidence-backed crypto misuse finding.
    Represents an observed or inferred cryptographic misuse in sample banking code.
    """
    rule_id: str = Field(..., description="Unique rule identifier, e.g. MISUSE-ECB-MODE")
    title: str = Field(..., description="Concise finding headline")
    description: str = Field(default="", description="Detailed technical description of the finding")
    language: str = Field(..., description="Source code language (python, java, javascript, php)")
    file: str = Field(..., description="File path relative to scan target or filename")
    line: int = Field(..., ge=1, description="1-based line number")
    column: Optional[int] = Field(default=None, description="1-based column number if observable")
    matched_value: str = Field(..., description="Observed matched code snippet or sanitized pattern")
    value: str = Field(default="", description="Alias for matched_value")
    source_file: str = Field(default="", description="Alias for file")
    line_number: int = Field(default=1, description="Alias for line")
    role: str = Field(..., description="Cryptographic role: BULK_ENCRYPTION, RANDOMNESS, etc.")
    risk: str = Field(..., description="Risk category: QUANTUM_SECURITY, CLASSICAL_SECURITY, etc.")
    severity: str = Field(..., description="Severity level: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL")
    evidence_status: str = Field(
        default="OBSERVED",
        description="Evidence status: OBSERVED, INFERRED, or NOT_OBSERVABLE"
    )
    confidence: str = Field(default="HIGH", description="Detection confidence: HIGH, MEDIUM, LOW")
    recommendation: str = Field(..., description="Actionable remediation guidance")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Supplementary context")

    @model_validator(mode="before")
    @classmethod
    def populate_aliases(cls, data: Any) -> Any:
        if isinstance(data, dict):
            # Sync value <-> matched_value
            if "matched_value" in data and not data.get("value"):
                data["value"] = data["matched_value"]
            elif "value" in data and not data.get("matched_value"):
                data["matched_value"] = data["value"]

            # Sync file <-> source_file
            if "file" in data and not data.get("source_file"):
                data["source_file"] = data["file"]
            elif "source_file" in data and not data.get("file"):
                data["file"] = data["source_file"]

            # Sync line <-> line_number
            if "line" in data and not data.get("line_number"):
                data["line_number"] = data["line"]
            elif "line_number" in data and not data.get("line"):
                data["line"] = data["line_number"]
        return data


class ScanSummary(BaseModel):
    """Summary statistics for a crypto-misuse scan."""
    total_findings: int = 0
    by_severity: Dict[str, int] = Field(default_factory=dict)
    by_risk: Dict[str, int] = Field(default_factory=dict)
    by_evidence_status: Dict[str, int] = Field(default_factory=dict)
    by_role: Dict[str, int] = Field(default_factory=dict)
    by_language: Dict[str, int] = Field(default_factory=dict)


class ScanResult(BaseModel):
    """Complete serialized scan output for sample banking systems."""
    findings: List[MisuseFinding] = Field(default_factory=list)
    files_scanned: int = 0
    rules_evaluated: int = 0
    summary: ScanSummary = Field(default_factory=ScanSummary)
    scan_duration_ms: float = 0.0


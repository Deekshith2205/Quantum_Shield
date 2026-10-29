"""Pydantic schemas for QuantumShield API contracts and internal models.
Phase 2B - Assessment Intelligence
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

from app.models.banking import BankingAsset
from app.models.audit import AuditFinding
from app.models.zero_trust import ZeroTrustAssessment


class ScanRequest(BaseModel):
    domain: str = Field(..., description="Target domain or hostname (e.g. example.com)")
    port: int = Field(default=443, ge=1, le=65535, description="Port number (defaults to 443)")
    probe_pqc: bool = Field(default=False, description="Whether to perform an active TLS 1.3 hybrid PQC capability probe if default is classical")
    asset_id: Optional[str] = Field(default=None, description="Optional banking asset / profile ID to associate with the scan")


class TargetInfo(BaseModel):
    domain: str
    port: int
    resolved_ip: str
    ip_version: str
    scan_timestamp: str
    connection_time_ms: float
    all_resolved_ips: List[str] = Field(default_factory=list)


class CertificateSummary(BaseModel):
    subject_cn: Optional[str] = None
    issuer_cn: Optional[str] = None
    public_key_algorithm: str
    key_size_bits: Optional[int] = None
    curve_name: Optional[str] = None
    signature_algorithm: str
    fingerprint_sha256: str = ""
    not_valid_after: str


class CertificateInfo(BaseModel):
    subject_cn: Optional[str] = None
    subject_org: Optional[str] = None
    subject_alt_names: List[str] = Field(default_factory=list)
    issuer_cn: Optional[str] = None
    issuer_org: Optional[str] = None
    serial_number: str
    fingerprint_sha256: str
    not_valid_before: str
    not_valid_after: str
    days_remaining: int
    is_expired: bool
    public_key_algorithm: str
    key_size_bits: Optional[int] = None
    curve_name: Optional[str] = None
    signature_algorithm: str
    signature_hash_algorithm: Optional[str] = None
    chain_length: int
    chain_certificates: List[CertificateSummary] = Field(default_factory=list)
    verification_status: str
    is_trusted: bool


class PqcKeyExchangeEvidence(BaseModel):
    raw_group: str = Field(default="Not observable", description="Negotiated or probed key exchange group")
    status: str = Field(default="NOT_OBSERVABLE", description="OBSERVED, CAPABILITY_PROBED, CLASSICAL_ONLY_OBSERVED, PROBED_UNSUPPORTED, NOT_OBSERVABLE")
    classical_component: Optional[str] = Field(default=None, description="Underlying classical key agreement component (e.g. X25519, P-256)")
    pqc_component: Optional[str] = Field(default=None, description="Underlying post-quantum component (e.g. ML-KEM-768)")
    is_hybrid: bool = Field(default=False, description="True if key exchange combines classical ECDHE with NIST FIPS 203 PQC KEM")
    source: str = Field(default="TLS 1.3 KeyShare", description="Observation origin")
    confidence: str = Field(default="HIGH", description="Confidence level: HIGH, MEDIUM, LOW, NONE")
    probe_attempted: bool = Field(default=False, description="True if an active capability probe was attempted")
    requested_group: Optional[str] = Field(default=None, description="Group requested in active capability probe")
    probe_result: Optional[str] = Field(default=None, description="Result of probe: ACCEPTED, REJECTED_UNSUPPORTED, etc.")
    details: Optional[str] = Field(default=None, description="Technical diagnostic or observation explanation")


class TlsInfo(BaseModel):
    negotiated_protocol: str
    negotiated_cipher: str
    cipher_bits: int
    alpn_protocol: Optional[str] = None
    session_reused: bool
    key_exchange_value: str = Field(default="Not observable", description="Observed key exchange name or 'Not observable'")
    key_exchange_evidence: str = Field(default="NOT_OBSERVABLE", description="OBSERVED, INFERRED, or NOT_OBSERVABLE")
    key_exchange_inferred: Optional[str] = None
    symmetric_encryption_inferred: Optional[str] = None
    hash_mac_inferred: Optional[str] = None
    pqc_evidence: Optional[PqcKeyExchangeEvidence] = Field(default=None, description="Observed or probed TLS 1.3 KeyShare / PQC telemetry")


class NormalizedCryptoMechanism(BaseModel):
    role: str = Field(..., description="Role of cryptographic mechanism: e.g. Certificate Public Key, Key Exchange, etc.")
    value: str = Field(..., description="Exact algorithm value or 'Not observable'")
    source: str = Field(..., description="Evidence source, e.g. TLS Leaf Certificate")
    evidence: str = Field(..., description="Evidence classification: OBSERVED, INFERRED, or NOT_OBSERVABLE")
    component: str  # certificate_public_key, certificate_signature, tls_key_exchange, etc.
    algorithm_family: str  # RSA, ECC, AES, SHA-2, ML-KEM, UNKNOWN, etc.
    algorithm_name: str  # RSA-2048, ECDSA P-256, AES-256-GCM, Not observable, etc.
    category: str  # public_key, signature, key_exchange, symmetric_cipher, hash, protocol
    key_size: Optional[int] = None
    curve: Optional[str] = None
    observability: str  # OBSERVED, INFERRED, NOT_OBSERVABLE
    evidence_source: str  # TLS server certificate, TLS handshake negotiation, etc.
    raw_observed_value: str


class QuantumFinding(BaseModel):
    id: str
    title: str
    role: str = Field(default="", description="Cryptographic role, e.g. Certificate Public Key")
    value: str = Field(default="", description="Observed/evaluated value, e.g. RSA-2048")
    source: str = Field(default="", description="Source of evidence, e.g. TLS Leaf Certificate")
    evidence: str = Field(default="OBSERVED", description="OBSERVED, INFERRED, or NOT_OBSERVABLE")
    component: str
    algorithm: str
    category: str
    quantum_threat: str = Field(default="", description="Shor's algorithm, Grover's algorithm, SNDL, or None")
    quantum_threat_vector: str = Field(default="", description="Detailed threat vector")
    risk_level: str = Field(..., description="CRITICAL, HIGH, MEDIUM, LOW, or INFORMATIONAL")
    security_impact: str = Field(default="", description="Detailed technical impact of the quantum vulnerability")
    reason: str = Field(default="", description="Concise rationale")
    recommendation: str = Field(..., description="Actionable technical recommendation")
    migration_target: str = Field(default="", description="Target post-quantum algorithm, e.g. ML-DSA / SLH-DSA")
    priority: str = Field(default="P1", description="P0 (Immediate), P1 (High), P2 (Medium), P3 (Monitor)")
    priority_score: int = Field(default=50, description="0 to 100 priority score")
    observed_from: str = Field(default="", description="Evidence location")
    observability: str = Field(default="OBSERVED", description="OBSERVED, INFERRED, or NOT_OBSERVABLE")
    target_pqc_standard: Optional[str] = None


class CategoryScoreBreakdown(BaseModel):
    certificates: int = Field(..., description="Certificate & Digital Signatures readiness (0-100)")
    key_establishment: int = Field(..., description="Key Establishment readiness (0-100)")
    symmetric_encryption: int = Field(..., description="Symmetric Encryption readiness (0-100)")
    hashing: int = Field(..., description="Hashing & Integrity readiness (0-100)")
    tls_configuration: int = Field(..., description="TLS Configuration readiness (0-100)")


class ScoreBreakdownItem(BaseModel):
    factor: str
    impact: str
    points: int
    explanation: str


class QuantumScore(BaseModel):
    score: int = Field(
        ...,
        description="Quantum Readiness Score (0-100). 0 = extremely poor quantum readiness, 100 = excellent quantum readiness."
    )
    readiness_score: int = Field(
        ...,
        description="Quantum Readiness Score (0-100). Higher is strictly better readiness."
    )
    exposure_risk_score: int = Field(
        ...,
        description="Quantum Exposure Risk Score (100 - readiness_score). Lower is lower risk."
    )
    grade: str  # Excellent, Good, Moderate, Needs Improvement, Critical
    summary: str
    category_breakdown: CategoryScoreBreakdown
    score_breakdown: List[ScoreBreakdownItem] = Field(default_factory=list)
    methodology_disclaimer: str
    formula_description: str


class RoleCategoryAssessment(BaseModel):
    category_id: str  # certificates, key_establishment, symmetric_encryption, hashing, tls_configuration
    category_name: str  # Certificate & Digital Signatures, Key Establishment, etc.
    status: str  # EXCELLENT, GOOD, MODERATE, HIGH RISK, CRITICAL, INFORMATIONAL
    readiness_score: int  # 0-100
    weight_percentage: int  # e.g. 30, 30, 20, 10, 10
    observed_value: str
    evidence: str  # OBSERVED, INFERRED, NOT_OBSERVABLE
    source: str
    quantum_threat: str
    migration_target: str
    priority: str  # P0, P1, P2, P3
    recommended_action: str
    findings: List[QuantumFinding] = Field(default_factory=list)


class ExecutiveSummary(BaseModel):
    domain: str
    readiness_verdict: str
    primary_concern: str
    secondary_concern: Optional[str] = None
    visibility_limitations: str
    recommended_next_steps: List[str] = Field(default_factory=list)
    full_text: str


class MigrationStep(BaseModel):
    priority: str = Field(default="P1", description="P0, P1, P2, P3")
    priority_rank: int = Field(..., description="1, 2, 3...")
    title: str
    affected_component: str
    current_mechanism: str
    reason: str
    recommended_target: str
    migration_approach: str
    evidence: str = Field(default="OBSERVED", description="OBSERVED, INFERRED, or NOT_OBSERVABLE")
    urgency: str = Field(default="High Priority", description="Immediate, High Priority, Medium Priority, Monitor")
    target_standards: List[str] = Field(default_factory=list)
    # Backwards compatibility fields:
    risk_level: Optional[str] = None
    why_it_matters: Optional[str] = None
    recommended_action: Optional[str] = None
    migration_urgency: Optional[str] = None
    observability: Optional[str] = None


class ObservabilityScope(BaseModel):
    observed_externally: List[str] = Field(default_factory=list)
    potentially_inferred: List[str] = Field(default_factory=list)
    not_externally_observable: List[str] = Field(default_factory=list)


class ScanResponse(BaseModel):
    target: TargetInfo
    scan_status: str
    certificate: CertificateInfo
    tls: TlsInfo
    cryptography: List[NormalizedCryptoMechanism]
    findings: List[QuantumFinding]
    score: QuantumScore
    role_assessments: List[RoleCategoryAssessment] = Field(default_factory=list)
    executive_summary: ExecutiveSummary
    migration_plan: List[MigrationStep]
    observability_scope: ObservabilityScope
    not_observable_notes: List[str]
    banking_asset: Optional[BankingAsset] = None
    audit_findings: List[AuditFinding] = Field(default_factory=list)
    zero_trust: Optional[ZeroTrustAssessment] = None


class ErrorResponse(BaseModel):
    error: str
    detail: str
    target_domain: Optional[str] = None

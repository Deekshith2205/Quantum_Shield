"""Crypto to Audit Layer Adapter.
Phase 0 - Banking Security Audit Architecture

Maps existing cryptographic facts and QuantumFindings into the Audit Layer,
preserving role separation and enforcing the core invariant:
NOT_OBSERVABLE != VULNERABLE.
"""

from typing import List, Dict, Any, Tuple
from app.schemas.scan import QuantumFinding
from app.models.audit import (
    AuditFinding,
    AuditDomain,
    FindingSeverity,
    RemediationPriority,
    ObservabilityState,
    AuditSummary,
)


def map_severity(risk_level: str, observability: ObservabilityState) -> FindingSeverity:
    """
    Maps risk levels to FindingSeverity while enforcing:
    NOT_OBSERVABLE != VULNERABLE.
    Unobservable items are classified as INFORMATIONAL rather than high/critical.
    """
    if observability == ObservabilityState.NOT_OBSERVABLE:
        return FindingSeverity.INFORMATIONAL

    clean = (risk_level or "").upper()
    if clean == "CRITICAL":
        return FindingSeverity.CRITICAL
    elif clean == "HIGH":
        return FindingSeverity.HIGH
    elif clean == "MEDIUM":
        return FindingSeverity.MEDIUM
    elif clean == "LOW":
        return FindingSeverity.LOW
    else:
        return FindingSeverity.INFORMATIONAL


def map_priority(priority_str: str) -> RemediationPriority:
    clean = (priority_str or "").upper()
    if clean.startswith("P0"):
        return RemediationPriority.P0
    elif clean.startswith("P1"):
        return RemediationPriority.P1
    elif clean.startswith("P2"):
        return RemediationPriority.P2
    else:
        return RemediationPriority.P3


def map_observability(evidence_str: str) -> ObservabilityState:
    clean = (evidence_str or "").upper()
    if clean == "NOT_OBSERVABLE":
        return ObservabilityState.NOT_OBSERVABLE
    elif clean == "CAPABILITY_PROBED":
        return ObservabilityState.CAPABILITY_PROBED
    elif clean == "PROBED_UNSUPPORTED":
        return ObservabilityState.PROBED_UNSUPPORTED
    elif clean == "CLASSICAL_ONLY_OBSERVED":
        return ObservabilityState.CLASSICAL_ONLY_OBSERVED
    else:
        return ObservabilityState.OBSERVED


def map_domain(category: str, quantum_threat: str, title: str) -> AuditDomain:
    """Classifies finding into the appropriate AuditDomain."""
    title_lower = title.lower()
    if any(k in title_lower for k in ["expired", "untrusted", "self-signed", "validation failed"]):
        return AuditDomain.CLASSICAL_SECURITY
    if quantum_threat and quantum_threat.lower() not in ["none", ""]:
        return AuditDomain.QUANTUM_SECURITY
    if category in ["symmetric_cipher", "hash", "protocol"]:
        return AuditDomain.CRYPTOGRAPHY
    return AuditDomain.QUANTUM_SECURITY


def map_quantum_finding_to_audit_finding(finding: QuantumFinding, asset_id: str) -> AuditFinding:
    """
    Converts an existing QuantumFinding into an AuditFinding.
    Preserves all technical evidence while enriching with Audit Layer context.
    """
    obs_state = map_observability(finding.evidence or finding.observability)
    severity = map_severity(finding.risk_level, obs_state)
    priority = map_priority(finding.priority)
    domain = map_domain(finding.category, finding.quantum_threat, finding.title)

    control_name = finding.role if finding.role else finding.component.replace("_", " ").title()
    if finding.category == "key_exchange" or "key establishment" in control_name.lower():
        control_name = "TLS Key Establishment"
        domain = AuditDomain.QUANTUM_SECURITY

    metadata = {
        "quantum_threat": finding.quantum_threat,
        "quantum_threat_vector": finding.quantum_threat_vector,
        "migration_target": finding.migration_target,
        "component": finding.component,
        "algorithm": finding.algorithm,
        "original_risk_level": finding.risk_level,
    }

    return AuditFinding(
        id=finding.id,
        asset_id=asset_id,
        domain=domain,
        control=control_name,
        title=finding.title,
        severity=severity,
        evidence=finding.value if finding.value else finding.algorithm,
        evidence_source=finding.source if finding.source else "TLS Telemetry",
        observability=obs_state,
        impact=finding.security_impact if finding.security_impact else finding.reason,
        recommendation=finding.recommendation,
        remediation_priority=priority,
        metadata=metadata,
    )


def map_findings_to_audit_layer(findings: List[QuantumFinding], asset_id: str) -> List[AuditFinding]:
    """Translates a collection of findings into AuditFindings."""
    return [map_quantum_finding_to_audit_finding(f, asset_id) for f in findings]


def summarize_audit_findings(findings: List[AuditFinding]) -> AuditSummary:
    """Aggregates audit metrics across findings."""
    total = len(findings)
    critical_count = sum(1 for f in findings if f.severity == FindingSeverity.CRITICAL)
    high_count = sum(1 for f in findings if f.severity == FindingSeverity.HIGH)
    medium_count = sum(1 for f in findings if f.severity == FindingSeverity.MEDIUM)
    low_count = sum(1 for f in findings if f.severity == FindingSeverity.LOW)
    info_count = sum(1 for f in findings if f.severity == FindingSeverity.INFORMATIONAL)

    domains = sorted(list({f.domain for f in findings}))

    obs_breakdown = {
        "OBSERVED": sum(1 for f in findings if f.observability == ObservabilityState.OBSERVED),
        "NOT_OBSERVABLE": sum(1 for f in findings if f.observability == ObservabilityState.NOT_OBSERVABLE),
        "CAPABILITY_PROBED": sum(1 for f in findings if f.observability == ObservabilityState.CAPABILITY_PROBED),
        "PROBED_UNSUPPORTED": sum(1 for f in findings if f.observability == ObservabilityState.PROBED_UNSUPPORTED),
        "CLASSICAL_ONLY_OBSERVED": sum(1 for f in findings if f.observability == ObservabilityState.CLASSICAL_ONLY_OBSERVED),
    }

    return AuditSummary(
        total_findings=total,
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        informational_count=info_count,
        domains_covered=domains,
        observability_breakdown=obs_breakdown,
    )


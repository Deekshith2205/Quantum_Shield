"""Unified Finding Normalization Pipeline.
Integrates findings across TLS Scanner, Crypto Misuse Scanner, Configuration Scanner,
and Banking Profile declarations into a standardized NormalizedFinding collection.
Enforces strict evidence semantics: NOT_OBSERVABLE != VULNERABLE.
"""

from typing import List, Dict, Any, Optional
from app.models.findings import NormalizedFinding
from app.models.banking import BankingAsset, EvidenceItem


def sanitize_secret_value(val: str) -> str:
    """Strictly redacts private keys and secret material from finding values."""
    val_u = str(val).upper()
    if "BEGIN" in val_u and "PRIVATE KEY" in val_u:
        return "[REDACTED_PRIVATE_KEY_MATERIAL]"
    if "AKIA" in str(val):
        return "[REDACTED_API_KEY]"
    return str(val)


def normalize_tls_finding(finding: Any, system_id: Optional[str] = None) -> NormalizedFinding:
    """Normalizes a raw TLS finding into a NormalizedFinding."""
    fid = getattr(finding, "id", getattr(finding, "rule_id", "TLS-FINDING"))
    title = getattr(finding, "title", "TLS Observation")
    role = getattr(finding, "role", getattr(finding, "category", "Perimeter Cryptography"))
    val = sanitize_secret_value(str(getattr(finding, "value", getattr(finding, "algorithm", "N/A"))))
    src = getattr(finding, "source", "EXTERNAL_SCAN")
    sev = getattr(finding, "risk_level", getattr(finding, "severity", "MEDIUM"))
    ev = getattr(finding, "evidence", getattr(finding, "observability", getattr(finding, "evidence_status", "OBSERVED")))

    # Determine risk category (Quantum vs Classical)
    threat = str(getattr(finding, "quantum_threat", getattr(finding, "quantum_threat_vector", ""))).upper()
    title_u = title.upper()
    val_u = val.upper()
    if any(q in title_u or q in threat or q in val_u for q in ["SHOR", "QUANTUM", "PQC", "ML-KEM", "ML-DSA", "RSA", "ECDH", "ECDSA", "X25519"]):
        risk = "QUANTUM"
    elif any(c in title_u or c in threat or c in val_u for c in ["MD5", "SHA-1", "3DES", "RC4", "TLS 1.0", "TLS 1.1", "EXPIRED", "DES"]):
        risk = "CLASSICAL"
    else:
        risk = "QUANTUM" if getattr(finding, "is_quantum_vulnerable", True) else "CLASSICAL"

    msg = getattr(finding, "security_impact", getattr(finding, "reason", getattr(finding, "message", title)))
    rec = getattr(finding, "recommendation", "Upgrade to post-quantum cryptographic standards.")

    # Invariant: If evidence is NOT_OBSERVABLE, severity must not be CRITICAL/HIGH vulnerability
    if str(ev).upper() == "NOT_OBSERVABLE":
        sev = "INFORMATIONAL"

    return NormalizedFinding(
        rule_id=str(fid),
        title=title,
        value=val,
        role=str(role),
        source=str(src) if src else "EXTERNAL_SCAN",
        source_file=getattr(finding, "source_file", None),
        source_line=getattr(finding, "source_line", getattr(finding, "line", None)),
        evidence_status=str(ev).upper(),
        severity=str(sev).upper(),
        risk=risk,
        message=str(msg),
        recommendation=str(rec),
        system_id=system_id,
        asset_id=system_id,
        layer="EDGE",
        metadata={"category": getattr(finding, "category", None)},
    )


def normalize_crypto_misuse_finding(finding: Any, system_id: Optional[str] = None) -> NormalizedFinding:
    """Normalizes a MisuseFinding into a NormalizedFinding."""
    fid = getattr(finding, "rule_id", "MISUSE-GENERIC")
    title = getattr(finding, "title", "Crypto Misuse Observation")
    val = sanitize_secret_value(str(getattr(finding, "matched_value", getattr(finding, "value", "N/A"))))
    role = str(getattr(finding, "role", "CODE_IMPLEMENTATION"))
    src = "CODE_ANALYSIS"
    ev = str(getattr(finding, "evidence_status", "OBSERVED")).upper()
    sev = str(getattr(finding, "severity", "HIGH")).upper()
    
    raw_risk = str(getattr(finding, "risk", "")).upper()
    if "QUANTUM" in raw_risk or any(q in fid.upper() for q in ["RSA-KEX", "ECDH-KEX", "QUANTUM"]):
        risk = "QUANTUM"
    else:
        risk = "CLASSICAL"

    msg = getattr(finding, "description", getattr(finding, "message", title))
    rec = getattr(finding, "recommendation", "Follow cryptographic implementation best practices.")
    file_path = getattr(finding, "file", getattr(finding, "source_file", None))
    line_no = getattr(finding, "line", getattr(finding, "line_number", getattr(finding, "source_line", None)))

    # Invariant: If evidence is NOT_OBSERVABLE, severity must not be CRITICAL/HIGH
    if ev == "NOT_OBSERVABLE":
        sev = "INFORMATIONAL"

    return NormalizedFinding(
        rule_id=str(fid),
        title=title,
        value=val,
        role=role,
        source=src,
        source_file=str(file_path) if file_path else None,
        source_line=int(line_no) if line_no is not None else None,
        evidence_status=ev,
        severity=sev,
        risk=risk,
        message=str(msg),
        recommendation=str(rec),
        system_id=system_id,
        asset_id=system_id,
        layer="SERVICE_TO_SERVICE",
        metadata={
            "language": getattr(finding, "language", None),
            "confidence": getattr(finding, "confidence", None),
            **(getattr(finding, "metadata", {}) or {}),
            "scanner_risk_category": raw_risk,
        },
    )


def normalize_config_finding(finding: Any, system_id: Optional[str] = None) -> NormalizedFinding:
    """Normalizes a ConfigObservation or ConfigFinding into a NormalizedFinding."""
    fid = getattr(finding, "rule_id", f"CFG-{getattr(finding, 'path', getattr(finding, 'asset_name', 'OBSERVATION'))}")
    title = getattr(finding, "title", getattr(finding, "asset_name", getattr(finding, "path", "Configuration Observation")))
    val = sanitize_secret_value(str(getattr(finding, "parsed_value", getattr(finding, "raw_value", getattr(finding, "value", "N/A")))))
    role_raw = getattr(finding, "role", "CONFIGURATION")
    role = role_raw.value if hasattr(role_raw, "value") else str(role_raw)
    src = "CONFIGURATION_FILE"
    ev_raw = getattr(finding, "evidence_status", "OBSERVED")
    ev = ev_raw.value if hasattr(ev_raw, "value") else str(ev_raw)
    sev = str(getattr(finding, "severity", "MEDIUM")).upper()

    val_u = val.upper()
    title_u = title.upper()
    fid_u = str(fid).upper()
    if any(q in val_u or q in title_u or q in fid_u for q in ["RSA", "ECDH", "ECDSA", "DIFFIE", "X25519", "QUANTUM", "PQC"]):
        risk = "QUANTUM"
    elif any(c in val_u or c in title_u or c in fid_u for c in ["3DES", "DES", "MD5", "SHA-1", "RC4", "TLS1.0", "TLS1.1", "ECB", "NO_SALT"]):
        risk = "CLASSICAL"
    else:
        risk = "QUANTUM" if any(k in val_u for k in ["RSA", "DH"]) else "CLASSICAL"

    msg = getattr(finding, "description", getattr(finding, "message", f"{title}: {val}"))
    rec = getattr(finding, "recommendation", "Review and align configuration with banking standards.")
    file_path = getattr(finding, "source_file", getattr(finding, "file", getattr(finding, "file_path", None)))
    line_no = getattr(finding, "source_line", getattr(finding, "line", None))

    # Invariant: If not observable, not vulnerable
    if ev.upper() == "NOT_OBSERVABLE":
        sev = "INFORMATIONAL"

    return NormalizedFinding(
        rule_id=str(fid),
        title=title,
        value=val,
        role=role,
        source=src,
        source_file=str(file_path) if file_path else None,
        source_line=int(line_no) if line_no is not None else None,
        evidence_status=ev.upper(),
        severity=sev,
        risk=risk,
        message=str(msg),
        recommendation=str(rec),
        system_id=system_id,
        asset_id=system_id,
        layer=getattr(finding, "layer", "CONFIGURATION"),
        metadata={
            "crypto_agility": getattr(finding, "crypto_agility", None),
            **(getattr(finding, "metadata", {}) or {}),
        },
    )


def normalize_profile_evidence_item(item: EvidenceItem, system_id: Optional[str] = None) -> NormalizedFinding:
    """Normalizes an explicit Banking Profile EvidenceItem into a NormalizedFinding."""
    val_upper = item.value.upper()
    role = item.control
    src = item.source.value if hasattr(item.source, "value") else str(item.source)
    obs = item.observability.value if hasattr(item.observability, "value") else str(item.observability)
    layer = item.layer.value if (item.layer and hasattr(item.layer, "value")) else str(item.layer or "EDGE")

    ev_status = "DECLARED" if src == "OPERATOR_DECLARED" else ("OBSERVED" if src == "CONFIGURATION_FILE" else obs)

    # Determine risk dimension
    if any(q in val_upper for q in ["RSA", "ECDH", "ECDSA", "DIFFIE", "X25519"]):
        risk = "QUANTUM"
        sev = "HIGH" if "RSA-2048" in val_upper or "ECDH" in val_upper else "MEDIUM"
        msg = f"{item.control} operates with classical asymmetric algorithm ({item.value}) vulnerable to Shor's algorithm."
        rec = "Transition to NIST Post-Quantum Cryptographic Standards (ML-KEM / ML-DSA)."
    elif any(c in val_upper for c in ["3DES", "DES", "MD5", "SHA-1", "TLSV1.0", "TLSV1.1"]):
        risk = "CLASSICAL"
        sev = "CRITICAL" if "3DES" in val_upper else "HIGH"
        msg = f"{item.control} configured with deprecated classical cryptographic primitive ({item.value})."
        rec = "Replace deprecated primitive with AES-256-GCM and SHA-256/384."
    elif any(pqc in val_upper for pqc in ["ML-KEM", "ML-DSA", "X25519MLKEM", "AES-256"]):
        risk = "QUANTUM"
        sev = "INFORMATIONAL"
        msg = f"{item.control} verified using quantum-resilient primitive ({item.value})."
        rec = "Maintain periodic audit and certificate lifecycle."
    else:
        risk = "CLASSICAL"
        sev = "LOW"
        msg = item.description or f"{item.control}: {item.value}"
        rec = "Maintain standard operational monitoring."

    # Invariant: If not observable, not vulnerable
    if obs == "NOT_OBSERVABLE":
        sev = "INFORMATIONAL"

    return NormalizedFinding(
        rule_id=f"PROF-EV-{item.id}",
        title=f"{item.control}: {item.value}",
        value=item.value,
        role=role,
        source=src,
        source_file=getattr(item, "file_path", None),
        source_line=None,
        evidence_status=ev_status,
        severity=sev,
        risk=risk,
        message=msg,
        recommendation=rec,
        system_id=system_id,
        asset_id=system_id,
        layer=layer,
        metadata={"original_description": item.description, "confidence": item.confidence},
    )


def collect_unified_findings(
    system_id: str,
    tls_findings: Optional[List[Any]] = None,
    crypto_misuse_findings: Optional[List[Any]] = None,
    config_findings: Optional[List[Any]] = None,
    banking_profile: Optional[BankingAsset] = None,
) -> List[NormalizedFinding]:
    """
    Integrates findings across all 4 sources into a deduplicated, normalized collection.
    """
    unified: List[NormalizedFinding] = []
    seen_keys = set()

    # 1. TLS Findings
    if tls_findings:
        for f in tls_findings:
            norm = normalize_tls_finding(f, system_id=system_id)
            dedup_key = (norm.rule_id, norm.value)
            if dedup_key not in seen_keys:
                seen_keys.add(dedup_key)
                unified.append(norm)

    # 2. Crypto Misuse Findings
    if crypto_misuse_findings:
        for f in crypto_misuse_findings:
            norm = normalize_crypto_misuse_finding(f, system_id=system_id)
            dedup_key = (norm.rule_id, norm.value)
            if dedup_key not in seen_keys:
                seen_keys.add(dedup_key)
                unified.append(norm)

    # 3. Config Findings
    if config_findings:
        for f in config_findings:
            norm = normalize_config_finding(f, system_id=system_id)
            dedup_key = (norm.rule_id, norm.value)
            if dedup_key not in seen_keys:
                seen_keys.add(dedup_key)
                unified.append(norm)

    # 4. Banking Profile Declarations
    if banking_profile and banking_profile.evidence_items:
        for item in banking_profile.evidence_items:
            norm = normalize_profile_evidence_item(item, system_id=system_id)
            dedup_key = (norm.rule_id, norm.value)
            if dedup_key not in seen_keys:
                seen_keys.add(dedup_key)
                unified.append(norm)

    return unified

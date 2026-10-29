"""Assessment Orchestrator Service.
Coordinates the scan lifecycle: domain normalization -> TLS scanning ->
cryptographic normalization -> quantum risk evaluation -> priority roadmap generation.
"""

from typing import Dict, Any, Optional
from app.schemas.scan import (
    ScanResponse,
    TargetInfo,
    CertificateInfo,
    TlsInfo,
)
from app.scanners.tls_scanner import TlsScanner, TlsScanError
from app.scanners.domain_validator import DomainValidationError
from app.security.normalizer import normalize_cryptographic_mechanisms
from app.security.quantum_risk import evaluate_quantum_risk
from app.models.banking import infer_default_banking_asset, BankingAsset
from app.models.profiles import get_synthetic_profile_by_id
from app.models.zero_trust import build_default_zero_trust_assessment
from app.services.crypto_audit_adapter import map_findings_to_audit_layer
from app.services.banking_risk_engine import evaluate_banking_risk


class AssessmentService:
    def __init__(self, scanner_timeout: float = 8.0):
        self.scanner = TlsScanner(timeout=scanner_timeout)

    def assess_domain(
        self,
        domain: str,
        port: int = 443,
        probe_pqc: bool = False,
        asset_id: Optional[str] = None
    ) -> ScanResponse:
        """
        Executes an end-to-end passive post-quantum cryptographic assessment for a domain.
        If probe_pqc is True and TLS 1.3 is negotiated, performs at most one active capability
        probe offering X25519MLKEM768.
        If asset_id is provided, attaches the matching banking asset/profile context.
        """
        # Step 1 & 2: TLS Scan & Certificate Extraction
        raw_scan_result = self.scanner.scan(domain, port=port, probe_pqc=probe_pqc)
        target_raw = raw_scan_result["target"]
        cert_raw = raw_scan_result["certificate"]
        tls_raw = raw_scan_result["tls"]

        # Step 3: Cryptographic Normalization
        mechanisms, not_observable_notes = normalize_cryptographic_mechanisms(cert_raw, tls_raw)

        # Enrich tls_raw with explicit role and evidence status
        kx_mech = next((m for m in mechanisms if m.category == "key_exchange"), None)
        sym_mech = next((m for m in mechanisms if m.category == "symmetric_cipher"), None)
        hash_mech = next((m for m in mechanisms if m.category == "hash"), None)

        tls_raw["key_exchange_value"] = kx_mech.value if kx_mech else "Not observable"
        tls_raw["key_exchange_evidence"] = kx_mech.evidence if kx_mech else "NOT_OBSERVABLE"
        tls_raw["key_exchange_inferred"] = kx_mech.value if kx_mech and kx_mech.evidence == "INFERRED" else None
        tls_raw["symmetric_encryption_inferred"] = sym_mech.value if sym_mech else None
        tls_raw["hash_mac_inferred"] = hash_mech.value if hash_mech else None

        # Step 4: Quantum Risk Evaluation & Priority Roadmap
        (
            findings,
            quantum_score,
            role_assessments,
            executive_summary,
            migration_plan,
            observability_scope
        ) = evaluate_quantum_risk(
            mechanisms, tls_raw, cert_raw, domain=target_raw["domain"]
        )

        # Step 5: Phase 4A Banking Asset & Audit Layer Context
        matched_profile = get_synthetic_profile_by_id(asset_id) if asset_id else None
        if matched_profile:
            banking_asset = matched_profile
        else:
            banking_asset = infer_default_banking_asset(target_raw["domain"])

        audit_findings = map_findings_to_audit_layer(findings, banking_asset.id)
        zero_trust = build_default_zero_trust_assessment(
            banking_asset.id,
            tls_version=tls_raw.get("negotiated_protocol", "TLSv1.3")
        )
        banking_risk = evaluate_banking_risk(
            banking_asset,
            scan_quantum_score=quantum_score.score,
            scan_classical_risk="LOW"
        )

        return ScanResponse(
            target=TargetInfo(**target_raw),
            scan_status="SUCCESS",
            certificate=CertificateInfo(**cert_raw),
            tls=TlsInfo(**tls_raw),
            cryptography=mechanisms,
            findings=findings,
            score=quantum_score,
            role_assessments=role_assessments,
            executive_summary=executive_summary,
            migration_plan=migration_plan,
            observability_scope=observability_scope,
            not_observable_notes=not_observable_notes,
            banking_asset=banking_asset,
            banking_risk=banking_risk,
            audit_findings=audit_findings,
            zero_trust=zero_trust,
        )


def assess_domain(
    domain: str,
    port: int = 443,
    probe_pqc: bool = False,
    asset_id: Optional[str] = None
) -> ScanResponse:
    """Convenience helper for AssessmentService().assess_domain."""
    return AssessmentService().assess_domain(domain, port=port, probe_pqc=probe_pqc, asset_id=asset_id)



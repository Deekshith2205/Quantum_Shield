"""Banking Security Audit Orchestrator Service.
Phase 0 - Banking Security Audit Architecture
"""

from typing import Optional
from app.services.assessment_service import AssessmentService
from app.schemas.scan import ScanResponse
from app.schemas.audit import AuditRequest, AuditResponse
from app.models.banking import BankingAsset, infer_default_banking_asset
from app.models.profiles import get_synthetic_profile_by_id
from app.models.zero_trust import build_default_zero_trust_assessment
from app.models.risk import RiskDimensions
from app.services.crypto_audit_adapter import (
    map_findings_to_audit_layer,
    summarize_audit_findings,
)
from app.services.banking_risk_engine import evaluate_banking_risk


class AuditService:
    """
    Coordinates the multi-layer banking security audit:
    Banking Asset Context -> TLS Crypto Assessment -> Audit Layer Mapping ->
    Zero Trust Posture -> Multidimensional Risk Separation.
    """

    def __init__(self, assessment_service: Optional[AssessmentService] = None):
        self.assessment_service = assessment_service or AssessmentService()

    def audit_target(
        self,
        domain: str,
        port: int = 443,
        request_override: Optional[AuditRequest] = None
    ) -> AuditResponse:
        """
        Executes an end-to-end banking security audit for a target host.
        """
        # 1. Passive Cryptographic Scan (Phase 1, 2B, 2C, 3B hardened)
        probe_pqc = request_override.probe_pqc if request_override else False
        target_asset_id = request_override.asset_id if request_override else None
        scan_response: ScanResponse = self.assessment_service.assess_domain(
            domain, port=port, probe_pqc=probe_pqc, asset_id=target_asset_id
        )

        # 2. Establish Banking Asset context
        if request_override:
            # Check if an existing synthetic profile was requested
            matched_profile = get_synthetic_profile_by_id(request_override.asset_id) if request_override.asset_id else None
            if matched_profile:
                # Use profile as template, applying user overrides if provided
                asset = BankingAsset(
                    id=matched_profile.id,
                    name=request_override.asset_name or matched_profile.name,
                    asset_type=request_override.asset_type or matched_profile.asset_type,
                    system_type=request_override.asset_type or matched_profile.system_type,
                    description=matched_profile.description,
                    criticality=request_override.criticality or matched_profile.criticality,
                    data_sensitivity=request_override.data_sensitivity or matched_profile.data_sensitivity,
                    exposure=request_override.exposure or matched_profile.exposure,
                    data_lifetime=matched_profile.data_lifetime,
                    trust_zone=request_override.trust_zone or matched_profile.trust_zone,
                    layers=matched_profile.layers,
                    cryptography=matched_profile.cryptography,
                    key_management=matched_profile.key_management,
                    authentication=matched_profile.authentication,
                    evidence_items=matched_profile.evidence_items,
                    evidence_gaps=matched_profile.evidence_gaps,
                    tags=request_override.tags if request_override.tags else matched_profile.tags,
                    metadata=matched_profile.metadata,
                )
            else:
                default_asset = infer_default_banking_asset(domain)
                asset = BankingAsset(
                    id=default_asset.id,
                    name=request_override.asset_name or default_asset.name,
                    asset_type=request_override.asset_type or default_asset.asset_type,
                    system_type=request_override.asset_type or default_asset.system_type,
                    description=default_asset.description,
                    criticality=request_override.criticality or default_asset.criticality,
                    data_sensitivity=request_override.data_sensitivity or default_asset.data_sensitivity,
                    exposure=request_override.exposure or default_asset.exposure,
                    data_lifetime=default_asset.data_lifetime,
                    trust_zone=request_override.trust_zone or default_asset.trust_zone,
                    tags=request_override.tags if request_override.tags else default_asset.tags,
                )
        else:
            asset = infer_default_banking_asset(domain)

        # 3. Map Technical Findings to the Audit Layer
        audit_findings = map_findings_to_audit_layer(scan_response.findings, asset.id)

        # 4. Zero Trust Evaluation
        zero_trust = build_default_zero_trust_assessment(
            asset.id,
            tls_version=scan_response.tls.negotiated_protocol
        )

        # 5. Multidimensional Risk Separation
        cert_is_trusted = scan_response.certificate.is_trusted
        cert_is_expired = scan_response.certificate.is_expired
        classical_risk = "LOW" if (cert_is_trusted and not cert_is_expired) else "HIGH"

        risk_dimensions = RiskDimensions(
            quantum_risk_score=scan_response.score.exposure_risk_score,
            quantum_readiness_score=scan_response.score.readiness_score,
            classical_security_risk=classical_risk,
            zero_trust_posture="EDGE_ENCRYPTED_INTERNAL_UNKNOWN",
            asset_criticality=asset.criticality,
            description=(
                f"Asset '{asset.name}' evaluated under {asset.criticality.value} business criticality. "
                f"Quantum readiness score is {scan_response.score.readiness_score}/100. "
                f"Classical TLS posture: {classical_risk}."
            ),
        )

        # 6. Audit Metrics Summary
        audit_summary = summarize_audit_findings(audit_findings)

        # 7. Phase 4B Banking Criticality + Key-Protection Risk Assessment
        banking_risk = evaluate_banking_risk(
            asset,
            scan_quantum_score=scan_response.score.readiness_score,
            scan_classical_risk=classical_risk,
        )

        # Enrich scan_response with audit context for backward compatibility
        scan_response.banking_asset = asset
        scan_response.banking_risk = banking_risk
        scan_response.audit_findings = audit_findings
        scan_response.zero_trust = zero_trust

        return AuditResponse(
            asset=asset,
            audit=audit_summary,
            findings=audit_findings,
            crypto=scan_response,
            zero_trust=zero_trust,
            risk=risk_dimensions,
            banking_risk=banking_risk,
        )


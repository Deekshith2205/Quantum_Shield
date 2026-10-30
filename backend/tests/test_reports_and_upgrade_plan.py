"""Integration tests for JSON/PDF Reports and Ranked Upgrade Planner."""

import pytest
import json
from app.services.report_service import build_complete_json_report, generate_pdf_report
from app.services.upgrade_planner import generate_ranked_upgrade_plan
from app.models.report import CompleteAssessmentReport
from app.models.upgrade_plan import RankedUpgradePlan


def test_complete_json_report_structure():
    """Report must contain all required sections specified in Section 19."""
    report = build_complete_json_report("BANK-PROF-CORE-BANKING")
    assert isinstance(report, CompleteAssessmentReport)

    r_dict = report.model_dump()
    required_sections = [
        "metadata",
        "executive_summary",
        "system",
        "quantum_posture",
        "classical_posture",
        "priority",
        "priority_factors",
        "findings",
        "key_protection_chain",
        "crypto_agility",
        "migration_impact",
        "ranked_upgrade_plan",
        "cbom",
        "evidence_gaps",
        "observability",
        "what_if",
        "audit",
    ]

    for section in required_sections:
        assert section in r_dict, f"Missing required report section: {section}"

    # Verify JSON serializability
    serialized = json.dumps(r_dict, default=str)
    assert len(serialized) > 500

    # Verify secrets are redacted
    assert "AKIA" not in serialized
    assert "-----BEGIN RSA PRIVATE KEY-----" not in serialized


def test_pdf_report_generation():
    """PDF export must generate valid, non-empty binary PDF stream."""
    pdf_bytes = generate_pdf_report("BANK-PROF-CORE-BANKING")
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 2000
    assert pdf_bytes.startswith(b"%PDF-"), "Generated file does not have a valid PDF magic header"


def test_pdf_report_for_all_banking_profiles():
    """PDF export must succeed across all synthetic banking systems without crashing."""
    for sys_id in [
        "BANK-PROF-PAYMENT-GATEWAY",
        "BANK-PROF-CORE-BANKING",
        "BANK-PROF-KYC-DB",
        "BANK-PROF-NET-BANKING",
        "BANK-PROF-ATM-NETWORK",
    ]:
        pdf = generate_pdf_report(sys_id)
        assert len(pdf) > 2000
        assert pdf.startswith(b"%PDF-")


def test_dynamic_ranked_upgrade_plan_calculation():
    """Ranked upgrade plan must be computed dynamically from the risk engine, not hardcoded."""
    plan = generate_ranked_upgrade_plan()
    assert isinstance(plan, RankedUpgradePlan)
    assert plan.total_systems >= 5
    assert len(plan.queue) == plan.total_systems

    # Verify queue ordering by priority_score descending
    scores = [item.priority_score for item in plan.queue]
    assert scores == sorted(scores, reverse=True)

    # Core Banking should lead the queue due to VERY_LONG lifetime + Criticality + Quantum-vulnerable KEK
    assert plan.queue[0].system_id == "BANK-PROF-CORE-BANKING"
    assert plan.queue[0].priority == "P0"

    # Payment Gateway should be last due to modern hybrid PQC deployment
    assert plan.queue[-1].system_id == "BANK-PROF-PAYMENT-GATEWAY"
    assert plan.queue[-1].priority == "P3"

    for idx, item in enumerate(plan.queue, start=1):
        assert item.rank == idx
        assert item.system
        assert item.recommended_upgrade
        assert item.migration_impact in ["VERY_HIGH", "HIGH", "MEDIUM", "LOW"]
        assert isinstance(item.top_findings, list)
        assert isinstance(item.key_protection_chain, dict)

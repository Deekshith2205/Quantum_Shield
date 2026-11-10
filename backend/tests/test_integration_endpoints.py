"""Integration tests for all newly added endpoints:
CBOM, JSON Report, PDF Report, Ranked Upgrade Plan, and Audit Verification.
"""

import pytest
from starlette.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_api_banking_upgrade_plan_endpoint():
    """GET /api/banking/upgrade-plan returns dynamically calculated priority roadmap."""
    resp = client.get("/api/banking/upgrade-plan")
    assert resp.status_code == 200
    data = resp.json()

    assert data["total_systems"] >= 5
    assert "queue" in data
    assert len(data["queue"]) == data["total_systems"]
    assert data["queue"][0]["rank"] == 1
    assert data["queue"][0]["system_id"] == "BANK-PROF-CORE-BANKING"
    # Priority-band counts must account for every ranked system.
    assert (
        data["p0_count"]
        + data["p1_count"]
        + data["p2_count"]
        + data["p3_count"]
    ) == data["total_systems"]

    # Every queue item must expose the factors behind its priority score.
    for item in data["queue"]:
        breakdown = item["score_breakdown"]

        assert 0 <= breakdown["governing_technical_risk"] <= 4
        assert 0.0 <= breakdown["technical_risk_factor"] <= 1.0
        assert 1 <= breakdown["criticality_score"] <= 4
        assert 1 <= breakdown["sensitivity_score"] <= 4
        assert 1 <= breakdown["lifetime_score"] <= 4
        assert 1 <= breakdown["exposure_score"] <= 4
        assert 1 <= breakdown["migration_effort_score"] <= 4

        expected_technical_factor = (
            breakdown["governing_technical_risk"] / 4.0
        )
        assert breakdown["technical_risk_factor"] == pytest.approx(
            expected_technical_factor
        )

        expected_effort_factor = (
            breakdown["migration_effort_score"] / 4.0
        )
        assert breakdown["migration_effort_factor"] == pytest.approx(
            expected_effort_factor
        )

        expected_urgency = (
            0.70 * breakdown["business_exposure_factor"]
            + 0.30 * expected_effort_factor
        )
        assert breakdown["composite_urgency_factor"] == pytest.approx(
            expected_urgency, abs=0.0001
        )


def test_api_banking_cbom_endpoint_get_and_post():
    """GET and POST /api/banking/systems/{id}/cbom return CycloneDX CBOM."""
    # Test GET
    resp_get = client.get("/api/banking/systems/BANK-PROF-CORE-BANKING/cbom")
    assert resp_get.status_code == 200
    cbom_get = resp_get.json()
    assert cbom_get["bomFormat"] == "CycloneDX"
    assert cbom_get["specVersion"] in ["1.6", "1.7"]
    assert len(cbom_get["components"]) >= 5

    # Test POST
    resp_post = client.post("/api/banking/systems/BANK-PROF-CORE-BANKING/cbom")
    assert resp_post.status_code == 200
    assert resp_post.json()["bomFormat"] == "CycloneDX"


def test_api_banking_cbom_404_on_invalid_id():
    """Non-existent profile ID must return 404."""
    resp = client.get("/api/banking/systems/INVALID-NONEXISTENT/cbom")
    assert resp.status_code == 404
    assert resp.json()["error"] == "PROFILE_NOT_FOUND"


def test_api_banking_json_report_endpoint():
    """GET /api/banking/systems/{id}/report/json returns complete assessment report."""
    resp = client.get("/api/banking/systems/BANK-PROF-CORE-BANKING/report/json")
    assert resp.status_code == 200
    report = resp.json()

    assert "metadata" in report
    assert "executive_summary" in report
    assert "quantum_posture" in report
    assert "classical_posture" in report
    assert "findings" in report
    assert "ranked_upgrade_plan" in report
    assert "cbom" in report
    assert "audit" in report
    assert report["audit"]["assessment_hash"]


def test_api_banking_pdf_report_endpoint():
    """GET /api/banking/systems/{id}/report/pdf returns valid binary PDF."""
    resp = client.get("/api/banking/systems/BANK-PROF-CORE-BANKING/report/pdf")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert resp.content.startswith(b"%PDF-")
    assert len(resp.content) > 2000


def test_api_audit_verify_valid_and_tampered():
    """POST /api/audit/verify verifies intact records and rejects tampered ones."""
    # Fetch legitimate report and audit record
    rep_resp = client.get("/api/banking/systems/BANK-PROF-CORE-BANKING/report/json")
    audit_rec = rep_resp.json()["audit"]

    # 1. Verify legitimate record
    valid_resp = client.post("/api/audit/verify", json={"record": audit_rec})
    assert valid_resp.status_code == 200
    assert valid_resp.json()["valid"] is True

    # 2. Verify tampered record
    tampered_rec = dict(audit_rec)
    tampered_rec["assessment_hash"] = "0" * 64
    invalid_resp = client.post("/api/audit/verify", json={"record": tampered_rec})
    assert invalid_resp.status_code == 200
    assert invalid_resp.json()["valid"] is False
    assert invalid_resp.json()["error"]


def test_api_audit_verify_chain_endpoint():
    """POST /api/audit/verify-chain verifies sequence of records."""
    rep_resp1 = client.get("/api/banking/systems/BANK-PROF-CORE-BANKING/report/json")
    audit_rec1 = rep_resp1.json()["audit"]

    rep_resp2 = client.get("/api/banking/systems/BANK-PROF-PAYMENT-GATEWAY/report/json")
    audit_rec2 = rep_resp2.json()["audit"]

    chain_resp = client.post("/api/audit/verify-chain", json=[audit_rec1, audit_rec2])
    assert chain_resp.status_code == 200
    assert chain_resp.json()["records_checked"] >= 1

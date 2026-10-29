"""Unit tests for FastAPI endpoints and error handling.
"""

from unittest.mock import patch
import pytest
from starlette.testclient import TestClient
from app.main import app
from tests.fixtures.cert_generator import generate_mock_rsa_cert_der

client = TestClient(app)


def test_health_check_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "QuantumShield" in data["service"]


def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    assert "QuantumShield" in response.json()["platform"]


def test_scan_empty_domain():
    response = client.post("/api/scan", json={"domain": ""})
    assert response.status_code == 400
    assert "error" in response.json()


def test_scan_prohibited_localhost():
    response = client.post("/api/scan", json={"domain": "localhost"})
    assert response.status_code == 400
    data = response.json()
    assert data["error"] == "DOMAIN_VALIDATION_ERROR"
    assert "prohibited" in data["detail"]


def test_scan_prohibited_private_ip():
    response = client.post("/api/scan", json={"domain": "10.0.0.1"})
    assert response.status_code == 400
    data = response.json()
    assert data["error"] == "DOMAIN_VALIDATION_ERROR"


def test_scan_with_mocked_tls():
    # Mock TlsScanner.scan to verify end-to-end API response contract deterministically
    mock_scan_return = {
        "target": {
            "domain": "test.mock.org",
            "port": 443,
            "resolved_ip": "93.184.216.34",
            "ip_version": "IPv4",
            "scan_timestamp": "2026-10-29T12:00:00Z",
            "connection_time_ms": 42.5,
        },
        "certificate": {
            "subject_cn": "test.mock.org",
            "subject_org": "Mock Company",
            "subject_alt_names": ["test.mock.org"],
            "issuer_cn": "Mock DigiCert",
            "issuer_org": "DigiCert",
            "serial_number": "ABCDEF123456",
            "fingerprint_sha256": "AA:BB:CC:DD",
            "not_valid_before": "2026-01-01T00:00:00Z",
            "not_valid_after": "2027-01-01T00:00:00Z",
            "days_remaining": 60,
            "is_expired": False,
            "public_key_algorithm": "RSA",
            "key_size_bits": 2048,
            "curve_name": None,
            "signature_algorithm": "sha256WithRSAEncryption",
            "signature_hash_algorithm": "SHA256",
            "chain_length": 2,
            "chain_certificates": [],
            "verification_status": "Trusted by system root CAs",
            "is_trusted": True,
        },
        "tls": {
            "negotiated_protocol": "TLSv1.3",
            "negotiated_cipher": "TLS_AES_256_GCM_SHA384",
            "cipher_bits": 256,
            "alpn_protocol": "h2",
            "session_reused": False,
        }
    }

    with patch("app.services.assessment_service.TlsScanner.scan", return_value=mock_scan_return):
        response = client.post("/api/scan", json={"domain": "test.mock.org"})
        assert response.status_code == 200
        data = response.json()

        assert data["scan_status"] == "SUCCESS"
        assert data["target"]["domain"] == "test.mock.org"
        assert data["certificate"]["public_key_algorithm"] == "RSA"
        assert data["tls"]["negotiated_protocol"] == "TLSv1.3"
        assert data["tls"]["key_exchange_evidence"] == "NOT_OBSERVABLE"
        assert data["tls"]["key_exchange_value"] == "Not observable"
        assert len(data["cryptography"]) > 0
        for mech in data["cryptography"]:
            assert "role" in mech
            assert "value" in mech
            assert "source" in mech
            assert "evidence" in mech
        assert len(data["findings"]) > 0
        assert "score" in data["score"]
        assert data["score"]["score"] >= 0 and data["score"]["score"] <= 100
        assert "category_breakdown" in data["score"]
        assert "role_assessments" in data and len(data["role_assessments"]) == 5
        assert "executive_summary" in data
        assert "observability_scope" in data
        assert len(data["migration_plan"]) > 0
        assert len(data["not_observable_notes"]) > 0


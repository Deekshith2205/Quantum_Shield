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


def test_scan_uploaded_config_success():
    response = client.post(
        "/api/scan/config",
        json={
            "files": [
                {
                    "name": "tls.yaml",
                    "content": (
                        "tls:\n"
                        "  min_version: TLSv1.0\n"
                        "  cipher: AES-128-CBC\n"
                    ),
                }
            ]
        },
    )

    assert response.status_code == 200
    data = response.json()

    assert data["scan_status"] == "SUCCESS"
    assert data["files_scanned"] == 1
    assert data["finding_count"] == 2

    finding = data["findings"][0]
    assert finding["evidence_status"] == "OBSERVED"
    assert finding["source"] == "CONFIGURATION_FILE"
    assert finding["source_file"] == "tls.yaml"
    assert finding["source_line"] is not None


def test_scan_uploaded_config_rejects_malformed_json():
    response = client.post(
        "/api/scan/config",
        json={
            "files": [
                {
                    "name": "settings.json",
                    "content": '{"tls": ',
                }
            ]
        },
    )

    assert response.status_code == 400
    assert response.json()["error"] == "INVALID_CONFIGURATION"


@pytest.mark.parametrize(
    "filename",
    [
        "../settings.yaml",
        "folder/settings.yaml",
        "folder\\settings.yaml",
    ],
)
def test_scan_uploaded_config_rejects_unsafe_filename(filename):
    response = client.post(
        "/api/scan/config",
        json={
            "files": [
                {
                    "name": filename,
                    "content": "tls:\n  min_version: TLSv1.2\n",
                }
            ]
        },
    )

    assert response.status_code == 400
    assert response.json()["error"] == "INVALID_FILENAME"


def test_scan_uploaded_config_rejects_unsupported_extension():
    response = client.post(
        "/api/scan/config",
        json={
            "files": [
                {
                    "name": "malware.exe",
                    "content": "not executable",
                }
            ]
        },
    )

    assert response.status_code == 400
    assert response.json()["error"] == "UNSUPPORTED_FILE_TYPE"


def test_scan_uploaded_config_rejects_duplicate_filenames():
    response = client.post(
        "/api/scan/config",
        json={
            "files": [
                {"name": "settings.yaml", "content": "a: 1"},
                {"name": "SETTINGS.yaml", "content": "b: 2"},
            ]
        },
    )

    assert response.status_code == 400
    assert response.json()["error"] == "DUPLICATE_FILENAME"


def test_scan_uploaded_code_success():
    response = client.post(
        "/api/scan/code",
        json={
            "files": [
                {
                    "name": "sample.py",
                    "content": (
                        "import hashlib\n"
                        'password_hash = hashlib.md5(b"demo").hexdigest()\n'
                    ),
                }
            ]
        },
    )

    assert response.status_code == 200
    data = response.json()

    assert data["scan_status"] == "SUCCESS"
    assert data["files_scanned"] == 1
    assert data["finding_count"] >= 1

    finding = next(
        item for item in data["findings"]
        if item["rule_id"] == "MISUSE-MD5-HASH"
    )

    assert finding["severity"] == "CRITICAL"
    assert finding["evidence_status"] == "OBSERVED"
    assert finding["role"] == "PASSWORD_HASHING"
    assert finding["source"] == "CODE_ANALYSIS"
    assert finding["source_file"] == "sample.py"
    assert finding["source_line"] == 2
    assert finding["risk"] == "CLASSICAL"


@pytest.mark.parametrize(
    "filename",
    [
        "../sample.py",
        "folder/sample.py",
        "folder\\sample.py",
    ],
)
def test_scan_uploaded_code_rejects_unsafe_filename(filename):
    response = client.post(
        "/api/scan/code",
        json={
            "files": [
                {"name": filename, "content": "print('demo')"}
            ]
        },
    )

    assert response.status_code == 400
    assert response.json()["error"] == "INVALID_FILENAME"


def test_scan_uploaded_code_rejects_unsupported_extension():
    response = client.post(
        "/api/scan/code",
        json={
            "files": [
                {"name": "sample.exe", "content": "not source code"}
            ]
        },
    )

    assert response.status_code == 400
    assert response.json()["error"] == "UNSUPPORTED_FILE_TYPE"


def test_scan_uploaded_code_rejects_duplicate_filenames():
    response = client.post(
        "/api/scan/code",
        json={
            "files": [
                {"name": "sample.py", "content": "print('one')"},
                {"name": "SAMPLE.py", "content": "print('two')"},
            ]
        },
    )

    assert response.status_code == 400
    assert response.json()["error"] == "DUPLICATE_FILENAME"


def test_scan_uploaded_code_rejects_null_byte_content():
    response = client.post(
        "/api/scan/code",
        json={
            "files": [
                {"name": "sample.py", "content": "print('demo')\x00"}
            ]
        },
    )

    assert response.status_code == 400
    assert response.json()["error"] == "INVALID_FILE_CONTENT"


def test_scan_uploaded_code_rejects_oversized_file():
    # Each U+00E9 character occupies two bytes in UTF-8.
    content = "\u00e9" * 600_000

    response = client.post(
        "/api/scan/code",
        json={
            "files": [
                {"name": "large.py", "content": content}
            ]
        },
    )

    assert response.status_code == 413
    assert response.json()["error"] == "FILE_TOO_LARGE"


def test_scan_uploaded_code_rejects_oversized_combined_upload():
    content = "a" * 900_000

    response = client.post(
        "/api/scan/code",
        json={
            "files": [
                {"name": f"sample_{index}.py", "content": content}
                for index in range(6)
            ]
        },
    )

    assert response.status_code == 413
    assert response.json()["error"] == "UPLOAD_TOO_LARGE"


def test_scan_uploaded_certificate_success():
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    der = generate_mock_rsa_cert_der()
    pem = x509.load_der_x509_certificate(der).public_bytes(
        serialization.Encoding.PEM
    ).decode("utf-8")

    response = client.post(
        "/api/scan/cert",
        json={"name": "server.pem", "content": pem},
    )

    assert response.status_code == 200
    data = response.json()

    assert data["scan_status"] == "SUCCESS"
    assert data["source"] == "UPLOADED_CERTIFICATE"
    assert data["source_file"] == "server.pem"
    assert data["evidence_status"] == "OBSERVED"

    certificate = data["certificate"]
    assert certificate["public_key_algorithm"] == "RSA"
    assert certificate["key_size_bits"] == 2048
    assert certificate["signature_algorithm"]
    assert certificate["fingerprint_sha256"]


def test_scan_uploaded_certificate_rejects_malformed_pem():
    response = client.post(
        "/api/scan/cert",
        json={
            "name": "invalid.pem",
            "content": (
                "-----BEGIN CERTIFICATE-----\n"
                "not-valid-base64!\n"
                "-----END CERTIFICATE-----"
            ),
        },
    )

    assert response.status_code == 400
    assert response.json()["error"] == "INVALID_CERTIFICATE"


@pytest.mark.parametrize(
    "filename",
    [
        "../server.pem",
        "folder/server.pem",
        "folder\\server.pem",
    ],
)
def test_scan_uploaded_certificate_rejects_unsafe_filename(filename):
    response = client.post(
        "/api/scan/cert",
        json={
            "name": filename,
            "content": "-----BEGIN CERTIFICATE-----",
        },
    )

    assert response.status_code == 400
    assert response.json()["error"] == "INVALID_FILENAME"


def test_scan_uploaded_certificate_rejects_unsupported_extension():
    response = client.post(
        "/api/scan/cert",
        json={
            "name": "server.exe",
            "content": "-----BEGIN CERTIFICATE-----",
        },
    )

    assert response.status_code == 400
    assert response.json()["error"] == "UNSUPPORTED_FILE_TYPE"


def test_scan_uploaded_certificate_rejects_null_byte():
    response = client.post(
        "/api/scan/cert",
        json={
            "name": "server.pem",
            "content": "-----BEGIN CERTIFICATE-----\x00",
        },
    )

    assert response.status_code == 400
    assert response.json()["error"] == "INVALID_FILE_CONTENT"


def test_scan_uploaded_certificate_rejects_oversized_file():
    # Each U+00E9 character occupies two bytes in UTF-8.
    content = "\u00e9" * 600_000

    response = client.post(
        "/api/scan/cert",
        json={
            "name": "large.pem",
            "content": content,
        },
    )

    assert response.status_code == 413
    assert response.json()["error"] == "FILE_TOO_LARGE"

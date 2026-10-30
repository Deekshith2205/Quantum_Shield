"""Tests for CBOM Validator.
Verifies positive and negative validation checks for CycloneDX CBOM conformity.
"""

from pathlib import Path
import pytest

from app.cbom.builder import CBOMBuilder
from app.cbom.models import (
    CBOMComponent,
    CBOMMetadata,
    CryptoProperties,
    CycloneDXDocument,
    AlgorithmProperties,
)
from app.cbom.validators import CBOMValidator
from app.scanners.config_scanner.scanner import BankingConfigScanner

SAMPLE_DIR = Path(__file__).resolve().parent.parent.parent / "sample_data" / "banking"


@pytest.fixture
def valid_document():
    scanner = BankingConfigScanner(root_dir=SAMPLE_DIR)
    inv = scanner.scan_directory(SAMPLE_DIR / "upi_backend")
    builder = CBOMBuilder(deterministic=True)
    return builder.build_cbom(inv)


def test_valid_document_passes_validation(valid_document):
    validator = CBOMValidator()
    report = validator.validate(valid_document)

    assert report.is_valid is True
    assert len(report.issues) == 0
    assert report.component_count > 0


def test_invalid_bom_format():
    validator = CBOMValidator()
    bad_doc = {
        "bomFormat": "SPDX",
        "specVersion": "1.7",
        "serialNumber": "urn:uuid:11111111-2222-3333-4444-555555555555",
        "version": 1,
        "metadata": {"timestamp": "2026-10-30T00:00:00Z"},
        "components": []
    }
    report = validator.validate(bad_doc)

    assert report.is_valid is False
    assert any("bomFormat" in i for i in report.issues)


def test_unsupported_spec_version():
    validator = CBOMValidator()
    bad_doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": "urn:uuid:11111111-2222-3333-4444-555555555555",
        "version": 1,
        "metadata": {"timestamp": "2026-10-30T00:00:00Z"},
        "components": []
    }
    report = validator.validate(bad_doc)

    assert report.is_valid is False
    assert any("specVersion" in i for i in report.issues)


def test_duplicate_bom_refs():
    validator = CBOMValidator()
    bad_doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": "urn:uuid:11111111-2222-3333-4444-555555555555",
        "version": 1,
        "metadata": {"timestamp": "2026-10-30T00:00:00Z"},
        "components": [
            {
                "type": "cryptographic-asset",
                "bom-ref": "duplicate-ref-01",
                "name": "AES-256",
                "cryptoProperties": {"assetType": "algorithm"}
            },
            {
                "type": "cryptographic-asset",
                "bom-ref": "duplicate-ref-01",
                "name": "AES-128",
                "cryptoProperties": {"assetType": "algorithm"}
            }
        ]
    }
    report = validator.validate(bad_doc)

    assert report.is_valid is False
    assert any("Duplicate bom-ref" in i for i in report.issues)


def test_broken_dependency_target():
    validator = CBOMValidator()
    bad_doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": "urn:uuid:11111111-2222-3333-4444-555555555555",
        "version": 1,
        "metadata": {"timestamp": "2026-10-30T00:00:00Z"},
        "components": [
            {
                "type": "cryptographic-asset",
                "bom-ref": "ref-01",
                "name": "AES-256",
                "cryptoProperties": {"assetType": "algorithm"}
            }
        ],
        "dependencies": [
            {
                "ref": "ref-01",
                "dependsOn": ["non-existent-ref-999"]
            }
        ]
    }
    report = validator.validate(bad_doc)

    assert report.is_valid is False
    assert any("non-existent-ref-999" in i for i in report.issues)


def test_secret_leakage_detected():
    validator = CBOMValidator()
    bad_doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": "urn:uuid:11111111-2222-3333-4444-555555555555",
        "version": 1,
        "metadata": {"timestamp": "2026-10-30T00:00:00Z"},
        "components": [
            {
                "type": "cryptographic-asset",
                "bom-ref": "ref-01",
                "name": "Leaked Key",
                "description": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...",
                "cryptoProperties": {"assetType": "algorithm"}
            }
        ]
    }
    report = validator.validate(bad_doc)

    assert report.is_valid is False
    assert any("Secret leakage" in i for i in report.issues)

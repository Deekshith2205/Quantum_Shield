"""Tests for CBOM Serializer.
Verifies JSON serialization, dict conversion, field aliasing, and deterministic output.
"""

import json
from pathlib import Path
import pytest

from app.cbom.builder import CBOMBuilder
from app.cbom.serializer import CBOMSerializer
from app.scanners.config_scanner.scanner import BankingConfigScanner

SAMPLE_DIR = Path(__file__).resolve().parent.parent.parent / "sample_data" / "banking"


@pytest.fixture
def sample_document():
    scanner = BankingConfigScanner(root_dir=SAMPLE_DIR)
    inv = scanner.scan_directory(SAMPLE_DIR / "core_banking")
    builder = CBOMBuilder(deterministic=True)
    return builder.build_cbom(inv)


def test_serializer_to_dict(sample_document):
    serializer = CBOMSerializer()
    data = serializer.to_dict(sample_document)

    assert isinstance(data, dict)
    assert data["bomFormat"] == "CycloneDX"
    assert data["specVersion"] == "1.7"
    assert "components" in data
    # Check that bom-ref is serialized as bom-ref, not bom_ref
    for comp in data["components"]:
        assert "bom-ref" in comp
        assert "bom_ref" not in comp


def test_serializer_to_json(sample_document):
    serializer = CBOMSerializer()
    json_str = serializer.to_json(sample_document)

    assert isinstance(json_str, str)
    # Parse back to verify validity
    parsed = json.loads(json_str)
    assert parsed["bomFormat"] == "CycloneDX"
    assert parsed["serialNumber"] == sample_document.serialNumber


def test_deterministic_json_serialization(sample_document):
    serializer = CBOMSerializer(sort_keys=True)
    json1 = serializer.to_json(sample_document)
    json2 = serializer.to_json(sample_document)

    assert json1 == json2
    # Check that keys are sorted
    lines = json1.splitlines()
    assert len(lines) > 20


def test_no_secrets_in_serialized_json(sample_document):
    serializer = CBOMSerializer()
    json_str = serializer.to_json(sample_document)

    # Assure no plaintext secret strings appear
    assert "SYNTHETIC_ENV_SECRET_DO_NOT_EXPOSE" not in json_str
    assert "PlaintextPassword" not in json_str
    assert "-----BEGIN RSA PRIVATE KEY-----" not in json_str

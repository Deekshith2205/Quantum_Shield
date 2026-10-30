"""Integration tests for CycloneDX Cryptographic Bill of Materials (CBOM)."""

import pytest
from app.services.report_service import generate_system_cbom
from app.cbom import CBOMBuilder, CBOMSerializer, CBOMValidator
from app.cbom.validators import SECRET_LEAKAGE_REGEX
from app.models.profiles import get_synthetic_banking_profiles


def test_generate_cbom_for_all_synthetic_profiles():
    """CBOM must successfully generate for representative banking profiles."""
    profiles = get_synthetic_banking_profiles()
    assert len(profiles) >= 5

    validator = CBOMValidator()
    for p in profiles:
        cbom = generate_system_cbom(p.id)
        assert cbom["bomFormat"] == "CycloneDX"
        assert cbom["specVersion"] in ["1.6", "1.7"]
        assert "serialNumber" in cbom
        assert cbom["serialNumber"].startswith("urn:uuid:")
        assert "metadata" in cbom
        assert "components" in cbom
        assert "dependencies" in cbom
        assert len(cbom["components"]) > 0

        # Run teammate's CBOMValidator
        val_res = validator.validate(cbom)
        assert val_res.is_valid is True, f"Validation failed with issues: {val_res.issues}"


def test_cbom_contains_no_secret_or_private_key_material():
    """CBOM must strictly redact and omit private keys, passwords, and secrets."""
    for p in get_synthetic_banking_profiles():
        cbom = generate_system_cbom(p.id)
        cbom_str = str(cbom)
        assert SECRET_LEAKAGE_REGEX.search(cbom_str) is None
        assert "-----BEGIN" not in cbom_str
        assert "supersecret" not in cbom_str


def test_cbom_includes_expected_crypto_assets():
    """CBOM components must include algorithms, protocols, certificates, and related crypto material."""
    cbom = generate_system_cbom("BANK-PROF-CORE-BANKING")
    components = cbom["components"]

    names = [c["name"] for c in components]
    types = [c.get("cryptoProperties", {}).get("assetType") for c in components]

    assert any(t in ["algorithm", "protocol", "certificate", "related-crypto-material"] for t in types)
    assert len(components) >= 5


def test_cbom_cryptographic_relationships():
    """Dependencies must model cryptographic relationships between components."""
    cbom = generate_system_cbom("BANK-PROF-CORE-BANKING")
    dependencies = cbom["dependencies"]
    assert len(dependencies) > 0
    for dep in dependencies:
        assert "ref" in dep
        assert "dependsOn" in dep
        assert isinstance(dep["dependsOn"], list)


def test_cbom_serializer_determinism():
    """Serializing the same inventory deterministically produces identical JSON output."""
    from pathlib import Path
    from app.scanners.config_scanner import BankingConfigScanner
    scanner = BankingConfigScanner()
    inv = scanner.scan_directory(Path("backend/sample_data/banking/core_banking"))
    builder = CBOMBuilder(deterministic=True)
    doc1 = builder.build_cbom(inv)
    doc2 = builder.build_cbom(inv)

    serializer = CBOMSerializer()
    json1 = serializer.to_json(doc1)
    json2 = serializer.to_json(doc2)

    assert json1 == json2

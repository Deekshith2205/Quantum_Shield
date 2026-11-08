
"""Integration tests for CycloneDX Cryptographic Bill of Materials (CBOM)."""

from pathlib import Path

import pytest

from app.services.report_service import generate_system_cbom
from app.services.upgrade_planner import (
    SYSTEM_CODE_MAP,
    get_system_config_findings,
    get_system_crypto_misuse_findings,
)
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

        # Run CBOMValidator.
        val_res = validator.validate(cbom)
        assert val_res.is_valid is True, (
            f"Validation failed with issues: {val_res.issues}"
        )


def test_cbom_contains_no_secret_or_private_key_material():
    """CBOM must strictly redact and omit private keys, passwords, and secrets."""
    for p in get_synthetic_banking_profiles():
        cbom = generate_system_cbom(p.id)
        cbom_str = str(cbom)

        assert SECRET_LEAKAGE_REGEX.search(cbom_str) is None
        assert "-----BEGIN" not in cbom_str
        assert "supersecret" not in cbom_str


def test_cbom_includes_expected_crypto_assets():
    """CBOM components must include expected cryptographic assets."""
    cbom = generate_system_cbom("BANK-PROF-CORE-BANKING")
    components = cbom["components"]

    names = [c["name"] for c in components]
    types = [
        c.get("cryptoProperties", {}).get("assetType")
        for c in components
    ]

    assert any(
        t in [
            "algorithm",
            "protocol",
            "certificate",
            "related-crypto-material",
        ]
        for t in types
    )
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
    from app.scanners.config_scanner import BankingConfigScanner

    project_root = Path(__file__).resolve().parents[2]
    sample_dir = (
        project_root / "backend" / "sample_data" / "banking" / "core_banking"
    )

    scanner = BankingConfigScanner()
    inv = scanner.scan_directory(sample_dir)

    builder = CBOMBuilder(deterministic=True)
    doc1 = builder.build_cbom(inv)
    doc2 = builder.build_cbom(inv)

    serializer = CBOMSerializer()
    json1 = serializer.to_json(doc1)
    json2 = serializer.to_json(doc2)

    assert json1 == json2


def test_sample_data_paths_are_independent_of_working_directory(monkeypatch):
    """
    CBOM and findings must remain consistent from project root and backend cwd.
    """
    project_root = Path(__file__).resolve().parents[2]
    backend_dir = project_root / "backend"
    system_id = "BANK-PROF-CORE-BANKING"

    # Capture results from the repository root.
    monkeypatch.chdir(project_root)

    root_cbom = generate_system_cbom(system_id)
    root_config_count = len(get_system_config_findings(system_id))
    root_crypto_count = len(get_system_crypto_misuse_findings(system_id))

    assert len(root_cbom["components"]) > 0
    assert root_config_count > 0

    # Repeat the same operations from backend/.
    monkeypatch.chdir(backend_dir)

    backend_cbom = generate_system_cbom(system_id)
    backend_config_count = len(get_system_config_findings(system_id))
    backend_crypto_count = len(get_system_crypto_misuse_findings(system_id))

    # CBOM must be populated and consistent in both working directories.
    assert len(backend_cbom["components"]) > 0
    assert len(backend_cbom["components"]) == len(root_cbom["components"])

    # Configuration and code findings must also remain consistent.
    assert backend_config_count == root_config_count
    assert backend_crypto_count == root_crypto_count

def test_banking_profiles_scan_sample_source_not_test_fixtures():
    """Each mapped banking profile must scan its own sample source directory."""
    expected_counts = {
        "BANK-PROF-PAYMENT-GATEWAY": 6,
        "BANK-PROF-CORE-BANKING": 6,
        "BANK-PROF-KYC-DB": 11,
        "BANK-PROF-NET-BANKING": 7,
        "BANK-PROF-ATM-NETWORK": 6,
    }

    assert set(expected_counts).issubset(SYSTEM_CODE_MAP)

    for system_id, expected_count in expected_counts.items():
        source_dir = Path(SYSTEM_CODE_MAP[system_id]).resolve()

        assert source_dir.is_dir(), (
            f"Missing source directory for {system_id}: {source_dir}"
        )
        assert source_dir.name == "src"
        assert "sample_data" in source_dir.parts
        assert "tests" not in source_dir.parts

        findings = get_system_crypto_misuse_findings(system_id)

        assert len(findings) == expected_count, (
            f"{system_id}: expected {expected_count} findings, "
            f"got {len(findings)}"
        )
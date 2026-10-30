"""Tests for CBOM Builder.
Verifies transformation from inventories to CycloneDX documents,
dependency graph creation, provenance preservation, and determinism.
"""

from pathlib import Path
import pytest

from app.cbom.builder import CBOMBuilder
from app.scanners.config_scanner.models import (
    ConfigObservation,
    CryptoAgility,
    CryptoRole,
    EvidenceStatus,
    NormalizedCryptoAsset,
    NormalizedCryptoInventory,
)
from app.scanners.config_scanner.scanner import BankingConfigScanner

SAMPLE_DIR = Path(__file__).resolve().parent.parent.parent / "sample_data" / "banking"


@pytest.fixture
def core_inventory():
    scanner = BankingConfigScanner(root_dir=SAMPLE_DIR)
    return scanner.scan_directory(SAMPLE_DIR / "core_banking")


def test_build_cbom_from_inventory(core_inventory):
    builder = CBOMBuilder(deterministic=True)
    doc = builder.build_cbom(core_inventory)

    assert doc.bomFormat == "CycloneDX"
    assert doc.specVersion == "1.7"
    assert doc.serialNumber.startswith("urn:uuid:")
    assert len(doc.components) > 0
    assert doc.metadata.component.name == core_inventory.system_name


def test_unique_bom_refs(core_inventory):
    builder = CBOMBuilder(deterministic=True)
    doc = builder.build_cbom(core_inventory)

    refs = [c.bom_ref for c in doc.components]
    assert len(refs) == len(set(refs)), "Duplicate bom-refs found in CBOM document!"


def test_cryptographic_asset_types(core_inventory):
    builder = CBOMBuilder(deterministic=True)
    doc = builder.build_cbom(core_inventory)

    for comp in doc.components:
        assert comp.type == "cryptographic-asset"
        assert comp.cryptoProperties.assetType in (
            "algorithm",
            "certificate",
            "protocol",
            "related-crypto-material"
        )


def test_provenance_properties_attached(core_inventory):
    builder = CBOMBuilder(deterministic=True)
    doc = builder.build_cbom(core_inventory)

    for comp in doc.components:
        prop_names = {p.name for p in comp.properties}
        assert "quantumshield:source_file" in prop_names
        assert "quantumshield:role" in prop_names
        assert "quantumshield:evidence_status" in prop_names


def test_dependency_relationships_formed(core_inventory):
    builder = CBOMBuilder(deterministic=True)
    doc = builder.build_cbom(core_inventory)

    assert len(doc.dependencies) > 0
    # Every dependency target must exist in components
    comp_refs = {c.bom_ref for c in doc.components}
    for dep in doc.dependencies:
        assert dep.ref in comp_refs
        for target in dep.dependsOn:
            assert target in comp_refs


def test_empty_inventory_handling():
    builder = CBOMBuilder(deterministic=True)
    empty_inv = NormalizedCryptoInventory(
        system_id="EMPTY-TEST",
        system_name="Empty System",
        components=[],
        observations=[]
    )
    doc = builder.build_cbom(empty_inv)

    assert doc.bomFormat == "CycloneDX"
    assert len(doc.components) == 0
    assert len(doc.dependencies) == 0


def test_build_cbom_from_raw_observations():
    builder = CBOMBuilder(deterministic=True)
    obs = [
        ConfigObservation(
            file="app.yaml",
            line=5,
            path="tls.version",
            value="TLS 1.3",
            role=CryptoRole.TRANSPORT_SECURITY,
            algorithm="TLS 1.3",
            metadata={"protocol": "TLS", "version": "1.3"}
        ),
        ConfigObservation(
            file="app.yaml",
            line=8,
            path="tls.cipher",
            value="TLS_AES_256_GCM_SHA384",
            role=CryptoRole.TRANSPORT_SECURITY,
            algorithm="TLS_AES_256_GCM_SHA384",
            metadata={"cipher_suite": "TLS_AES_256_GCM_SHA384"}
        )
    ]
    meta = {"system_id": "RAW-TEST", "name": "Raw Obs System"}
    doc = builder.build_cbom_from_observations(obs, meta)

    assert len(doc.components) == 2
    refs = [c.bom_ref for c in doc.components]
    assert len(set(refs)) == 2


def test_deterministic_output():
    scanner = BankingConfigScanner(root_dir=SAMPLE_DIR)
    inv = scanner.scan_directory(SAMPLE_DIR / "upi_backend")

    builder = CBOMBuilder(deterministic=True)
    doc1 = builder.build_cbom(inv)
    doc2 = builder.build_cbom(inv)

    assert doc1.serialNumber == doc2.serialNumber
    assert [c.bom_ref for c in doc1.components] == [c.bom_ref for c in doc2.components]
    assert [d.ref for d in doc1.dependencies] == [d.ref for d in doc2.dependencies]

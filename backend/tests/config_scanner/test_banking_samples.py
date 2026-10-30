"""Integration tests for all 7 Banking Sample Environments.
Verifies cryptographic inventory extraction, evidence provenance, and source immutability.
"""

import hashlib
import os
from pathlib import Path
import pytest

from app.scanners.config_scanner.scanner import BankingConfigScanner
from app.scanners.config_scanner.models import EvidenceStatus, CryptoRole

SAMPLE_DIR = Path(__file__).resolve().parent.parent.parent / "sample_data" / "banking"


@pytest.fixture
def scanner():
    return BankingConfigScanner(root_dir=SAMPLE_DIR)


def test_scan_all_seven_banking_systems(scanner):
    results = scanner.scan_all_banking_samples(SAMPLE_DIR)
    expected_systems = {
        "net_banking",
        "upi_backend",
        "payment_gateway",
        "core_banking",
        "interbank",
        "atm",
        "admin_vpn"
    }
    assert set(results.keys()) == expected_systems


def test_net_banking_sample(scanner):
    inv = scanner.scan_directory(SAMPLE_DIR / "net_banking")
    assert inv.system_id == "SAMPLE-BANK-NETBANK-01"
    assert inv.criticality == "HIGH"
    assert inv.exposure == "INTERNET"

    algos = {c.algorithm for c in inv.components if c.algorithm}
    assert "TLS 1.2" in algos or "TLS 1.3" in algos
    assert any("AES" in a for a in algos)
    assert any(c.role == "CERTIFICATE_AUTHENTICATION" for c in inv.components)


def test_upi_backend_sample(scanner):
    inv = scanner.scan_directory(SAMPLE_DIR / "upi_backend")
    assert inv.system_id == "SAMPLE-BANK-UPI-02"
    assert inv.criticality == "CRITICAL"
    assert inv.exposure == "PARTNER"

    algos = {c.algorithm for c in inv.components if c.algorithm}
    assert "X25519MLKEM768" in algos
    assert "ML-DSA-65" in algos
    assert "ML-KEM-768" in algos
    assert "AES-256-GCM" in algos

    # Verify KMS storage asset present
    kms_assets = [c for c in inv.components if c.role == "KEY_STORAGE"]
    assert len(kms_assets) > 0


def test_card_payment_gateway_sample(scanner):
    inv = scanner.scan_directory(SAMPLE_DIR / "payment_gateway")
    assert inv.system_id == "SAMPLE-BANK-CARD-03"

    algos = {c.algorithm for c in inv.components if c.algorithm}
    assert "3DES" in algos
    assert "AES-256-CBC" in algos
    assert "RSA-2048" in algos

    # HSM verification
    hsm_assets = [c for c in inv.components if c.role == "KEY_STORAGE"]
    assert len(hsm_assets) > 0


def test_core_banking_sample(scanner):
    inv = scanner.scan_directory(SAMPLE_DIR / "core_banking")
    assert inv.system_id == "SAMPLE-BANK-CORE-04"
    assert inv.trust_zone == "DATA"
    assert inv.exposure == "RESTRICTED"

    algos = {c.algorithm for c in inv.components if c.algorithm}
    assert "AES-256-GCM" in algos
    assert "RSA-2048" in algos

    wrapping_assets = [c for c in inv.components if c.role == "KEY_WRAPPING"]
    assert len(wrapping_assets) > 0


def test_interbank_swift_sample(scanner):
    inv = scanner.scan_directory(SAMPLE_DIR / "interbank")
    assert inv.system_id == "SAMPLE-BANK-INTERBANK-05"

    algos = {c.algorithm for c in inv.components if c.algorithm}
    assert any("4096" in a for a in algos)
    assert "AES-256-GCM" in algos
    assert "SHA-384" in algos


def test_atm_network_sample(scanner):
    inv = scanner.scan_directory(SAMPLE_DIR / "atm")
    assert inv.system_id in ("SAMPLE-BANK-ATM-06", "SYNTHETIC-ATM-NORTH")

    algos = {c.algorithm for c in inv.components if c.algorithm}
    assert "3DES" in algos
    assert "DES" in algos
    assert any("1024" in a for a in algos)

    # Legacy protocols
    assert any("1.0" in a or "1.1" in a for a in algos)


def test_admin_vpn_sample(scanner):
    inv = scanner.scan_directory(SAMPLE_DIR / "admin_vpn")
    assert inv.system_id == "SAMPLE-BANK-VPN-07"
    assert inv.trust_zone == "ADMIN"

    algos = {c.algorithm for c in inv.components if c.algorithm}
    assert "TLS 1.3" in algos
    assert "AES-256-GCM" in algos
    assert any("384" in a for a in algos)


def test_no_mutation_of_source_files(scanner):
    """Ensure scanner never mutates configuration files."""
    file_hashes_before = {}
    for root, _, files in os.walk(SAMPLE_DIR):
        for f in files:
            path = Path(root) / f
            file_hashes_before[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()

    # Execute scans
    scanner.scan_all_banking_samples(SAMPLE_DIR)

    file_hashes_after = {}
    for root, _, files in os.walk(SAMPLE_DIR):
        for f in files:
            path = Path(root) / f
            file_hashes_after[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()

    assert file_hashes_before == file_hashes_after, "Scanner mutated configuration files!"


def test_deterministic_scanner_output(scanner):
    """Ensure scanner produces deterministic inventory for repeated runs."""
    inv1 = scanner.scan_directory(SAMPLE_DIR / "core_banking")
    inv2 = scanner.scan_directory(SAMPLE_DIR / "core_banking")

    assert len(inv1.components) == len(inv2.components)
    for c1, c2 in zip(inv1.components, inv2.components):
        assert c1.name == c2.name
        assert c1.algorithm == c2.algorithm
        assert c1.role == c2.role
        assert c1.source_file == c2.source_file
        assert c1.source_line == c2.source_line

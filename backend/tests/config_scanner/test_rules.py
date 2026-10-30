"""Tests for Cryptographic Extraction Rules and Agility Assessment.
Validates detection of TLS versions, ciphers, key exchanges, certificates,
cryptographic algorithms, crypto-agility, secret redaction, and invariants.
"""

from pathlib import Path
import pytest

from app.scanners.config_scanner.models import (
    CryptoAgility,
    CryptoRole,
    EvidenceStatus,
)
from app.scanners.config_scanner.parsers import ParsedEntry
from app.scanners.config_scanner.rules import ConfigRuleEngine

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "config_scanner"


def test_tls_versions_detection():
    engine = ConfigRuleEngine(source_file="test_tls.yaml")
    entry = ParsedEntry(path="server.tls.protocols", value=["TLSv1.2", "TLSv1.3"], line=10)
    obs = engine.evaluate_entry(entry)

    tls_obs = [o for o in obs if o.role == CryptoRole.TRANSPORT_SECURITY]
    versions = {o.algorithm for o in tls_obs}
    assert "TLS 1.2" in versions
    assert "TLS 1.3" in versions


def test_hard_invariant_no_kex_inferred_from_tls13():
    """HARD INVARIANT: Do NOT infer TLS 1.3 key exchange merely from a TLS 1.3 version."""
    engine = ConfigRuleEngine(source_file="test_tls.yaml")
    entry = ParsedEntry(path="server.tls.version", value="TLS 1.3", line=12)
    obs = engine.evaluate_entry(entry)

    # Must NOT contain any KEY_EXCHANGE observation
    kex_obs = [o for o in obs if o.role == CryptoRole.KEY_EXCHANGE]
    assert len(kex_obs) == 0, "Violation of hard invariant: key exchange inferred from TLS version alone!"


def test_explicit_key_exchange_detection():
    engine = ConfigRuleEngine(source_file="test_kex.yaml")
    entry = ParsedEntry(path="transport.key_exchange", value="X25519MLKEM768", line=15)
    obs = engine.evaluate_entry(entry)

    kex_obs = [o for o in obs if o.role == CryptoRole.KEY_EXCHANGE]
    assert len(kex_obs) > 0
    assert any(o.algorithm == "X25519MLKEM768" for o in kex_obs)


def test_cipher_suite_detection():
    engine = ConfigRuleEngine(source_file="nginx.conf")
    entry = ParsedEntry(
        path="ssl_server.ssl_ciphers",
        value="ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:DES-CBC3-SHA",
        line=22
    )
    obs = engine.evaluate_entry(entry)

    ciphers = [o.algorithm for o in obs if o.role == CryptoRole.TRANSPORT_SECURITY]
    assert "ECDHE-RSA-AES256-GCM-SHA384" in ciphers
    assert "ECDHE-ECDSA-AES128-GCM-SHA256" in ciphers
    assert "DES-CBC3-SHA" in ciphers


def test_certificate_and_rsa_key_size():
    engine = ConfigRuleEngine(source_file="certs.yaml")
    entry_path = ParsedEntry(path="certificates.primary.certificate_path", value="/etc/ssl/cert.pem", line=30)
    obs_path = engine.evaluate_entry(entry_path)
    assert any(o.role == CryptoRole.CERTIFICATE_AUTHENTICATION for o in obs_path)

    entry_size = ParsedEntry(path="certificates.primary.key_size", value=4096, line=32)
    obs_size = engine.evaluate_entry(entry_size)
    assert any(o.algorithm == "RSA-4096" for o in obs_size)


def test_insecure_certificate_validation():
    engine = ConfigRuleEngine(source_file="insecure.ini")
    entry_peer = ParsedEntry(path="tls.verify_peer", value=False, line=5)
    obs_peer = engine.evaluate_entry(entry_peer)
    assert len(obs_peer) > 0
    assert obs_peer[0].metadata.get("insecure_validation") is True

    entry_trust = ParsedEntry(path="tls.trust_all", value=True, line=6)
    obs_trust = engine.evaluate_entry(entry_trust)
    assert len(obs_trust) > 0
    assert obs_trust[0].metadata.get("insecure_validation") is True


def test_crypto_agility_evaluation():
    engine = ConfigRuleEngine(source_file="agility.yaml")

    # 1. Interpolated variable -> CONFIGURABLE
    entry_interp = ParsedEntry(
        path="crypto.kex",
        value="${KEY_EXCHANGE_ALGO}",
        is_interpolated=True,
        line=2
    )
    obs_interp = engine.evaluate_entry(entry_interp)
    # The agility assessor directly returns CONFIGURABLE
    assert engine._assess_agility(entry_interp, [entry_interp.value]) == CryptoAgility.CONFIGURABLE

    # 2. Multi-algorithm list -> CONFIGURABLE
    entry_list = ParsedEntry(
        path="crypto.ciphers",
        value=["AES-256-GCM", "CHACHA20-POLY1305"],
        is_list=True,
        line=4
    )
    assert engine._assess_agility(entry_list, entry_list.value) == CryptoAgility.CONFIGURABLE

    # 3. Single literal -> HARDCODED
    entry_single = ParsedEntry(
        path="crypto.bulk",
        value="AES-256-CBC",
        is_list=False,
        line=8
    )
    assert engine._assess_agility(entry_single, [entry_single.value]) == CryptoAgility.HARDCODED


def test_key_wrapping_and_hsm_detection():
    engine = ConfigRuleEngine(source_file="core.yaml")
    entry_wrap = ParsedEntry(path="database.key_wrapping_algorithm", value="RSA-2048", line=15)
    obs_wrap = engine.evaluate_entry(entry_wrap)
    assert any(o.role == CryptoRole.KEY_WRAPPING for o in obs_wrap)

    entry_hsm = ParsedEntry(path="database.master_key_storage", value="Thales Luna HSM 7", line=18)
    obs_hsm = engine.evaluate_entry(entry_hsm)
    assert any(o.role == CryptoRole.KEY_STORAGE for o in obs_hsm)


def test_secret_redaction_rule():
    engine = ConfigRuleEngine(source_file="secrets.json")
    entry_pass = ParsedEntry(path="database.db_password", value="MySecretPassword123!", line=4)
    obs_pass = engine.evaluate_entry(entry_pass)

    assert len(obs_pass) == 1
    assert obs_pass[0].secret_redacted is True
    assert obs_pass[0].value == "[REDACTED_SECRET]"
    assert "MySecretPassword123!" not in str(obs_pass[0])

    entry_pem = ParsedEntry(
        path="tls.key_blob",
        value="-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...",
        line=10
    )
    obs_pem = engine.evaluate_entry(entry_pem)
    assert len(obs_pem) == 1
    assert obs_pem[0].secret_redacted is True
    assert obs_pem[0].value == "[REDACTED_PRIVATE_KEY]"

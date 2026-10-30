"""Integration tests for Unified Normalized Evidence Integration."""

import pytest
from app.models.findings import NormalizedFinding
from app.services.finding_normalizer import (
    collect_unified_findings,
    normalize_tls_finding,
    normalize_crypto_misuse_finding,
    normalize_config_finding,
    normalize_profile_evidence_item,
)
from app.services.upgrade_planner import (
    get_system_config_findings,
    get_system_crypto_misuse_findings,
)
from app.scanners.crypto_misuse import CryptoMisuseScanner
from app.scanners.config_scanner import BankingConfigScanner
from app.models.profiles import get_synthetic_profile_by_id


def test_collect_unified_findings_preserves_required_fields():
    """Every unified finding must preserve rule_id, title, value, role, source, evidence_status, severity, risk, message, recommendation."""
    profile = get_synthetic_profile_by_id("BANK-PROF-CORE-BANKING")
    crypto_f = get_system_crypto_misuse_findings(profile.id)
    config_f = get_system_config_findings(profile.id)

    unified = collect_unified_findings(
        system_id=profile.id,
        crypto_misuse_findings=crypto_f,
        config_findings=config_f,
        banking_profile=profile,
    )

    assert len(unified) > 0
    for f in unified:
        assert isinstance(f, NormalizedFinding)
        assert f.rule_id
        assert f.title
        assert f.value
        assert f.role
        assert f.source in ["EXTERNAL_SCAN", "CONFIGURATION_FILE", "CODE_ANALYSIS", "SOURCE_CODE", "OPERATOR_DECLARED", "INFERRED"]
        assert f.evidence_status in ["OBSERVED", "DECLARED", "INFERRED", "NOT_OBSERVABLE", "CAPABILITY_PROBED", "CLASSICAL_ONLY_OBSERVED", "PROBED_UNSUPPORTED"]
        assert f.severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
        assert f.risk in ["QUANTUM", "CLASSICAL", "BOTH"]
        assert f.message
        assert f.recommendation


def test_not_observable_never_converted_to_vulnerable():
    """Invariant: NOT_OBSERVABLE must never be mapped to CRITICAL or HIGH vulnerability."""
    profile = get_synthetic_profile_by_id("BANK-PROF-CORE-BANKING")
    unified = collect_unified_findings(system_id=profile.id, banking_profile=profile)

    not_obs = [f for f in unified if f.evidence_status == "NOT_OBSERVABLE"]
    for f in not_obs:
        assert f.severity not in ["CRITICAL", "HIGH"]
        assert f.severity in ["INFORMATIONAL", "LOW", "MEDIUM"]


def test_inferred_distinguishable_from_observed():
    """INFERRED evidence status must remain distinct from direct OBSERVED status."""
    class DummyTLSFinding:
        id = "TLS-KX-INFERRED"
        title = "Inferred ECDHE Key Exchange"
        category = "key_exchange"
        value = "ECDHE"
        source = "EXTERNAL_SCAN"
        evidence = "INFERRED"
        risk_level = "HIGH"
        is_quantum_vulnerable = True

    norm = normalize_tls_finding(DummyTLSFinding(), system_id="TEST-SYS")
    assert norm.evidence_status == "INFERRED"
    assert norm.source == "EXTERNAL_SCAN"


def test_configuration_declarations_not_represented_as_external_scan():
    """Configuration declarations must have source CONFIGURATION_FILE or OPERATOR_DECLARED, never EXTERNAL_SCAN."""
    profile = get_synthetic_profile_by_id("BANK-PROF-CORE-BANKING")
    config_findings = get_system_config_findings(profile.id)

    unified = collect_unified_findings(system_id=profile.id, config_findings=config_findings)
    for f in unified:
        if f.source == "CONFIGURATION_FILE":
            assert f.source != "EXTERNAL_SCAN"
            assert f.evidence_status in ["OBSERVED", "DECLARED"]


def test_crypto_misuse_detection_on_source_code():
    """Direct scanner test on source code snippets."""
    code_sample = """
import hashlib
from Crypto.Cipher import AES
import random

# Insecure MD5
h = hashlib.md5(b"test").hexdigest()
# Insecure ECB mode
cipher = AES.new(key, AES.MODE_ECB)
# Weak random
token = random.random()
    """
    scanner = CryptoMisuseScanner()
    res = scanner.scan_source(code_sample, language="python", filename="app/crypto.py")
    rule_ids = [f.rule_id for f in res.findings]

    assert any("MD5" in rid for rid in rule_ids)
    assert any("ECB" in rid for rid in rule_ids)
    assert any("RANDOM" in rid for rid in rule_ids)

    for f in res.findings:
        assert f.evidence_status == "OBSERVED"
        assert f.language == "python"
        assert f.file == "app/crypto.py"
        assert f.line is not None


def test_config_scanner_on_manifest_content():
    """Direct scanner test on server configuration manifests."""
    from pathlib import Path
    scanner = BankingConfigScanner()
    inv = scanner.scan_directory(Path("backend/sample_data/banking/net_banking"))
    assert len(inv.observations) > 0
    for obs in inv.observations:
        assert obs.file.endswith(".conf") or obs.file.endswith(".yaml")
        assert obs.evidence_status.value == "OBSERVED"

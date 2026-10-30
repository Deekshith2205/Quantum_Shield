"""Tests for deterministic duplicate cryptographic key detection.
Verifies cross-file correlation, safe fingerprinting, and zero secret leakage.
"""

from pathlib import Path
from app.scanners.crypto_misuse.scanner import CryptoMisuseScanner

CROSS_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "crypto_misuse" / "cross_system"


def test_detect_duplicate_keys_across_assets():
    scanner = CryptoMisuseScanner()
    result = scanner.scan_directory(CROSS_DIR)

    # Filter for duplicate key findings
    dup_findings = [f for f in result.findings if f.rule_id == "MISUSE-DUPLICATE-KEY"]

    assert len(dup_findings) >= 3, f"Expected duplicate key findings across 3 assets, got {len(dup_findings)}"

    # All duplicate findings should reference the shared fingerprint
    for df in dup_findings:
        assert "fingerprint:sha256:" in df.matched_value
        # Raw secret MUST NOT be leaked in matched_value
        assert "bank_shared_master_vault_key_2026" not in df.matched_value
        assert "affected_files" in df.metadata
        # Check affected files includes multiple files
        affected = df.metadata["affected_files"]
        assert len(affected) >= 2
        assert df.role in ("KEY", "SECRET_STORAGE")
        assert df.risk == "SECRET_EXPOSURE"
        assert df.evidence_status == "OBSERVED"
        assert df.severity == "HIGH"


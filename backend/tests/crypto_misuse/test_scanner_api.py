"""Unit tests for CryptoMisuseScanner API contract and security boundaries.
Deterministic, non-network, non-executing.
"""

import json
import tempfile
from pathlib import Path
import pytest
from app.scanners.crypto_misuse.scanner import CryptoMisuseScanner
from app.scanners.crypto_misuse.models import ScanResult, MisuseFinding


def test_scan_source_basic():
    scanner = CryptoMisuseScanner()
    code = 'password = "SuperSecretBankPassword123!"'
    result = scanner.scan_source(code, "python", "auth_snippet.py")

    assert isinstance(result, ScanResult)
    assert result.files_scanned == 1
    assert result.rules_evaluated >= 18
    assert len(result.findings) >= 1

    finding = result.findings[0]
    assert finding.rule_id == "MISUSE-HARDCODED-PASSWORD"
    assert finding.language == "python"
    assert finding.file == "auth_snippet.py"
    assert finding.line == 1
    # Check that plaintext secret is masked
    assert "SuperSecretBankPassword123!" not in finding.matched_value
    assert "*" in finding.matched_value
    assert finding.evidence_status == "OBSERVED"


def test_scan_result_json_serializable():
    scanner = CryptoMisuseScanner()
    code = """
import hashlib
from Crypto.Cipher import AES

aes_key = b"bank_super_aes_key_12345678"
cipher = AES.new(aes_key, AES.MODE_ECB)
"""
    result = scanner.scan_source(code, "python", "test_serialize.py")
    json_str = result.model_dump_json()

    # Must be valid parseable JSON
    parsed = json.loads(json_str)
    assert "findings" in parsed
    assert "files_scanned" in parsed
    assert "rules_evaluated" in parsed
    assert "summary" in parsed
    assert parsed["files_scanned"] == 1
    assert parsed["summary"]["total_findings"] >= 2


def test_scan_file_and_read_only_invariant(tmp_path: Path):
    scanner = CryptoMisuseScanner()
    test_file = tmp_path / "payment.py"
    original_content = 'password = "BankAdminPassword2026!"\n'
    test_file.write_text(original_content, encoding="utf-8")

    result = scanner.scan_file(test_file)

    assert result.files_scanned == 1
    assert len(result.findings) >= 1
    # INVARIANT: Source file must never be mutated
    assert test_file.read_text(encoding="utf-8") == original_content


def test_scan_directory_and_traversal_boundary(tmp_path: Path):
    scanner = CryptoMisuseScanner()

    # Create nested structure
    sub_dir = tmp_path / "services"
    sub_dir.mkdir()
    f1 = sub_dir / "service_a.py"
    f1.write_text('password = "SecretPasswordA123!"\n', encoding="utf-8")

    f2 = sub_dir / "service_b.js"
    f2.write_text('const password = "SecretPasswordB123!";\n', encoding="utf-8")

    result = scanner.scan_directory(tmp_path)
    assert result.files_scanned == 2
    assert result.summary.total_findings >= 2

    # Test unified scan() entrypoint
    unified_dir_result = scanner.scan(tmp_path)
    assert unified_dir_result.files_scanned == 2

    unified_file_result = scanner.scan(f1)
    assert unified_file_result.files_scanned == 1


def test_skip_large_files(tmp_path: Path):
    # Set limit to 10 KB for test
    scanner = CryptoMisuseScanner(max_file_size_bytes=10 * 1024)
    large_file = tmp_path / "huge_file.py"
    # Write 20 KB
    large_file.write_text("a = 1\n" * 3500, encoding="utf-8")

    result = scanner.scan_file(large_file)
    # Oversized file skipped
    assert result.files_scanned == 0
    assert len(result.findings) == 0


def test_skip_binary_files(tmp_path: Path):
    scanner = CryptoMisuseScanner()
    binary_file = tmp_path / "app.py"
    binary_file.write_bytes(b"\x7fELF\x00\x00\x00\x00password = 'secret'\x00")

    result = scanner.scan_file(binary_file)
    assert result.files_scanned == 0
    assert len(result.findings) == 0


def test_empty_file_handling(tmp_path: Path):
    scanner = CryptoMisuseScanner()
    empty_file = tmp_path / "empty.py"
    empty_file.write_text("", encoding="utf-8")

    result = scanner.scan_file(empty_file)
    assert result.files_scanned == 1
    assert len(result.findings) == 0
    assert result.summary.total_findings == 0


def test_nonexistent_target_raises_error():
    scanner = CryptoMisuseScanner()
    with pytest.raises(FileNotFoundError):
        scanner.scan("C:/path/does/not/exist/anywhere")


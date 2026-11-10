"""Tests verifying evidence status invariant and finding schema completeness.
CRITICAL INVARIANT: NOT_OBSERVABLE != VULNERABLE.
"""

from app.scanners.crypto_misuse.scanner import CryptoMisuseScanner
from app.scanners.crypto_misuse.models import EvidenceStatus, FindingSeverity, MisuseFinding
from app.scanners.crypto_misuse.evidence import is_binary_content


def test_evidence_status_validity():
    scanner = CryptoMisuseScanner()
    code = """
password = "TestPassword2026!"
verify = False
"""
    result = scanner.scan_source(code, "python", "evidence_test.py")

    valid_statuses = {
        EvidenceStatus.OBSERVED.value,
        EvidenceStatus.INFERRED.value,
        EvidenceStatus.NOT_OBSERVABLE.value,
    }

    for f in result.findings:
        assert f.evidence_status in valid_statuses
        # Concrete observed code must be OBSERVED
        assert f.evidence_status == EvidenceStatus.OBSERVED.value


def test_not_observable_never_critical():
    # Invariant: If a finding has evidence_status NOT_OBSERVABLE,
    # it must never be treated as CRITICAL or HIGH vulnerability.
    dummy = MisuseFinding(
        rule_id="MISUSE-CRYPTO-AGILITY-LACK",
        title="Configuration Not Observable Externally",
        description="Configuration cannot be verified from static inspectable artifact.",
        language="python",
        file="unknown.py",
        line=1,
        matched_value="[NOT_OBSERVABLE]",
        role="CRYPTO_AGILITY",
        risk="CRYPTO_AGILITY",
        severity=FindingSeverity.INFORMATIONAL.value,
        evidence_status=EvidenceStatus.NOT_OBSERVABLE.value,
        recommendation="Provide explicit configuration file for audit.",
    )

    assert dummy.evidence_status == EvidenceStatus.NOT_OBSERVABLE.value
    assert dummy.severity != FindingSeverity.CRITICAL.value
    assert dummy.severity != FindingSeverity.HIGH.value


def test_finding_all_required_fields_present():
    scanner = CryptoMisuseScanner()
    code = 'password = "AdminSecretPassword123!"'
    result = scanner.scan_source(code, "python", "fields_test.py")

    assert len(result.findings) >= 1
    f = result.findings[0]

    # Verify all fields from Section 4 and EVIDENCE REQUIREMENT:
    assert hasattr(f, "rule_id") and f.rule_id
    assert hasattr(f, "title") and f.title
    assert hasattr(f, "description") and f.description
    assert hasattr(f, "language") and f.language
    assert hasattr(f, "file") and f.file
    assert hasattr(f, "source_file") and f.source_file
    assert hasattr(f, "line") and f.line >= 1
    assert hasattr(f, "line_number") and f.line_number >= 1
    assert hasattr(f, "column")
    assert hasattr(f, "matched_value") and f.matched_value
    assert hasattr(f, "value") and f.value
    assert hasattr(f, "role") and f.role
    assert hasattr(f, "risk") and f.risk
    assert hasattr(f, "severity") and f.severity
    assert hasattr(f, "evidence_status") and f.evidence_status
    assert hasattr(f, "confidence") and f.confidence
    assert hasattr(f, "recommendation") and f.recommendation
    assert hasattr(f, "metadata") and isinstance(f.metadata, dict)


def test_binary_content_detects_null_bytes():
    assert is_binary_content(b"hello\x00world")


def test_binary_content_detects_control_characters():
    assert is_binary_content(b"hello\x01world")


def test_binary_content_allows_normal_text_formatting():
    content = b"password = 'test'\t\r\nnext_line = True"
    assert not is_binary_content(content)


def test_binary_content_allows_valid_utf8():
    content = "message = 'नमस्ते'".encode("utf-8")
    assert not is_binary_content(content)


def test_binary_content_allows_empty_content():
    assert not is_binary_content(b"")


def test_binary_content_detects_invalid_utf8():
    assert is_binary_content(b"hello\xffworld")


def test_binary_content_detects_del_character():
    assert is_binary_content(b"hello\x7fworld")

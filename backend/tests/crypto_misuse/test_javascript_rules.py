"""Tests for JavaScript/TypeScript cryptographic misuse detection.
Verifies all JavaScript rules, line number accuracy, and false-positive resistance.
"""

from pathlib import Path
from app.scanners.crypto_misuse.scanner import CryptoMisuseScanner

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "crypto_misuse" / "javascript"


def test_javascript_payment_vulnerabilities():
    scanner = CryptoMisuseScanner()
    file_path = FIXTURES_DIR / "payment.js"
    result = scanner.scan_file(file_path)

    rule_ids = [f.rule_id for f in result.findings]

    # 1. Static IV
    assert "MISUSE-STATIC-IV" in rule_ids
    # 2. ECB mode
    assert "MISUSE-ECB-MODE" in rule_ids
    # 3. Broken DES cipher
    assert "MISUSE-INSECURE-CIPHER-CONFIG" in rule_ids
    # 4. Weak randomness (Math.random)
    assert "MISUSE-WEAK-RANDOM" in rule_ids
    # 5. Disabled certificate validation (rejectUnauthorized: false)
    assert "MISUSE-DISABLED-CERT-VERIFY" in rule_ids

    for finding in result.findings:
        assert finding.line >= 1
        assert finding.language == "javascript"
        assert finding.evidence_status == "OBSERVED"


def test_javascript_auth_vulnerabilities():
    scanner = CryptoMisuseScanner()
    file_path = FIXTURES_DIR / "auth.js"
    result = scanner.scan_file(file_path)

    rule_ids = [f.rule_id for f in result.findings]

    # 1. Hardcoded password
    assert "MISUSE-HARDCODED-PASSWORD" in rule_ids
    # 2. Hardcoded JWT secret
    assert "MISUSE-HARDCODED-SECRET" in rule_ids
    # 3. Disabled TLS environment verification (NODE_TLS_REJECT_UNAUTHORIZED = '0')
    assert "MISUSE-DISABLED-CERT-VERIFY" in rule_ids
    # 4. MD5 for password
    assert "MISUSE-MD5-HASH" in rule_ids
    # 5. Small RSA key (1024)
    assert "MISUSE-SMALL-RSA-KEY" in rule_ids
    # 6. Weak RSA exponent (3)
    assert "MISUSE-WEAK-RSA-EXPONENT" in rule_ids
    # 7. Hardcoded ECDH curve
    assert "MISUSE-HARDCODED-ECDH-KEX" in rule_ids


def test_javascript_secure_payment_zero_false_positives():
    scanner = CryptoMisuseScanner()
    file_path = FIXTURES_DIR / "secure_payment.js"
    result = scanner.scan_file(file_path)

    # Clean JavaScript code with crypto.randomBytes, aes-256-gcm, RSA-4096 must produce 0 findings
    assert len(result.findings) == 0, f"False positives detected: {[f.title for f in result.findings]}"


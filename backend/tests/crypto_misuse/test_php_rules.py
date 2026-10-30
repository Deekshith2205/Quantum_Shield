"""Tests for PHP cryptographic misuse detection.
Verifies all PHP rules, line number accuracy, and false-positive resistance.
"""

from pathlib import Path
from app.scanners.crypto_misuse.scanner import CryptoMisuseScanner

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "crypto_misuse" / "php"


def test_php_payment_vulnerabilities():
    scanner = CryptoMisuseScanner()
    file_path = FIXTURES_DIR / "payment.php"
    result = scanner.scan_file(file_path)

    rule_ids = [f.rule_id for f in result.findings]

    # 1. Static IV
    assert "MISUSE-STATIC-IV" in rule_ids
    # 2. ECB mode
    assert "MISUSE-ECB-MODE" in rule_ids
    # 3. Broken DES cipher
    assert "MISUSE-INSECURE-CIPHER-CONFIG" in rule_ids
    # 4. Weak randomness (rand)
    assert "MISUSE-WEAK-RANDOM" in rule_ids
    # 5. Disabled certificate validation (CURLOPT_SSL_VERIFYPEER => false)
    assert "MISUSE-DISABLED-CERT-VERIFY" in rule_ids
    # 6. Disabled hostname verification (CURLOPT_SSL_VERIFYHOST => 0)
    assert "MISUSE-DISABLED-HOSTNAME-VERIFY" in rule_ids

    for finding in result.findings:
        assert finding.line >= 1
        assert finding.language == "php"
        assert finding.evidence_status == "OBSERVED"


def test_php_auth_vulnerabilities():
    scanner = CryptoMisuseScanner()
    file_path = FIXTURES_DIR / "auth.php"
    result = scanner.scan_file(file_path)

    rule_ids = [f.rule_id for f in result.findings]

    # 1. Hardcoded password
    assert "MISUSE-HARDCODED-PASSWORD" in rule_ids
    # 2. Hardcoded API secret
    assert "MISUSE-HARDCODED-SECRET" in rule_ids
    # 3. MD5 password hashing
    assert "MISUSE-MD5-HASH" in rule_ids
    # 4. Deprecated SHA-1
    assert "MISUSE-SHA1-HASH" in rule_ids
    # 5. Small RSA key (1024)
    assert "MISUSE-SMALL-RSA-KEY" in rule_ids
    # 6. Weak RSA exponent (3)
    assert "MISUSE-WEAK-RSA-EXPONENT" in rule_ids
    # 7. Hardcoded ECDH curve
    assert "MISUSE-HARDCODED-ECDH-KEX" in rule_ids


def test_php_secure_payment_zero_false_positives():
    scanner = CryptoMisuseScanner()
    file_path = FIXTURES_DIR / "secure_payment.php"
    result = scanner.scan_file(file_path)

    # Clean PHP code with random_bytes, aes-256-gcm, password_hash must produce 0 findings
    assert len(result.findings) == 0, f"False positives detected: {[f.title for f in result.findings]}"


"""Tests for Python cryptographic misuse detection.
Verifies all required rules, line number accuracy, and false-positive resistance.
"""

from pathlib import Path
from app.scanners.crypto_misuse.scanner import CryptoMisuseScanner

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "crypto_misuse" / "python"


def test_python_payment_service_vulnerabilities():
    scanner = CryptoMisuseScanner()
    file_path = FIXTURES_DIR / "payment_service.py"
    result = scanner.scan_file(file_path)

    rule_ids = [f.rule_id for f in result.findings]

    # Must detect:
    # 1. Hardcoded AES key
    assert "MISUSE-HARDCODED-KEY" in rule_ids
    # 2. Static IV
    assert "MISUSE-STATIC-IV" in rule_ids
    # 3. ECB mode
    assert "MISUSE-ECB-MODE" in rule_ids
    # 4. MD5 for password/pin
    assert "MISUSE-MD5-HASH" in rule_ids
    # 5. Broken DES cipher
    assert "MISUSE-INSECURE-CIPHER-CONFIG" in rule_ids

    # Verify line numbers are accurate (greater than 0)
    for finding in result.findings:
        assert finding.line >= 1
        assert finding.column is not None and finding.column >= 1
        assert finding.language == "python"
        assert finding.evidence_status == "OBSERVED"


def test_python_auth_service_vulnerabilities():
    scanner = CryptoMisuseScanner()
    file_path = FIXTURES_DIR / "auth_service.py"
    result = scanner.scan_file(file_path)

    rule_ids = [f.rule_id for f in result.findings]

    # 1. Hardcoded password
    assert "MISUSE-HARDCODED-PASSWORD" in rule_ids
    # 2. Hardcoded API secret / token
    assert "MISUSE-HARDCODED-SECRET" in rule_ids
    # 3. Hardcoded PEM private key
    assert "MISUSE-HARDCODED-KEY" in rule_ids
    # 4. Weak randomness for OTP
    assert "MISUSE-WEAK-RANDOM" in rule_ids
    # 5. Disabled certificate validation
    assert "MISUSE-DISABLED-CERT-VERIFY" in rule_ids
    # 6. Disabled hostname verification
    assert "MISUSE-DISABLED-HOSTNAME-VERIFY" in rule_ids


def test_python_token_service_vulnerabilities():
    scanner = CryptoMisuseScanner()
    file_path = FIXTURES_DIR / "token_service.py"
    result = scanner.scan_file(file_path)

    rule_ids = [f.rule_id for f in result.findings]

    # 1. Static Nonce
    assert "MISUSE-STATIC-NONCE" in rule_ids
    # 2. Inflexible cipher config / agility
    assert "MISUSE-CRYPTO-AGILITY-LACK" in rule_ids
    # 3. Small RSA key size (1024)
    assert "MISUSE-SMALL-RSA-KEY" in rule_ids
    # 4. Weak RSA exponent (e=3)
    assert "MISUSE-WEAK-RSA-EXPONENT" in rule_ids
    # 5. Hardcoded RSA key exchange
    assert "MISUSE-HARDCODED-RSA-KEX" in rule_ids
    # 6. Hardcoded ECDH
    assert "MISUSE-HARDCODED-ECDH-KEX" in rule_ids
    # 7. Deprecated SHA-1
    assert "MISUSE-SHA1-HASH" in rule_ids


def test_python_secure_service_zero_false_positives():
    scanner = CryptoMisuseScanner()
    file_path = FIXTURES_DIR / "secure_payment_service.py"
    result = scanner.scan_file(file_path)

    # Safe banking code using AES-GCM, secrets, verify=True, SHA-256 must produce 0 findings!
    assert len(result.findings) == 0, f"False positives detected: {[f.title for f in result.findings]}"


def test_python_malformed_syntax_fallback():
    # Syntax error in Python: unclosed parenthesis or invalid statement
    malformed_code = """
def broken_syntax(
    password = "HardcodedSecretPassword123!"
    iv = b"0000000000000000"
    AES.MODE_ECB
"""
    scanner = CryptoMisuseScanner()
    result = scanner.scan_source(malformed_code, "python", "malformed.py")

    # Scanner must NOT crash; regex fallback should still identify misuses
    rule_ids = [f.rule_id for f in result.findings]
    assert "MISUSE-HARDCODED-PASSWORD" in rule_ids
    assert "MISUSE-STATIC-IV" in rule_ids
    assert "MISUSE-ECB-MODE" in rule_ids


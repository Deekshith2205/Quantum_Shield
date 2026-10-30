"""Tests for Java cryptographic misuse detection.
Verifies all Java rules, line number accuracy, and false-positive resistance.
"""

from pathlib import Path
from app.scanners.crypto_misuse.scanner import CryptoMisuseScanner

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "crypto_misuse" / "java"


def test_java_payment_gateway_vulnerabilities():
    scanner = CryptoMisuseScanner()
    file_path = FIXTURES_DIR / "PaymentGateway.java"
    result = scanner.scan_file(file_path)

    rule_ids = [f.rule_id for f in result.findings]

    # Must detect:
    # 1. Hardcoded AES key
    assert "MISUSE-HARDCODED-KEY" in rule_ids
    # 2. ECB mode
    assert "MISUSE-ECB-MODE" in rule_ids
    # 3. Static IV (IvParameterSpec)
    assert "MISUSE-STATIC-IV" in rule_ids
    # 4. Weak randomness (new Random())
    assert "MISUSE-WEAK-RANDOM" in rule_ids
    # 5. Broken DES cipher
    assert "MISUSE-INSECURE-CIPHER-CONFIG" in rule_ids

    for finding in result.findings:
        assert finding.line >= 1
        assert finding.language == "java"
        assert finding.evidence_status == "OBSERVED"


def test_java_auth_service_vulnerabilities():
    scanner = CryptoMisuseScanner()
    file_path = FIXTURES_DIR / "AuthService.java"
    result = scanner.scan_file(file_path)

    rule_ids = [f.rule_id for f in result.findings]

    # 1. Hardcoded password
    assert "MISUSE-HARDCODED-PASSWORD" in rule_ids
    # 2. Hardcoded RSA key exchange suite
    assert "MISUSE-HARDCODED-RSA-KEX" in rule_ids
    # 3. MD5 for password
    assert "MISUSE-MD5-HASH" in rule_ids
    # 4. Small RSA key size (1024)
    assert "MISUSE-SMALL-RSA-KEY" in rule_ids
    # 5. Weak RSA exponent (e=3)
    assert "MISUSE-WEAK-RSA-EXPONENT" in rule_ids
    # 6. Disabled Hostname Verification
    assert "MISUSE-DISABLED-HOSTNAME-VERIFY" in rule_ids
    # 7. Disabled Certificate Verification (TrustAllCertificates)
    assert "MISUSE-DISABLED-CERT-VERIFY" in rule_ids


def test_java_secure_payment_gateway_zero_false_positives():
    scanner = CryptoMisuseScanner()
    file_path = FIXTURES_DIR / "SecurePaymentGateway.java"
    result = scanner.scan_file(file_path)

    # Clean Java code with SecureRandom, AES/GCM/NoPadding, RSA-4096 must produce 0 findings
    assert len(result.findings) == 0, f"False positives detected: {[f.title for f in result.findings]}"


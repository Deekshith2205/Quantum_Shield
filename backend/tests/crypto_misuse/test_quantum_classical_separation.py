"""Tests verifying strict separation between Quantum Risk, Classical Risk, and Implementation Flaws.
Enforces the core rule: Do not mix classical and quantum vulnerabilities into one generic score.
"""

from app.scanners.crypto_misuse.scanner import CryptoMisuseScanner
from app.scanners.crypto_misuse.models import RiskCategory


def test_quantum_vs_classical_risk_categorization():
    scanner = CryptoMisuseScanner()

    # Quantum vulnerable construct: Hardcoded RSA key exchange & ECDH
    quantum_code = """
kex = "RSA"
curve = ec.SECP256R1()
"""
    q_result = scanner.scan_source(quantum_code, "python", "quantum_sample.py")
    q_risks = [f.risk for f in q_result.findings]
    assert RiskCategory.QUANTUM_SECURITY.value in q_risks

    # Classical cryptographic flaw: ECB mode and disabled hostname verification
    classical_code = """
cipher = AES.new(key, AES.MODE_ECB)
check_hostname = False
"""
    c_result = scanner.scan_source(classical_code, "python", "classical_sample.py")
    c_risks = [f.risk for f in c_result.findings]
    assert RiskCategory.CLASSICAL_SECURITY.value in c_risks
    # Must NOT be classified as QUANTUM_SECURITY
    assert RiskCategory.QUANTUM_SECURITY.value not in c_risks

    # Classical hash weakness: MD5 and SHA-1
    hash_code = """
h1 = hashlib.md5(b"test").hexdigest()
h2 = hashlib.sha1(b"test").hexdigest()
"""
    h_result = scanner.scan_source(hash_code, "python", "hash_sample.py")
    for f in h_result.findings:
        assert f.risk == RiskCategory.CLASSICAL_SECURITY.value

    # Implementation flaw: Weak randomness & static IV
    impl_code = """
iv = b"0000000000000000"
otp = random.randint(1000, 9999)
"""
    i_result = scanner.scan_source(impl_code, "python", "impl_sample.py")
    i_risks = [f.risk for f in i_result.findings]
    assert RiskCategory.IMPLEMENTATION_SECURITY.value in i_risks
    assert RiskCategory.QUANTUM_SECURITY.value not in i_risks


def test_aes_256_never_marked_quantum_vulnerable():
    scanner = CryptoMisuseScanner()
    # AES-256 is post-quantum secure (Grover requires 2^128 operations)
    aes_code = """
from Crypto.Cipher import AES
key = os.urandom(32)
cipher = AES.new(key, AES.MODE_GCM, nonce=os.urandom(12))
"""
    result = scanner.scan_source(aes_code, "python", "aes_gcm.py")
    # Should have no quantum vulnerability findings
    quantum_findings = [f for f in result.findings if f.risk == RiskCategory.QUANTUM_SECURITY.value]
    assert len(quantum_findings) == 0


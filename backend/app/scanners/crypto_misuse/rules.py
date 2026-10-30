"""Rule catalog and metadata for QuantumShield Crypto-Misuse Scanner.
Covers 20 deterministic cryptographic misuse detection rules across Python, Java, JS, and PHP.
"""

from typing import Dict, Optional
from pydantic import BaseModel
from app.scanners.crypto_misuse.models import (
    CryptoRole,
    FindingSeverity,
    RiskCategory,
    EvidenceStatus,
)


class MisuseRule(BaseModel):
    """Metadata definition for a deterministic crypto-misuse rule."""
    rule_id: str
    title: str
    description: str
    default_role: str
    default_risk: str
    default_severity: str
    default_evidence_status: str
    recommendation: str


RULE_CATALOG: Dict[str, MisuseRule] = {
    "MISUSE-HARDCODED-KEY": MisuseRule(
        rule_id="MISUSE-HARDCODED-KEY",
        title="Hardcoded Cryptographic Key / Private Key",
        description=(
            "Cryptographic key material or private key is directly embedded in source code. "
            "Hardcoded keys cannot be safely rotated, leak in revision history, and expose "
            "encrypted banking payloads to unauthorized decryption."
        ),
        default_role=CryptoRole.KEY.value,
        default_risk=RiskCategory.SECRET_EXPOSURE.value,
        default_severity=FindingSeverity.CRITICAL.value,
        default_evidence_status=EvidenceStatus.OBSERVED.value,
        recommendation=(
            "Extract cryptographic keys into a Hardware Security Module (HSM) or secure "
            "secret management service (e.g. Vault, AWS KMS). Inject credentials via runtime configuration."
        ),
    ),
    "MISUSE-HARDCODED-SECRET": MisuseRule(
        rule_id="MISUSE-HARDCODED-SECRET",
        title="Hardcoded Secret / API Token",
        description=(
            "A sensitive API secret, application secret, or authentication token is hardcoded in source text. "
            "Exposes core banking endpoints and microservices to credential harvesting."
        ),
        default_role=CryptoRole.SECRET.value,
        default_risk=RiskCategory.SECRET_EXPOSURE.value,
        default_severity=FindingSeverity.HIGH.value,
        default_evidence_status=EvidenceStatus.OBSERVED.value,
        recommendation=(
            "Store secrets in environment variables or a dedicated secrets manager. Rotate the exposed secret immediately."
        ),
    ),
    "MISUSE-HARDCODED-PASSWORD": MisuseRule(
        rule_id="MISUSE-HARDCODED-PASSWORD",
        title="Hardcoded Password or Credential",
        description=(
            "Static password or service credential detected in plaintext source code. "
            "Violates banking credential hygiene and enables lateral movement upon repository compromise."
        ),
        default_role=CryptoRole.CREDENTIAL.value,
        default_risk=RiskCategory.SECRET_EXPOSURE.value,
        default_severity=FindingSeverity.HIGH.value,
        default_evidence_status=EvidenceStatus.OBSERVED.value,
        recommendation=(
            "Remove hardcoded passwords. Utilize mutual TLS (mTLS), managed identities, or external secret stores."
        ),
    ),
    "MISUSE-WEAK-RANDOM": MisuseRule(
        rule_id="MISUSE-WEAK-RANDOM",
        title="Weak Pseudorandom Generator for Security Tokens/OTPs",
        description=(
            "Cryptographically weak pseudo-random number generator (e.g. Math.random, rand(), random.random(), "
            "java.util.Random) used for security-critical values such as OTPs, session tokens, nonces, or keys. "
            "Weak PRNG states can be reconstructed by adversaries to predict subsequent values."
        ),
        default_role=CryptoRole.RANDOMNESS.value,
        default_risk=RiskCategory.IMPLEMENTATION_SECURITY.value,
        default_severity=FindingSeverity.HIGH.value,
        default_evidence_status=EvidenceStatus.OBSERVED.value,
        recommendation=(
            "Use a cryptographically secure random number generator (CSPRNG): secrets module in Python, "
            "java.security.SecureRandom in Java, crypto.randomBytes() in JS, or random_bytes() in PHP."
        ),
    ),
    "MISUSE-ECB-MODE": MisuseRule(
        rule_id="MISUSE-ECB-MODE",
        title="Insecure Electronic Codebook (ECB) Mode",
        description=(
            "Electronic Codebook (ECB) mode of operation is used for symmetric bulk encryption. "
            "ECB is not IND-CPA secure: identical plaintext blocks encrypt to identical ciphertext blocks, "
            "revealing patterns and structure in sensitive financial data."
        ),
        default_role=CryptoRole.BULK_ENCRYPTION.value,
        default_risk=RiskCategory.CLASSICAL_SECURITY.value,
        default_severity=FindingSeverity.HIGH.value,
        default_evidence_status=EvidenceStatus.OBSERVED.value,
        recommendation=(
            "Migrate from ECB to an Authenticated Encryption with Associated Data (AEAD) mode such as "
            "AES-GCM (AES-256-GCM) or ChaCha20-Poly1305 with unique nonces."
        ),
    ),
    "MISUSE-STATIC-IV": MisuseRule(
        rule_id="MISUSE-STATIC-IV",
        title="Static / Hardcoded Initialization Vector (IV)",
        description=(
            "A constant or hardcoded Initialization Vector (IV) is supplied to a block cipher. "
            "Static IVs in CBC mode eliminate semantic security, allowing dictionary and replay attacks."
        ),
        default_role=CryptoRole.NONCE_IV.value,
        default_risk=RiskCategory.IMPLEMENTATION_SECURITY.value,
        default_severity=FindingSeverity.HIGH.value,
        default_evidence_status=EvidenceStatus.OBSERVED.value,
        recommendation=(
            "Generate a fresh, cryptographically random IV for every encryption operation using a CSPRNG. "
            "Prepend or store the IV alongside the ciphertext."
        ),
    ),
    "MISUSE-REUSED-IV": MisuseRule(
        rule_id="MISUSE-REUSED-IV",
        title="Reused Initialization Vector Across Operations",
        description=(
            "The same initialization vector is reused across multiple cipher instances or encryption invocations. "
            "In streaming or feedback modes (CTR/OFB/CFB), IV reuse completely destroys confidentiality."
        ),
        default_role=CryptoRole.NONCE_IV.value,
        default_risk=RiskCategory.IMPLEMENTATION_SECURITY.value,
        default_severity=FindingSeverity.HIGH.value,
        default_evidence_status=EvidenceStatus.OBSERVED.value,
        recommendation=(
            "Ensure every encryption operation derives or generates an independent, unique IV."
        ),
    ),
    "MISUSE-STATIC-NONCE": MisuseRule(
        rule_id="MISUSE-STATIC-NONCE",
        title="Static / Hardcoded Cryptographic Nonce",
        description=(
            "A static or fixed nonce is used in an AEAD scheme (e.g. AES-GCM or ChaCha20-Poly1305). "
            "A nonce MUST be used only once per key; static nonces lead to catastrophic loss of confidentiality "
            "and authentication integrity."
        ),
        default_role=CryptoRole.NONCE_IV.value,
        default_risk=RiskCategory.IMPLEMENTATION_SECURITY.value,
        default_severity=FindingSeverity.CRITICAL.value,
        default_evidence_status=EvidenceStatus.OBSERVED.value,
        recommendation=(
            "Generate unique 96-bit nonces using CSPRNG or a deterministic counter for each encryption operation."
        ),
    ),
    "MISUSE-REUSED-NONCE": MisuseRule(
        rule_id="MISUSE-REUSED-NONCE",
        title="Reused Nonce in AEAD Encryption",
        description=(
            "Reused nonce detected in authenticated encryption. Nonce reuse in AES-GCM permits recovery of the "
            "GHASH authentication subkey, allowing ciphertext forgery."
        ),
        default_role=CryptoRole.NONCE_IV.value,
        default_risk=RiskCategory.IMPLEMENTATION_SECURITY.value,
        default_severity=FindingSeverity.CRITICAL.value,
        default_evidence_status=EvidenceStatus.OBSERVED.value,
        recommendation=(
            "Never reuse nonces with the same key. Use AES-GCM-SIV or generate 96-bit random nonces."
        ),
    ),
    "MISUSE-MD5-HASH": MisuseRule(
        rule_id="MISUSE-MD5-HASH",
        title="Insecure MD5 Hash Algorithm in Security Context",
        description=(
            "MD5 algorithm is utilized for passwords, digital signatures, integrity checks, or authentication tokens. "
            "MD5 suffers from practical collision attacks and pre-image vulnerabilities."
        ),
        default_role=CryptoRole.HASH.value,
        default_risk=RiskCategory.CLASSICAL_SECURITY.value,
        default_severity=FindingSeverity.HIGH.value,
        default_evidence_status=EvidenceStatus.OBSERVED.value,
        recommendation=(
            "Replace MD5 with SHA-256/SHA-384 for general hashing, or use Argon2id/bcrypt for password hashing."
        ),
    ),
    "MISUSE-SHA1-HASH": MisuseRule(
        rule_id="MISUSE-SHA1-HASH",
        title="Deprecated SHA-1 Hash Algorithm in Security Context",
        description=(
            "SHA-1 algorithm is utilized for passwords, signatures, or certificates. "
            "Practical collision attacks (SHAttered) make SHA-1 untrusted for security verification."
        ),
        default_role=CryptoRole.HASH.value,
        default_risk=RiskCategory.CLASSICAL_SECURITY.value,
        default_severity=FindingSeverity.MEDIUM.value,
        default_evidence_status=EvidenceStatus.OBSERVED.value,
        recommendation=(
            "Migrate to SHA-256, SHA-384, or SHA-3 for hashing and digital signatures. Use Argon2id for password storage."
        ),
    ),
    "MISUSE-SMALL-RSA-KEY": MisuseRule(
        rule_id="MISUSE-SMALL-RSA-KEY",
        title="Small / Insecure RSA Key Size (< 2048 bits)",
        description=(
            "RSA key generated or configured with a key size below 2048 bits (e.g. 512 or 1024 bits). "
            "RSA-1024 and smaller keys are vulnerable to classical factorization attacks using General Number Field Sieve."
        ),
        default_role=CryptoRole.KEY.value,
        default_risk=RiskCategory.CLASSICAL_SECURITY.value,
        default_severity=FindingSeverity.HIGH.value,
        default_evidence_status=EvidenceStatus.OBSERVED.value,
        recommendation=(
            "Enforce a minimum RSA key size of 2048 bits (3072+ recommended for banking longevity), or migrate to "
            "post-quantum stateful/stateless signature standards (ML-DSA / FIPS 204)."
        ),
    ),
    "MISUSE-WEAK-RSA-EXPONENT": MisuseRule(
        rule_id="MISUSE-WEAK-RSA-EXPONENT",
        title="Weak RSA Public Exponent (e <= 3)",
        description=(
            "RSA key generated with a small public exponent (e=3 or smaller). "
            "Small public exponents are susceptible to Coppersmith's theorem attacks and broadcast attacks when padding is flawed."
        ),
        default_role=CryptoRole.KEY.value,
        default_risk=RiskCategory.CLASSICAL_SECURITY.value,
        default_severity=FindingSeverity.HIGH.value,
        default_evidence_status=EvidenceStatus.OBSERVED.value,
        recommendation=(
            "Use the standard Fermat prime F4 (65537) as the public exponent for all RSA key generations."
        ),
    ),
    "MISUSE-DUPLICATE-KEY": MisuseRule(
        rule_id="MISUSE-DUPLICATE-KEY",
        title="Duplicated Cryptographic Key Material Across Assets",
        description=(
            "The same cryptographic key or secret material appears across multiple distinct sample banking assets or files. "
            "Key reuse across environments breaches fault isolation and escalates blast radius."
        ),
        default_role=CryptoRole.SECRET_STORAGE.value,
        default_risk=RiskCategory.SECRET_EXPOSURE.value,
        default_severity=FindingSeverity.HIGH.value,
        default_evidence_status=EvidenceStatus.OBSERVED.value,
        recommendation=(
            "Isolate cryptographic keys per asset and environment. Rotate duplicated keys and provision independent credentials."
        ),
    ),
    "MISUSE-DISABLED-CERT-VERIFY": MisuseRule(
        rule_id="MISUSE-DISABLED-CERT-VERIFY",
        title="Disabled TLS Certificate Verification",
        description=(
            "TLS/SSL certificate validation is explicitly disabled (e.g. verify=False, rejectUnauthorized: false, "
            "TrustAllCertificates, CURLOPT_SSL_VERIFYPEER => false). Allows Man-In-The-Middle (MITM) attacks on banking traffic."
        ),
        default_role=CryptoRole.CERTIFICATE_VALIDATION.value,
        default_risk=RiskCategory.CLASSICAL_SECURITY.value,
        default_severity=FindingSeverity.CRITICAL.value,
        default_evidence_status=EvidenceStatus.OBSERVED.value,
        recommendation=(
            "Enable strict TLS certificate verification against the system trust store or banking enterprise CA bundle."
        ),
    ),
    "MISUSE-DISABLED-HOSTNAME-VERIFY": MisuseRule(
        rule_id="MISUSE-DISABLED-HOSTNAME-VERIFY",
        title="Disabled TLS Hostname Verification",
        description=(
            "TLS hostname verification is disabled (e.g. check_hostname=False, NoopHostnameVerifier, CURLOPT_SSL_VERIFYHOST => 0). "
            "Enables MITM attackers with any valid certificate to impersonate legitimate banking services."
        ),
        default_role=CryptoRole.CERTIFICATE_VALIDATION.value,
        default_risk=RiskCategory.CLASSICAL_SECURITY.value,
        default_severity=FindingSeverity.HIGH.value,
        default_evidence_status=EvidenceStatus.OBSERVED.value,
        recommendation=(
            "Enable strict hostname verification matching Subject Alternative Name (SAN) fields in TLS certificates."
        ),
    ),
    "MISUSE-HARDCODED-RSA-KEX": MisuseRule(
        rule_id="MISUSE-HARDCODED-RSA-KEX",
        title="Hardcoded RSA Key Exchange (Quantum-Exposed)",
        description=(
            "RSA static key exchange is hardcoded into cipher configuration. RSA key agreement lacks Forward Secrecy "
            "and is fully vulnerable to Shor's algorithm on Cryptanalytically Relevant Quantum Computers (CRQCs) via Store Now Decrypt Later (SNDL)."
        ),
        default_role=CryptoRole.KEY_ESTABLISHMENT.value,
        default_risk=RiskCategory.QUANTUM_SECURITY.value,
        default_severity=FindingSeverity.HIGH.value,
        default_evidence_status=EvidenceStatus.OBSERVED.value,
        recommendation=(
            "Replace static RSA key exchange with hybrid post-quantum key encapsulation (e.g. X25519MLKEM768 / FIPS 203) "
            "providing Ephemeral Forward Secrecy and quantum resistance."
        ),
    ),
    "MISUSE-HARDCODED-ECDH-KEX": MisuseRule(
        rule_id="MISUSE-HARDCODED-ECDH-KEX",
        title="Hardcoded ECDH/ECDHE Key Exchange",
        description=(
            "Elliptic Curve Diffie-Hellman key exchange is hardcoded with no algorithm negotiation or post-quantum fallback. "
            "While providing classical forward secrecy, ECDH is vulnerable to Shor's algorithm on quantum computers."
        ),
        default_role=CryptoRole.KEY_ESTABLISHMENT.value,
        default_risk=RiskCategory.QUANTUM_SECURITY.value,
        default_severity=FindingSeverity.MEDIUM.value,
        default_evidence_status=EvidenceStatus.OBSERVED.value,
        recommendation=(
            "Upgrade key exchange to hybrid PQC KEM (e.g., X25519 + ML-KEM-768 per NIST FIPS 203) with configurable negotiation."
        ),
    ),
    "MISUSE-CRYPTO-AGILITY-LACK": MisuseRule(
        rule_id="MISUSE-CRYPTO-AGILITY-LACK",
        title="Inflexible Cryptographic Algorithm Configuration",
        description=(
            "The cryptographic mechanism appears hardcoded, reducing the ability to migrate to a replacement algorithm without source changes."
        ),
        default_role=CryptoRole.CRYPTO_AGILITY.value,
        default_risk=RiskCategory.CRYPTO_AGILITY.value,
        default_severity=FindingSeverity.LOW.value,
        default_evidence_status=EvidenceStatus.OBSERVED.value,
        recommendation=(
            "Introduce cryptographic agility by configuring cipher suites, hash algorithms, and KEMs via external configuration profiles."
        ),
    ),
    "MISUSE-INSECURE-CIPHER-CONFIG": MisuseRule(
        rule_id="MISUSE-INSECURE-CIPHER-CONFIG",
        title="Insecure / Legacy Cipher Algorithm (DES / 3DES / RC4 / Null Cipher / Static Salt)",
        description=(
            "A deprecated or broken cipher algorithm (such as DES, Triple-DES, RC4, or Null cipher) or a static/zero salt "
            "is configured. These ciphers have known cryptanalytic breaks (Sweet32, RC4 bias, Sweet32 birthday attacks)."
        ),
        default_role=CryptoRole.BULK_ENCRYPTION.value,
        default_risk=RiskCategory.CLASSICAL_SECURITY.value,
        default_severity=FindingSeverity.HIGH.value,
        default_evidence_status=EvidenceStatus.OBSERVED.value,
        recommendation=(
            "Migrate legacy ciphers to AES-256-GCM. Ensure key derivation uses random salts of at least 16 bytes."
        ),
    ),
}


def get_rule(rule_id: str) -> Optional[MisuseRule]:
    """Retrieve rule definition by ID."""
    return RULE_CATALOG.get(rule_id)


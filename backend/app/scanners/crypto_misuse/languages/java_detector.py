"""Java-specific cryptographic misuse detector.
Deterministic static analysis on Java source files.
Never executes or compiles scanned code.
"""

import re
from typing import List, Tuple, Dict, Any
from app.scanners.crypto_misuse.evidence import (
    calculate_line_col,
    mask_secret,
    compute_key_fingerprint,
)
from app.scanners.crypto_misuse.models import (
    MisuseFinding,
    EvidenceStatus,
    CryptoRole,
    RiskCategory,
    FindingSeverity,
)
from app.scanners.crypto_misuse.rules import get_rule
from app.scanners.crypto_misuse.languages.common import (
    find_pem_private_keys,
    is_placeholder_or_env,
)


def analyze_java_source(
    content: str, filename: str
) -> Tuple[List[MisuseFinding], List[Dict[str, Any]]]:
    """
    Perform deterministic static analysis on Java source text.
    Returns findings and detected key material for cross-file duplicate detection.
    """
    findings: List[MisuseFinding] = []
    key_entries: List[Dict[str, Any]] = []

    # 1. Common PEM private keys
    pem_findings, pem_keys = find_pem_private_keys(content, "java", filename)
    findings.extend(pem_findings)
    key_entries.extend(pem_keys)

    lines = content.splitlines()

    # 2. Hardcoded keys, secrets, passwords
    _detect_hardcoded_secrets(content, lines, filename, findings, key_entries)

    # 3. Weak randomness
    _detect_weak_randomness(content, lines, filename, findings)

    # 4. ECB mode
    _detect_ecb_mode(content, lines, filename, findings)

    # 5. Static / Reused IV or Nonce
    _detect_static_iv_and_nonce(content, lines, filename, findings)

    # 6. MD5 / SHA-1 misuse
    _detect_weak_hashes(content, lines, filename, findings)

    # 7. Small RSA keys & weak exponent
    _detect_rsa_parameters(content, lines, filename, findings)

    # 8. Disabled certificate & hostname verification
    _detect_disabled_verification(content, lines, filename, findings)

    # 9. Hardcoded RSA / ECDH key exchange & agility
    _detect_key_exchange_and_agility(content, lines, filename, findings)

    # 10. Insecure cipher configuration (DES, 3DES, RC4, static salt)
    _detect_insecure_ciphers(content, lines, filename, findings)

    return findings, key_entries


def _detect_hardcoded_secrets(
    content: str,
    lines: List[str],
    filename: str,
    findings: List[MisuseFinding],
    key_entries: List[Dict[str, Any]],
) -> None:
    # Passwords in Java: String password = "..." or private String dbPassword = "..."
    pw_pattern = re.compile(
        r"""(?i)\b(?:String|char\[\])\s+(password|passwd|pwd|dbPassword|secretKey|servicePassword|adminPassword)\s*=\s*["']([^"'\r\n]{4,})["']"""
    )
    for match in pw_pattern.finditer(content):
        var_name = match.group(1)
        raw_val = match.group(2)
        start_idx = match.start()
        line_num, col_num = calculate_line_col(content, start_idx)
        line_text = lines[line_num - 1] if line_num <= len(lines) else ""

        if is_placeholder_or_env(raw_val, line_text):
            continue

        rule = get_rule("MISUSE-HARDCODED-PASSWORD")
        masked = mask_secret(raw_val)
        fingerprint = compute_key_fingerprint(raw_val)

        findings.append(
            MisuseFinding(
                rule_id="MISUSE-HARDCODED-PASSWORD",
                title=f"Hardcoded Password in Java Variable '{var_name}'",
                description=rule.description if rule else "Hardcoded password in Java source.",
                language="java",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value=masked,
                role=CryptoRole.CREDENTIAL.value,
                risk=RiskCategory.SECRET_EXPOSURE.value,
                severity=FindingSeverity.HIGH.value,
                evidence_status=EvidenceStatus.OBSERVED.value,
                confidence="HIGH",
                recommendation=rule.recommendation if rule else "Inject secrets from Vault or environment variables.",
                metadata={"variable": var_name, "fingerprint": fingerprint},
            )
        )
        key_entries.append({
            "fingerprint": fingerprint,
            "raw_material": raw_val,
            "file": filename,
            "line": line_num,
            "column": col_num,
            "role": CryptoRole.CREDENTIAL.value,
        })

    # Java SecretKeySpec("...".getBytes()) or hardcoded apiKey
    key_spec_pattern = re.compile(
        r"""(?i)new\s+SecretKeySpec\s*\(\s*["']([^"'\r\n]{8,})["']\.getBytes\(\)"""
    )
    for match in key_spec_pattern.finditer(content):
        raw_val = match.group(1)
        start_idx = match.start()
        line_num, col_num = calculate_line_col(content, start_idx)
        line_text = lines[line_num - 1] if line_num <= len(lines) else ""

        if is_placeholder_or_env(raw_val, line_text):
            continue

        rule = get_rule("MISUSE-HARDCODED-KEY")
        masked = mask_secret(raw_val)
        fingerprint = compute_key_fingerprint(raw_val)

        findings.append(
            MisuseFinding(
                rule_id="MISUSE-HARDCODED-KEY",
                title="Hardcoded Encryption Key in SecretKeySpec",
                description=rule.description if rule else "Direct key literal in SecretKeySpec instantiation.",
                language="java",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value=masked,
                role=CryptoRole.KEY.value,
                risk=RiskCategory.SECRET_EXPOSURE.value,
                severity=FindingSeverity.CRITICAL.value,
                evidence_status=EvidenceStatus.OBSERVED.value,
                confidence="HIGH",
                recommendation=rule.recommendation if rule else "Load cryptographic keys from Java Keystore (JKS) or HSM.",
                metadata={"fingerprint": fingerprint},
            )
        )
        key_entries.append({
            "fingerprint": fingerprint,
            "raw_material": raw_val,
            "file": filename,
            "line": line_num,
            "column": col_num,
            "role": CryptoRole.KEY.value,
        })

    # Hardcoded API keys or AES key constants in Java
    key_const_pattern = re.compile(
        r"""(?i)(?:private|public|protected|static|final|\s)*\b(?:String|byte\[\])\s+([a-zA-Z0-9_]+)\s*=\s*(?:["']([^"'\r\n]{8,})["']|["']([^"'\r\n]{8,})["']\.getBytes\(\))"""
    )
    for match in key_const_pattern.finditer(content):
        var_name = match.group(1)
        if not any(k in var_name.lower() for k in ["api", "key", "secret", "token", "aes", "cipher"]):
            continue
        raw_val = match.group(2) or match.group(3)
        start_idx = match.start()
        line_num, col_num = calculate_line_col(content, start_idx)
        line_text = lines[line_num - 1] if line_num <= len(lines) else ""

        if is_placeholder_or_env(raw_val, line_text):
            continue

        is_crypto_key = any(k in var_name.lower() for k in ["aes", "encryption", "master", "cipher", "hmac", "private"])
        rule_id = "MISUSE-HARDCODED-KEY" if is_crypto_key else "MISUSE-HARDCODED-SECRET"
        role = CryptoRole.KEY.value if is_crypto_key else CryptoRole.SECRET.value
        masked = mask_secret(raw_val)
        fingerprint = compute_key_fingerprint(raw_val)

        findings.append(
            MisuseFinding(
                rule_id=rule_id,
                title=f"Hardcoded Cryptographic Key/Secret in Variable '{var_name}'",
                description=f"Static secret value hardcoded in Java variable '{var_name}'.",
                language="java",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value=masked,
                role=role,
                risk=RiskCategory.SECRET_EXPOSURE.value,
                severity=FindingSeverity.HIGH.value,
                evidence_status=EvidenceStatus.OBSERVED.value,
                confidence="HIGH",
                recommendation="Store secrets outside source code using Java Keystore or enterprise secrets manager.",
                metadata={"variable": var_name, "fingerprint": fingerprint},
            )
        )
        key_entries.append({
            "fingerprint": fingerprint,
            "raw_material": raw_val,
            "file": filename,
            "line": line_num,
            "column": col_num,
            "role": role,
        })


def _detect_weak_randomness(
    content: str, lines: List[str], filename: str, findings: List[MisuseFinding]
) -> None:
    # Java java.util.Random or Math.random()
    pattern = re.compile(
        r"""(?i)(?:new\s+java\.util\.Random\s*\(|new\s+Random\s*\(|\bMath\.random\s*\(\))"""
    )
    rule = get_rule("MISUSE-WEAK-RANDOM")

    for match in pattern.finditer(content):
        start_idx = match.start()
        line_num, col_num = calculate_line_col(content, start_idx)
        line_text = lines[line_num - 1] if line_num <= len(lines) else ""

        is_security = any(
            k in line_text.lower()
            for k in ["token", "otp", "key", "salt", "nonce", "iv", "pin", "session", "auth", "secret", "password"]
        )

        findings.append(
            MisuseFinding(
                rule_id="MISUSE-WEAK-RANDOM",
                title="Weak PRNG ('java.util.Random' or 'Math.random') in Security Context",
                description=(
                    f"Insecure PRNG '{match.group(0)}' detected in Java line: '{line_text.strip()}'. "
                    "java.util.Random utilizes a linear congruential formula (LCG) with only 48 bits of state, "
                    "making generated OTPs and tokens easily predictable."
                ),
                language="java",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value=match.group(0),
                role=CryptoRole.RANDOMNESS.value,
                risk=RiskCategory.IMPLEMENTATION_SECURITY.value,
                severity=FindingSeverity.HIGH.value if is_security else FindingSeverity.MEDIUM.value,
                evidence_status=EvidenceStatus.OBSERVED.value,
                confidence="HIGH",
                recommendation="Replace java.util.Random with java.security.SecureRandom.",
                metadata={"matched_call": match.group(0), "context_line": line_text.strip()},
            )
        )


def _detect_ecb_mode(
    content: str, lines: List[str], filename: str, findings: List[MisuseFinding]
) -> None:
    # Cipher.getInstance("AES/ECB/PKCS5Padding"), Cipher.getInstance("AES/ECB/NoPadding"), etc.
    pattern = re.compile(
        r"""(?i)Cipher\.getInstance\s*\(\s*["']([^"']*(?:/ECB(?:/|$)|MODE_ECB)[^"']*)["']\s*\)"""
    )
    rule = get_rule("MISUSE-ECB-MODE")

    for match in pattern.finditer(content):
        cipher_str = match.group(1)
        start_idx = match.start()
        line_num, col_num = calculate_line_col(content, start_idx)

        findings.append(
            MisuseFinding(
                rule_id="MISUSE-ECB-MODE",
                title="Insecure ECB Mode in Java Cipher.getInstance",
                description=f"Cipher initialized with ECB mode: '{cipher_str}'. Lacks semantic security.",
                language="java",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value=cipher_str,
                role=CryptoRole.BULK_ENCRYPTION.value,
                risk=RiskCategory.CLASSICAL_SECURITY.value,
                severity=FindingSeverity.HIGH.value,
                evidence_status=EvidenceStatus.OBSERVED.value,
                confidence="HIGH",
                recommendation="Migrate to Cipher.getInstance(\"AES/GCM/NoPadding\").",
                metadata={"cipher_transformation": cipher_str},
            )
        )


def _detect_static_iv_and_nonce(
    content: str, lines: List[str], filename: str, findings: List[MisuseFinding]
) -> None:
    # new IvParameterSpec("...".getBytes()) or new IvParameterSpec(new byte[16])
    iv_pattern = re.compile(
        r"""(?i)new\s+IvParameterSpec\s*\(\s*(?:["']([^"'\r\n]+)["']\.getBytes\(\)|new\s+byte\[\s*16\s*\])"""
    )
    rule_iv = get_rule("MISUSE-STATIC-IV")

    for match in iv_pattern.finditer(content):
        start_idx = match.start()
        line_num, col_num = calculate_line_col(content, start_idx)
        raw_val = match.group(0)

        findings.append(
            MisuseFinding(
                rule_id="MISUSE-STATIC-IV",
                title="Static / Hardcoded Initialization Vector (IvParameterSpec)",
                description="Hardcoded byte array or string used as IvParameterSpec. Breaches semantic confidentiality.",
                language="java",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value=mask_secret(raw_val),
                role=CryptoRole.NONCE_IV.value,
                risk=RiskCategory.IMPLEMENTATION_SECURITY.value,
                severity=FindingSeverity.HIGH.value,
                evidence_status=EvidenceStatus.OBSERVED.value,
                confidence="HIGH",
                recommendation="Generate random IV using SecureRandom.nextBytes(new byte[16]).",
                metadata={"expression": raw_val},
            )
        )

    # new GCMParameterSpec(128, "...".getBytes()) or new GCMParameterSpec(128, new byte[12])
    gcm_pattern = re.compile(
        r"""(?i)new\s+GCMParameterSpec\s*\(\s*\d+\s*,\s*(?:["']([^"'\r\n]+)["']\.getBytes\(\)|new\s+byte\[\s*12\s*\])"""
    )
    rule_nonce = get_rule("MISUSE-STATIC-NONCE")

    for match in gcm_pattern.finditer(content):
        start_idx = match.start()
        line_num, col_num = calculate_line_col(content, start_idx)
        raw_val = match.group(0)

        findings.append(
            MisuseFinding(
                rule_id="MISUSE-STATIC-NONCE",
                title="Static Nonce in GCMParameterSpec",
                description="Static nonce used in GCMParameterSpec. Nonce reuse in GCM allows GHASH subkey recovery.",
                language="java",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value=mask_secret(raw_val),
                role=CryptoRole.NONCE_IV.value,
                risk=RiskCategory.IMPLEMENTATION_SECURITY.value,
                severity=FindingSeverity.CRITICAL.value,
                evidence_status=EvidenceStatus.OBSERVED.value,
                confidence="HIGH",
                recommendation="Generate fresh 96-bit nonces via SecureRandom for each GCM encryption call.",
                metadata={"expression": raw_val},
            )
        )


def _detect_weak_hashes(
    content: str, lines: List[str], filename: str, findings: List[MisuseFinding]
) -> None:
    # MessageDigest.getInstance("MD5"), DigestUtils.md5Hex
    md5_pattern = re.compile(
        r"""(?i)(?:MessageDigest\.getInstance\s*\(\s*["']MD5["']\s*\)|DigestUtils\.md5(?:Hex)?\s*\()"""
    )
    for match in md5_pattern.finditer(content):
        start_idx = match.start()
        line_num, col_num = calculate_line_col(content, start_idx)
        line_text = lines[line_num - 1] if line_num <= len(lines) else ""

        is_pw = any(w in line_text.lower() for w in ["password", "pwd", "pass", "cred"])
        role = CryptoRole.PASSWORD_HASHING.value if is_pw else CryptoRole.HASH.value
        severity = FindingSeverity.CRITICAL.value if is_pw else FindingSeverity.HIGH.value

        findings.append(
            MisuseFinding(
                rule_id="MISUSE-MD5-HASH",
                title="MD5 MessageDigest Detected in Java Code",
                description=f"MD5 invoked in: '{line_text.strip()}'. MD5 is cryptographically broken.",
                language="java",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value="MessageDigest.getInstance(\"MD5\")",
                role=role,
                risk=RiskCategory.CLASSICAL_SECURITY.value,
                severity=severity,
                evidence_status=EvidenceStatus.OBSERVED.value,
                confidence="HIGH",
                recommendation="Migrate to SHA-256 for integrity or PBKDF2/Argon2 for passwords.",
                metadata={"context_line": line_text.strip()},
            )
        )

    # MessageDigest.getInstance("SHA-1") or "SHA1"
    sha1_pattern = re.compile(
        r"""(?i)(?:MessageDigest\.getInstance\s*\(\s*["']SHA-?1["']\s*\)|DigestUtils\.sha1(?:Hex)?\s*\()"""
    )
    for match in sha1_pattern.finditer(content):
        start_idx = match.start()
        line_num, col_num = calculate_line_col(content, start_idx)
        line_text = lines[line_num - 1] if line_num <= len(lines) else ""

        is_pw = any(w in line_text.lower() for w in ["password", "pwd", "pass", "cred"])
        role = CryptoRole.PASSWORD_HASHING.value if is_pw else CryptoRole.HASH.value

        findings.append(
            MisuseFinding(
                rule_id="MISUSE-SHA1-HASH",
                title="SHA-1 MessageDigest Detected in Java Code",
                description=f"SHA-1 invoked in: '{line_text.strip()}'. Vulnerable to collision attacks.",
                language="java",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value="MessageDigest.getInstance(\"SHA-1\")",
                role=role,
                risk=RiskCategory.CLASSICAL_SECURITY.value,
                severity=FindingSeverity.HIGH.value if is_pw else FindingSeverity.MEDIUM.value,
                evidence_status=EvidenceStatus.OBSERVED.value,
                confidence="HIGH",
                recommendation="Migrate to MessageDigest.getInstance(\"SHA-256\").",
                metadata={"context_line": line_text.strip()},
            )
        )


def _detect_rsa_parameters(
    content: str, lines: List[str], filename: str, findings: List[MisuseFinding]
) -> None:
    # keyPairGen.initialize(1024) or initialize(512)
    key_size_pattern = re.compile(
        r"""(?i)\.initialize\s*\(\s*(512|1024)\b"""
    )
    for match in key_size_pattern.finditer(content):
        size = int(match.group(1))
        start_idx = match.start()
        line_num, col_num = calculate_line_col(content, start_idx)

        findings.append(
            MisuseFinding(
                rule_id="MISUSE-SMALL-RSA-KEY",
                title=f"Insecure Small RSA Key Size ({size} bits) in Java KeyPairGenerator",
                description=f"KeyPairGenerator initialized with {size} bits.",
                language="java",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value=f"initialize({size})",
                role=CryptoRole.KEY.value,
                risk=RiskCategory.CLASSICAL_SECURITY.value,
                severity=FindingSeverity.CRITICAL.value if size <= 512 else FindingSeverity.HIGH.value,
                evidence_status=EvidenceStatus.OBSERVED.value,
                confidence="HIGH",
                recommendation="Initialize KeyPairGenerator with at least 2048 bits (3072+ recommended).",
                metadata={"key_size_bits": size},
            )
        )

    # Weak exponent: RSAKeyGenParameterSpec(2048, BigInteger.valueOf(3))
    exp_pattern = re.compile(
        r"""(?i)new\s+RSAKeyGenParameterSpec\s*\(\s*\d+\s*,\s*BigInteger\.valueOf\s*\(\s*([13])\s*\)"""
    )
    for match in exp_pattern.finditer(content):
        exp = int(match.group(1))
        start_idx = match.start()
        line_num, col_num = calculate_line_col(content, start_idx)

        findings.append(
            MisuseFinding(
                rule_id="MISUSE-WEAK-RSA-EXPONENT",
                title=f"Weak RSA Exponent (e={exp}) in RSAKeyGenParameterSpec",
                description=f"RSA public exponent explicitly set to {exp}.",
                language="java",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value=f"BigInteger.valueOf({exp})",
                role=CryptoRole.KEY.value,
                risk=RiskCategory.CLASSICAL_SECURITY.value,
                severity=FindingSeverity.HIGH.value,
                evidence_status=EvidenceStatus.OBSERVED.value,
                confidence="HIGH",
                recommendation="Use RSAKeyGenParameterSpec.F4 (65537).",
                metadata={"public_exponent": exp},
            )
        )


def _detect_disabled_verification(
    content: str, lines: List[str], filename: str, findings: List[MisuseFinding]
) -> None:
    # TrustAllCertificates or empty checkServerTrusted in X509TrustManager
    trust_all_pattern = re.compile(
        r"""(?i)(?:TrustAllCertificates|class\s+\w+\s+implements\s+X509TrustManager|TrustStrategy\s*\(?\)?\s*\{[^}]*return\s+true)"""
    )
    for match in trust_all_pattern.finditer(content):
        start_idx = match.start()
        line_num, col_num = calculate_line_col(content, start_idx)
        val = match.group(0)

        findings.append(
            MisuseFinding(
                rule_id="MISUSE-DISABLED-CERT-VERIFY",
                title="Disabled TLS Certificate Verification (All-Trusting TrustManager)",
                description="Custom TrustManager or TrustAllCertificates implementation bypassing TLS chain validation.",
                language="java",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value=val,
                role=CryptoRole.CERTIFICATE_VALIDATION.value,
                risk=RiskCategory.CLASSICAL_SECURITY.value,
                severity=FindingSeverity.CRITICAL.value,
                evidence_status=EvidenceStatus.OBSERVED.value,
                confidence="HIGH",
                recommendation="Use default TrustManagerFactory with enterprise root CA certificates.",
                metadata={"matched_pattern": val},
            )
        )

    # HostnameVerifier returning true: (hostname, session) -> true or ALLOW_ALL_HOSTNAME_VERIFIER or NoopHostnameVerifier
    host_pattern = re.compile(
        r"""(?i)(?:ALLOW_ALL_HOSTNAME_VERIFIER|NoopHostnameVerifier|\(\s*\w+\s*,\s*\w+\s*\)\s*->\s*true)"""
    )
    for match in host_pattern.finditer(content):
        start_idx = match.start()
        line_num, col_num = calculate_line_col(content, start_idx)
        val = match.group(0)

        findings.append(
            MisuseFinding(
                rule_id="MISUSE-DISABLED-HOSTNAME-VERIFY",
                title="Disabled Hostname Verification in Java TLS",
                description="Hostname verification bypassed using permissive verifier. Enables MITM attacks.",
                language="java",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value=val,
                role=CryptoRole.CERTIFICATE_VALIDATION.value,
                risk=RiskCategory.CLASSICAL_SECURITY.value,
                severity=FindingSeverity.HIGH.value,
                evidence_status=EvidenceStatus.OBSERVED.value,
                confidence="HIGH",
                recommendation="Use HttpsURLConnection.getDefaultHostnameVerifier() with strict SAN validation.",
                metadata={"matched_pattern": val},
            )
        )


def _detect_key_exchange_and_agility(
    content: str, lines: List[str], filename: str, findings: List[MisuseFinding]
) -> None:
    # Hardcoded RSA Key Exchange
    rsa_pattern = re.compile(
        r"""(?i)["']TLS_RSA_WITH_AES_[^"']+["']"""
    )
    for match in rsa_pattern.finditer(content):
        start_idx = match.start()
        line_num, col_num = calculate_line_col(content, start_idx)
        val = match.group(0)

        findings.append(
            MisuseFinding(
                rule_id="MISUSE-HARDCODED-RSA-KEX",
                title="Hardcoded RSA Key Exchange Suite",
                description="RSA static key exchange cipher suite configured without forward secrecy or PQC resistance.",
                language="java",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value=val,
                role=CryptoRole.KEY_ESTABLISHMENT.value,
                risk=RiskCategory.QUANTUM_SECURITY.value,
                severity=FindingSeverity.HIGH.value,
                evidence_status=EvidenceStatus.OBSERVED.value,
                confidence="HIGH",
                recommendation="Upgrade to TLS 1.3 with hybrid PQC key exchange.",
                metadata={"cipher_suite": val},
            )
        )

    # KeyAgreement.getInstance("ECDH")
    ecdh_pattern = re.compile(
        r"""(?i)KeyAgreement\.getInstance\s*\(\s*["']ECDH["']\s*\)"""
    )
    for match in ecdh_pattern.finditer(content):
        start_idx = match.start()
        line_num, col_num = calculate_line_col(content, start_idx)
        val = match.group(0)

        findings.append(
            MisuseFinding(
                rule_id="MISUSE-HARDCODED-ECDH-KEX",
                title="Hardcoded ECDH KeyAgreement (Lacks Agility)",
                description="The cryptographic mechanism appears hardcoded, reducing the ability to migrate to a replacement algorithm without source changes.",
                language="java",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value=val,
                role=CryptoRole.KEY_ESTABLISHMENT.value,
                risk=RiskCategory.QUANTUM_SECURITY.value,
                severity=FindingSeverity.MEDIUM.value,
                evidence_status=EvidenceStatus.OBSERVED.value,
                confidence="HIGH",
                recommendation="Adopt post-quantum hybrid KEM (ML-KEM-768 / FIPS 203) with configurable negotiation.",
                metadata={"mechanism": val},
            )
        )


def _detect_insecure_ciphers(
    content: str, lines: List[str], filename: str, findings: List[MisuseFinding]
) -> None:
    # Cipher.getInstance("DES..."), Cipher.getInstance("DESede..."), Cipher.getInstance("RC4...")
    pattern = re.compile(
        r"""(?i)Cipher\.getInstance\s*\(\s*["'](DES(?:ede)?|RC4|ARCFOUR|Blowfish)(?:/[^"']*)?["']\s*\)"""
    )
    for match in pattern.finditer(content):
        start_idx = match.start()
        line_num, col_num = calculate_line_col(content, start_idx)
        cipher_name = match.group(1)

        findings.append(
            MisuseFinding(
                rule_id="MISUSE-INSECURE-CIPHER-CONFIG",
                title=f"Insecure Legacy Cipher ({cipher_name}) in Java Cipher.getInstance",
                description=f"Cipher initialized with legacy cipher '{cipher_name}'. Broken against cryptanalysis.",
                language="java",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value=match.group(0),
                role=CryptoRole.BULK_ENCRYPTION.value,
                risk=RiskCategory.CLASSICAL_SECURITY.value,
                severity=FindingSeverity.HIGH.value,
                evidence_status=EvidenceStatus.OBSERVED.value,
                confidence="HIGH",
                recommendation="Replace legacy ciphers with AES-256-GCM.",
                metadata={"cipher": cipher_name},
            )
        )

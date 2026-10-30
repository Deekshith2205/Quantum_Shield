"""JavaScript/TypeScript cryptographic misuse detector.
Deterministic static analysis on JavaScript and TypeScript source files.
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


def analyze_javascript_source(
    content: str, filename: str
) -> Tuple[List[MisuseFinding], List[Dict[str, Any]]]:
    """
    Perform deterministic static analysis on JavaScript/TypeScript source text.
    Returns findings and detected key material for cross-file duplicate detection.
    """
    findings: List[MisuseFinding] = []
    key_entries: List[Dict[str, Any]] = []

    # 1. Common PEM private keys
    pem_findings, pem_keys = find_pem_private_keys(content, "javascript", filename)
    findings.extend(pem_findings)
    key_entries.extend(pem_keys)

    lines = content.splitlines()

    # 2. Hardcoded keys, secrets, passwords
    _detect_hardcoded_secrets(content, lines, filename, findings, key_entries)

    # 3. Weak randomness (Math.random)
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

    # 9. Hardcoded RSA / ECDH key exchange
    _detect_key_exchange_and_agility(content, lines, filename, findings)

    # 10. Insecure cipher configuration (DES, 3DES, RC4)
    _detect_insecure_ciphers(content, lines, filename, findings)

    return findings, key_entries


def _detect_hardcoded_secrets(
    content: str,
    lines: List[str],
    filename: str,
    findings: List[MisuseFinding],
    key_entries: List[Dict[str, Any]],
) -> None:
    # Passwords in JS: const password = "..." or password: "..."
    pw_pattern = re.compile(
        r"""(?i)\b(?:const|let|var)?\s*(password|passwd|pwd|dbPassword|servicePassword|adminPassword)\s*[:=]\s*["']([^"'\r\n]{4,})["']"""
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
                title=f"Hardcoded Password in Variable '{var_name}'",
                description=rule.description if rule else "Hardcoded password in JavaScript source.",
                language="javascript",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value=masked,
                role=CryptoRole.CREDENTIAL.value,
                risk=RiskCategory.SECRET_EXPOSURE.value,
                severity=FindingSeverity.HIGH.value,
                evidence_status=EvidenceStatus.OBSERVED.value,
                confidence="HIGH",
                recommendation=rule.recommendation if rule else "Store credentials in process.env or secret manager.",
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

    # Keys and secrets in JS: const apiKey = "...", const aesKey = "...", const jwtSecret = "..."
    key_pattern = re.compile(
        r"""(?i)\b(?:const|let|var)?\s*(apiKey|apiSecret|aesKey|encryptionKey|masterKey|jwtSecret|clientSecret|secretKey)\s*[:=]\s*["']([^"'\r\n]{8,})["']"""
    )
    for match in key_pattern.finditer(content):
        var_name = match.group(1)
        raw_val = match.group(2)
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
                title=f"Hardcoded Cryptographic Secret/Key in Variable '{var_name}'",
                description=f"Static secret value hardcoded in JavaScript variable '{var_name}'.",
                language="javascript",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value=masked,
                role=role,
                risk=RiskCategory.SECRET_EXPOSURE.value,
                severity=FindingSeverity.HIGH.value,
                evidence_status=EvidenceStatus.OBSERVED.value,
                confidence="HIGH",
                recommendation="Inject keys securely at runtime via environment variables or cloud secret storage.",
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
    # Math.random() in JS
    pattern = re.compile(r"""\bMath\.random\s*\(\)""")
    rule = get_rule("MISUSE-WEAK-RANDOM")

    for match in pattern.finditer(content):
        start_idx = match.start()
        line_num, col_num = calculate_line_col(content, start_idx)
        line_text = lines[line_num - 1] if line_num <= len(lines) else ""

        is_security = any(
            k in line_text.lower()
            for k in ["token", "otp", "key", "salt", "nonce", "iv", "pin", "session", "auth", "secret", "password", "id"]
        )

        findings.append(
            MisuseFinding(
                rule_id="MISUSE-WEAK-RANDOM",
                title="Insecure 'Math.random()' PRNG in Security-Sensitive Flow",
                description=(
                    f"Math.random() detected in: '{line_text.strip()}'. "
                    "Math.random() is not a cryptographically secure random number generator (CSPRNG)."
                ),
                language="javascript",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value="Math.random()",
                role=CryptoRole.RANDOMNESS.value,
                risk=RiskCategory.IMPLEMENTATION_SECURITY.value,
                severity=FindingSeverity.HIGH.value if is_security else FindingSeverity.MEDIUM.value,
                evidence_status=EvidenceStatus.OBSERVED.value,
                confidence="HIGH",
                recommendation="Replace Math.random() with crypto.randomBytes() or crypto.getRandomValues().",
                metadata={"context_line": line_text.strip()},
            )
        )


def _detect_ecb_mode(
    content: str, lines: List[str], filename: str, findings: List[MisuseFinding]
) -> None:
    # crypto.createCipheriv('aes-128-ecb', ...), 'aes-256-ecb', etc.
    pattern = re.compile(
        r"""(?i)createCipher(?:iv)?\s*\(\s*["']([^"']*(?:-ecb|_ecb)[^"']*)["']"""
    )
    rule = get_rule("MISUSE-ECB-MODE")

    for match in pattern.finditer(content):
        cipher_str = match.group(1)
        start_idx = match.start()
        line_num, col_num = calculate_line_col(content, start_idx)

        findings.append(
            MisuseFinding(
                rule_id="MISUSE-ECB-MODE",
                title="Electronic Codebook (ECB) Mode in Node.js Crypto",
                description=f"Cipher initialized with ECB mode: '{cipher_str}'. Lacks semantic security.",
                language="javascript",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value=cipher_str,
                role=CryptoRole.BULK_ENCRYPTION.value,
                risk=RiskCategory.CLASSICAL_SECURITY.value,
                severity=FindingSeverity.HIGH.value,
                evidence_status=EvidenceStatus.OBSERVED.value,
                confidence="HIGH",
                recommendation="Use an authenticated cipher such as 'aes-256-gcm' with a unique 96-bit IV.",
                metadata={"cipher": cipher_str},
            )
        )


def _detect_static_iv_and_nonce(
    content: str, lines: List[str], filename: str, findings: List[MisuseFinding]
) -> None:
    # Buffer.from('fixed_iv...'), Buffer.alloc(16, 0), or static string iv
    iv_pattern = re.compile(
        r"""(?i)\b(?:const|let|var)?\s*(iv|initializationVector)\s*=\s*(?:Buffer\.from\s*\(\s*["']([^"'\r\n]+)["']|Buffer\.alloc\s*\(\s*16\s*,\s*0\s*\)|["']([0-9a-fA-F]{16,32})["'])"""
    )
    rule_iv = get_rule("MISUSE-STATIC-IV")

    for match in iv_pattern.finditer(content):
        start_idx = match.start()
        line_num, col_num = calculate_line_col(content, start_idx)
        raw_val = match.group(0)

        findings.append(
            MisuseFinding(
                rule_id="MISUSE-STATIC-IV",
                title="Static / Hardcoded Initialization Vector (IV)",
                description="Hardcoded or zero-filled buffer used as IV. Eliminates semantic encryption security.",
                language="javascript",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value=mask_secret(raw_val),
                role=CryptoRole.NONCE_IV.value,
                risk=RiskCategory.IMPLEMENTATION_SECURITY.value,
                severity=FindingSeverity.HIGH.value,
                evidence_status=EvidenceStatus.OBSERVED.value,
                confidence="HIGH",
                recommendation="Generate random IV via crypto.randomBytes(16).",
                metadata={"expression": raw_val},
            )
        )

    # Static nonce in JS
    nonce_pattern = re.compile(
        r"""(?i)\b(?:const|let|var)?\s*(nonce)\s*=\s*(?:Buffer\.from\s*\(\s*["']([^"'\r\n]+)["']|Buffer\.alloc\s*\(\s*12\s*,\s*0\s*\)|["']([0-9a-zA-Z]{12,24})["'])"""
    )
    rule_nonce = get_rule("MISUSE-STATIC-NONCE")

    for match in nonce_pattern.finditer(content):
        start_idx = match.start()
        line_num, col_num = calculate_line_col(content, start_idx)
        raw_val = match.group(0)

        findings.append(
            MisuseFinding(
                rule_id="MISUSE-STATIC-NONCE",
                title="Static Cryptographic Nonce in JavaScript",
                description="Hardcoded nonce detected. Reusing nonces in GCM allows forgery attacks.",
                language="javascript",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value=mask_secret(raw_val),
                role=CryptoRole.NONCE_IV.value,
                risk=RiskCategory.IMPLEMENTATION_SECURITY.value,
                severity=FindingSeverity.CRITICAL.value,
                evidence_status=EvidenceStatus.OBSERVED.value,
                confidence="HIGH",
                recommendation="Generate fresh nonces using crypto.randomBytes(12).",
                metadata={"expression": raw_val},
            )
        )


def _detect_weak_hashes(
    content: str, lines: List[str], filename: str, findings: List[MisuseFinding]
) -> None:
    # crypto.createHash('md5'), crypto.createHash('sha1')
    hash_pattern = re.compile(
        r"""(?i)createHash\s*\(\s*["'](md5|sha1)["']\s*\)"""
    )
    for match in hash_pattern.finditer(content):
        algo = match.group(1).lower()
        start_idx = match.start()
        line_num, col_num = calculate_line_col(content, start_idx)
        line_text = lines[line_num - 1] if line_num <= len(lines) else ""

        is_pw = any(w in line_text.lower() for w in ["password", "pwd", "pass", "cred"])
        rule_id = "MISUSE-MD5-HASH" if algo == "md5" else "MISUSE-SHA1-HASH"
        role = CryptoRole.PASSWORD_HASHING.value if is_pw else CryptoRole.HASH.value
        severity = FindingSeverity.CRITICAL.value if is_pw else (FindingSeverity.HIGH.value if algo == "md5" else FindingSeverity.MEDIUM.value)

        findings.append(
            MisuseFinding(
                rule_id=rule_id,
                title=f"Insecure Hash Algorithm ({algo.upper()}) in createHash",
                description=f"{algo.upper()} invoked in: '{line_text.strip()}'. Vulnerable to collision attacks.",
                language="javascript",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value=f"createHash('{algo}')",
                role=role,
                risk=RiskCategory.CLASSICAL_SECURITY.value,
                severity=severity,
                evidence_status=EvidenceStatus.OBSERVED.value,
                confidence="HIGH",
                recommendation="Use 'sha256' or 'sha384' for hashing, or argon2/bcrypt for passwords.",
                metadata={"algorithm": algo, "context_line": line_text.strip()},
            )
        )


def _detect_rsa_parameters(
    content: str, lines: List[str], filename: str, findings: List[MisuseFinding]
) -> None:
    # modulusLength: 1024 or modulusLength: 512
    rsa_pattern = re.compile(
        r"""(?i)\bmodulusLength\s*:\s*(512|1024)\b"""
    )
    for match in rsa_pattern.finditer(content):
        size = int(match.group(1))
        start_idx = match.start()
        line_num, col_num = calculate_line_col(content, start_idx)

        findings.append(
            MisuseFinding(
                rule_id="MISUSE-SMALL-RSA-KEY",
                title=f"Insecure Small RSA Key Size ({size} bits) in Node.js generateKeyPair",
                description=f"RSA modulusLength set to {size} bits.",
                language="javascript",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value=f"modulusLength: {size}",
                role=CryptoRole.KEY.value,
                risk=RiskCategory.CLASSICAL_SECURITY.value,
                severity=FindingSeverity.CRITICAL.value if size <= 512 else FindingSeverity.HIGH.value,
                evidence_status=EvidenceStatus.OBSERVED.value,
                confidence="HIGH",
                recommendation="Enforce modulusLength >= 2048 (3072+ recommended).",
                metadata={"key_size_bits": size},
            )
        )

    # Weak exponent: publicExponent: 3
    exp_pattern = re.compile(r"""(?i)\bpublicExponent\s*:\s*([13])\b""")
    for match in exp_pattern.finditer(content):
        exp = int(match.group(1))
        start_idx = match.start()
        line_num, col_num = calculate_line_col(content, start_idx)

        findings.append(
            MisuseFinding(
                rule_id="MISUSE-WEAK-RSA-EXPONENT",
                title=f"Weak RSA Public Exponent (e={exp}) in Node.js Key Generation",
                description=f"RSA publicExponent explicitly configured as {exp}.",
                language="javascript",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value=f"publicExponent: {exp}",
                role=CryptoRole.KEY.value,
                risk=RiskCategory.CLASSICAL_SECURITY.value,
                severity=FindingSeverity.HIGH.value,
                evidence_status=EvidenceStatus.OBSERVED.value,
                confidence="HIGH",
                recommendation="Use standard Fermat exponent (65537 / 0x10001).",
                metadata={"public_exponent": exp},
            )
        )


def _detect_disabled_verification(
    content: str, lines: List[str], filename: str, findings: List[MisuseFinding]
) -> None:
    # rejectUnauthorized: false or NODE_TLS_REJECT_UNAUTHORIZED = '0'
    cert_pattern = re.compile(
        r"""(?i)(?:rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]0['"])"""
    )
    for match in cert_pattern.finditer(content):
        start_idx = match.start()
        line_num, col_num = calculate_line_col(content, start_idx)
        val = match.group(0)

        findings.append(
            MisuseFinding(
                rule_id="MISUSE-DISABLED-CERT-VERIFY",
                title="Disabled TLS Certificate Verification (rejectUnauthorized: false)",
                description=f"TLS certificate validation bypassed via '{val}'. Allows MITM attacks.",
                language="javascript",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value=val,
                role=CryptoRole.CERTIFICATE_VALIDATION.value,
                risk=RiskCategory.CLASSICAL_SECURITY.value,
                severity=FindingSeverity.CRITICAL.value,
                evidence_status=EvidenceStatus.OBSERVED.value,
                confidence="HIGH",
                recommendation="Enable strict TLS validation (rejectUnauthorized: true).",
                metadata={"matched_pattern": val},
            )
        )

    # checkServerIdentity: () => {} (disabled hostname verification)
    host_pattern = re.compile(
        r"""(?i)checkServerIdentity\s*:\s*(?:\(\s*\)\s*=>|function\s*\([^)]*\)\s*\{[^}]*\})"""
    )
    for match in host_pattern.finditer(content):
        start_idx = match.start()
        line_num, col_num = calculate_line_col(content, start_idx)
        val = match.group(0)

        findings.append(
            MisuseFinding(
                rule_id="MISUSE-DISABLED-HOSTNAME-VERIFY",
                title="Disabled Hostname Verification (checkServerIdentity bypass)",
                description="Custom checkServerIdentity function bypassing hostname checks.",
                language="javascript",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value=val,
                role=CryptoRole.CERTIFICATE_VALIDATION.value,
                risk=RiskCategory.CLASSICAL_SECURITY.value,
                severity=FindingSeverity.HIGH.value,
                evidence_status=EvidenceStatus.OBSERVED.value,
                confidence="HIGH",
                recommendation="Rely on standard TLS hostname verification.",
                metadata={"matched_pattern": val},
            )
        )


def _detect_key_exchange_and_agility(
    content: str, lines: List[str], filename: str, findings: List[MisuseFinding]
) -> None:
    # Hardcoded ECDH: crypto.createECDH('secp256r1') or 'prime256v1'
    ecdh_pattern = re.compile(
        r"""(?i)createECDH\s*\(\s*["']([^"']+)["']\s*\)"""
    )
    for match in ecdh_pattern.finditer(content):
        curve = match.group(1)
        start_idx = match.start()
        line_num, col_num = calculate_line_col(content, start_idx)

        findings.append(
            MisuseFinding(
                rule_id="MISUSE-HARDCODED-ECDH-KEX",
                title=f"Hardcoded ECDH Curve ({curve})",
                description="The cryptographic mechanism appears hardcoded, reducing the ability to migrate to a replacement algorithm without source changes.",
                language="javascript",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value=f"createECDH('{curve}')",
                role=CryptoRole.KEY_ESTABLISHMENT.value,
                risk=RiskCategory.QUANTUM_SECURITY.value,
                severity=FindingSeverity.MEDIUM.value,
                evidence_status=EvidenceStatus.OBSERVED.value,
                confidence="HIGH",
                recommendation="Adopt post-quantum hybrid KEM (ML-KEM-768 / FIPS 203) with configurable negotiation.",
                metadata={"curve": curve},
            )
        )


def _detect_insecure_ciphers(
    content: str, lines: List[str], filename: str, findings: List[MisuseFinding]
) -> None:
    # createCipheriv('des-cbc', ...), 'des-ede3', 'rc4'
    pattern = re.compile(
        r"""(?i)createCipher(?:iv)?\s*\(\s*["'](des(?:-[a-z0-9]+)?|des3|des-ede3|rc4)(?:-[a-z0-9]+)?["']"""
    )
    for match in pattern.finditer(content):
        cipher = match.group(1)
        start_idx = match.start()
        line_num, col_num = calculate_line_col(content, start_idx)

        findings.append(
            MisuseFinding(
                rule_id="MISUSE-INSECURE-CIPHER-CONFIG",
                title=f"Insecure Broken Cipher ({cipher}) in Node.js Crypto",
                description=f"Legacy cipher '{cipher}' used in createCipher. Broken against cryptanalysis.",
                language="javascript",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value=match.group(0),
                role=CryptoRole.BULK_ENCRYPTION.value,
                risk=RiskCategory.CLASSICAL_SECURITY.value,
                severity=FindingSeverity.HIGH.value,
                evidence_status=EvidenceStatus.OBSERVED.value,
                confidence="HIGH",
                recommendation="Migrate to 'aes-256-gcm'.",
                metadata={"cipher": cipher},
            )
        )

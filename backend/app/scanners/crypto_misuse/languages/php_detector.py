"""PHP-specific cryptographic misuse detector.
Deterministic static analysis on PHP source files.
Never executes or evals scanned code.
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


def analyze_php_source(
    content: str, filename: str
) -> Tuple[List[MisuseFinding], List[Dict[str, Any]]]:
    """
    Perform deterministic static analysis on PHP source text.
    Returns findings and detected key material for cross-file duplicate detection.
    """
    findings: List[MisuseFinding] = []
    key_entries: List[Dict[str, Any]] = []

    # 1. Common PEM private keys
    pem_findings, pem_keys = find_pem_private_keys(content, "php", filename)
    findings.extend(pem_findings)
    key_entries.extend(pem_keys)

    lines = content.splitlines()

    # 2. Hardcoded keys, secrets, passwords
    _detect_hardcoded_secrets(content, lines, filename, findings, key_entries)

    # 3. Weak randomness (rand, mt_rand)
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

    # 10. Insecure cipher configuration (DES, 3DES, RC4, mcrypt)
    _detect_insecure_ciphers(content, lines, filename, findings)

    return findings, key_entries


def _detect_hardcoded_secrets(
    content: str,
    lines: List[str],
    filename: str,
    findings: List[MisuseFinding],
    key_entries: List[Dict[str, Any]],
) -> None:
    # Passwords in PHP: $password = "..." or define('DB_PASSWORD', '...')
    pw_pattern = re.compile(
        r"""(?i)(?:\$(?:password|passwd|pwd|db_pass|db_password|admin_pass)|define\s*\(\s*['"](?:DB_PASS|PASSWORD|ADMIN_PASS)['"]\s*,)\s*=\s*["']([^"'\r\n]{4,})["']"""
    )
    for match in pw_pattern.finditer(content):
        raw_val = match.group(1)
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
                title="Hardcoded Password in PHP Source",
                description=rule.description if rule else "Hardcoded password in PHP file.",
                language="php",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value=masked,
                role=CryptoRole.CREDENTIAL.value,
                risk=RiskCategory.SECRET_EXPOSURE.value,
                severity=FindingSeverity.HIGH.value,
                evidence_status=EvidenceStatus.OBSERVED.value,
                confidence="HIGH",
                recommendation=rule.recommendation if rule else "Store passwords in $_ENV or external secrets vault.",
                metadata={"fingerprint": fingerprint},
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

    # Keys and secrets in PHP: $api_key = "...", $encryption_key = "...", $secret_key = "..."
    key_pattern = re.compile(
        r"""(?i)\$((?:api_key|secret_key|aes_key|encryption_key|master_key|jwt_secret))\s*=\s*["']([^"'\r\n]{8,})["']"""
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
                title=f"Hardcoded Cryptographic Secret/Key in '${var_name}'",
                description=f"Static secret value hardcoded in PHP variable '${var_name}'.",
                language="php",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value=masked,
                role=role,
                risk=RiskCategory.SECRET_EXPOSURE.value,
                severity=FindingSeverity.HIGH.value,
                evidence_status=EvidenceStatus.OBSERVED.value,
                confidence="HIGH",
                recommendation="Store keys outside source code in KMS or protected environment configuration.",
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
    # rand(), mt_rand(), array_rand()
    pattern = re.compile(r"""\b(rand|mt_rand|array_rand)\s*\(""")
    rule = get_rule("MISUSE-WEAK-RANDOM")

    for match in pattern.finditer(content):
        fn_name = match.group(1)
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
                title=f"Weak PRNG '{fn_name}()' Used for Security-Sensitive Value",
                description=(
                    f"PHP '{fn_name}()' detected in: '{line_text.strip()}'. "
                    f"'{fn_name}()' produces predictable pseudo-random sequences and is not cryptographically secure."
                ),
                language="php",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value=f"{fn_name}()",
                role=CryptoRole.RANDOMNESS.value,
                risk=RiskCategory.IMPLEMENTATION_SECURITY.value,
                severity=FindingSeverity.HIGH.value if is_security else FindingSeverity.MEDIUM.value,
                evidence_status=EvidenceStatus.OBSERVED.value,
                confidence="HIGH",
                recommendation="Replace with random_bytes() or random_int() (available in PHP 7+).",
                metadata={"function": fn_name, "context_line": line_text.strip()},
            )
        )


def _detect_ecb_mode(
    content: str, lines: List[str], filename: str, findings: List[MisuseFinding]
) -> None:
    # openssl_encrypt($data, 'aes-128-ecb', ...), MCRYPT_MODE_ECB
    pattern = re.compile(
        r"""(?i)(?:openssl_encrypt\s*\([^,]+,\s*['"]([^'"]*(?:-ecb|_ecb)[^'"]*)['"]|MCRYPT_MODE_ECB)"""
    )
    rule = get_rule("MISUSE-ECB-MODE")

    for match in pattern.finditer(content):
        start_idx = match.start()
        line_num, col_num = calculate_line_col(content, start_idx)
        val = match.group(1) if match.group(1) else match.group(0)

        findings.append(
            MisuseFinding(
                rule_id="MISUSE-ECB-MODE",
                title="Electronic Codebook (ECB) Mode in PHP OpenSSL",
                description=f"Cipher configured with ECB mode: '{val}'. Lacks semantic security.",
                language="php",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value=val,
                role=CryptoRole.BULK_ENCRYPTION.value,
                risk=RiskCategory.CLASSICAL_SECURITY.value,
                severity=FindingSeverity.HIGH.value,
                evidence_status=EvidenceStatus.OBSERVED.value,
                confidence="HIGH",
                recommendation="Migrate to 'aes-256-gcm' with a random 12-byte IV.",
                metadata={"cipher": val},
            )
        )


def _detect_static_iv_and_nonce(
    content: str, lines: List[str], filename: str, findings: List[MisuseFinding]
) -> None:
    # $iv = "1234567890123456" or str_repeat("\0", 16)
    iv_pattern = re.compile(
        r"""(?i)\$iv\s*=\s*(?:["']([^"'\r\n]{16,32})["']|str_repeat\s*\(\s*["']\\0["']\s*,\s*16\s*\))"""
    )
    rule_iv = get_rule("MISUSE-STATIC-IV")

    for match in iv_pattern.finditer(content):
        start_idx = match.start()
        line_num, col_num = calculate_line_col(content, start_idx)
        val = match.group(0)

        findings.append(
            MisuseFinding(
                rule_id="MISUSE-STATIC-IV",
                title="Static / Hardcoded Initialization Vector in PHP",
                description="Hardcoded string used as IV in encryption. Destroys semantic security.",
                language="php",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value=mask_secret(val),
                role=CryptoRole.NONCE_IV.value,
                risk=RiskCategory.IMPLEMENTATION_SECURITY.value,
                severity=FindingSeverity.HIGH.value,
                evidence_status=EvidenceStatus.OBSERVED.value,
                confidence="HIGH",
                recommendation="Generate fresh IV via openssl_random_pseudo_bytes(16) or random_bytes(16).",
                metadata={"expression": val},
            )
        )


def _detect_weak_hashes(
    content: str, lines: List[str], filename: str, findings: List[MisuseFinding]
) -> None:
    # md5($pass), sha1($pass), hash('md5', ...), hash('sha1', ...)
    pattern = re.compile(
        r"""(?i)(?:\b(md5|sha1)\s*\(\s*(\$[a-zA-Z0-9_]+)?|hash\s*\(\s*['"](md5|sha1)['"]\s*,\s*(\$[a-zA-Z0-9_]+)?)"""
    )
    for match in pattern.finditer(content):
        algo = (match.group(1) or match.group(3)).lower()
        arg_var = (match.group(2) or match.group(4) or "").lower()
        start_idx = match.start()
        line_num, col_num = calculate_line_col(content, start_idx)
        line_text = lines[line_num - 1] if line_num <= len(lines) else ""

        is_pw = any(w in arg_var or w in line_text.lower() for w in ["password", "pwd", "pass", "cred", "pin"])
        rule_id = "MISUSE-MD5-HASH" if algo == "md5" else "MISUSE-SHA1-HASH"
        role = CryptoRole.PASSWORD_HASHING.value if is_pw else CryptoRole.HASH.value
        severity = FindingSeverity.CRITICAL.value if is_pw else (FindingSeverity.HIGH.value if algo == "md5" else FindingSeverity.MEDIUM.value)
        title = f"{algo.upper()} Used for Password Hashing" if is_pw else f"Deprecated {algo.upper()} Hash Function"

        findings.append(
            MisuseFinding(
                rule_id=rule_id,
                title=title,
                description=f"{algo.upper()} invoked in: '{line_text.strip()}'. Vulnerable to collision attacks.",
                language="php",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value=f"{algo}(...)",
                role=role,
                risk=RiskCategory.CLASSICAL_SECURITY.value,
                severity=severity,
                evidence_status=EvidenceStatus.OBSERVED.value,
                confidence="HIGH",
                recommendation="Use password_hash($password, PASSWORD_BCRYPT) or hash('sha256', ...) for digests.",
                metadata={"algorithm": algo, "context_line": line_text.strip()},
            )
        )


def _detect_rsa_parameters(
    content: str, lines: List[str], filename: str, findings: List[MisuseFinding]
) -> None:
    # openssl_pkey_new(['private_key_bits' => 1024])
    rsa_pattern = re.compile(
        r"""(?i)['"]private_key_bits['"]\s*=>\s*(512|1024)\b"""
    )
    for match in rsa_pattern.finditer(content):
        size = int(match.group(1))
        start_idx = match.start()
        line_num, col_num = calculate_line_col(content, start_idx)

        findings.append(
            MisuseFinding(
                rule_id="MISUSE-SMALL-RSA-KEY",
                title=f"Insecure Small RSA Key Size ({size} bits) in PHP openssl_pkey_new",
                description=f"private_key_bits configured with {size} bits.",
                language="php",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value=f"'private_key_bits' => {size}",
                role=CryptoRole.KEY.value,
                risk=RiskCategory.CLASSICAL_SECURITY.value,
                severity=FindingSeverity.CRITICAL.value if size <= 512 else FindingSeverity.HIGH.value,
                evidence_status=EvidenceStatus.OBSERVED.value,
                confidence="HIGH",
                recommendation="Enforce 'private_key_bits' => 2048 or higher.",
                metadata={"key_size_bits": size},
            )
        )

    # Weak exponent: 'rsa_exponent' => 3
    exp_pattern = re.compile(r"""(?i)['"]rsa_exponent['"]\s*=>\s*([13])\b""")
    for match in exp_pattern.finditer(content):
        exp = int(match.group(1))
        start_idx = match.start()
        line_num, col_num = calculate_line_col(content, start_idx)

        findings.append(
            MisuseFinding(
                rule_id="MISUSE-WEAK-RSA-EXPONENT",
                title=f"Weak RSA Exponent (e={exp}) in openssl_pkey_new",
                description=f"RSA exponent explicitly configured as {exp}.",
                language="php",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value=f"'rsa_exponent' => {exp}",
                role=CryptoRole.KEY.value,
                risk=RiskCategory.CLASSICAL_SECURITY.value,
                severity=FindingSeverity.HIGH.value,
                evidence_status=EvidenceStatus.OBSERVED.value,
                confidence="HIGH",
                recommendation="Use default Fermat prime F4 (65537).",
                metadata={"public_exponent": exp},
            )
        )


def _detect_disabled_verification(
    content: str, lines: List[str], filename: str, findings: List[MisuseFinding]
) -> None:
    # CURLOPT_SSL_VERIFYPEER => false / 0 or curl_setopt(..., CURLOPT_SSL_VERIFYPEER, false/0)
    cert_pattern = re.compile(
        r"""(?i)(?:CURLOPT_SSL_VERIFYPEER\s*(?:=>|,)\s*(?:false|0)|['"]verify_peer['"]\s*=>\s*false)"""
    )
    for match in cert_pattern.finditer(content):
        start_idx = match.start()
        line_num, col_num = calculate_line_col(content, start_idx)
        val = match.group(0)

        findings.append(
            MisuseFinding(
                rule_id="MISUSE-DISABLED-CERT-VERIFY",
                title="Disabled TLS Peer Verification in PHP (CURLOPT_SSL_VERIFYPEER)",
                description=f"TLS certificate verification disabled via '{val}'. Allows MITM attacks.",
                language="php",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value=val,
                role=CryptoRole.CERTIFICATE_VALIDATION.value,
                risk=RiskCategory.CLASSICAL_SECURITY.value,
                severity=FindingSeverity.CRITICAL.value,
                evidence_status=EvidenceStatus.OBSERVED.value,
                confidence="HIGH",
                recommendation="Set CURLOPT_SSL_VERIFYPEER => true and provide a valid CA bundle.",
                metadata={"matched_pattern": val},
            )
        )

    # CURLOPT_SSL_VERIFYHOST => 0 / false
    host_pattern = re.compile(
        r"""(?i)(?:CURLOPT_SSL_VERIFYHOST\s*(?:=>|,)\s*(?:false|0)|['"]verify_peer_name['"]\s*=>\s*false)"""
    )
    for match in host_pattern.finditer(content):
        start_idx = match.start()
        line_num, col_num = calculate_line_col(content, start_idx)
        val = match.group(0)

        findings.append(
            MisuseFinding(
                rule_id="MISUSE-DISABLED-HOSTNAME-VERIFY",
                title="Disabled Hostname Verification in PHP cURL",
                description="CURLOPT_SSL_VERIFYHOST set to 0. Any certificate matching any host is accepted.",
                language="php",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value=val,
                role=CryptoRole.CERTIFICATE_VALIDATION.value,
                risk=RiskCategory.CLASSICAL_SECURITY.value,
                severity=FindingSeverity.HIGH.value,
                evidence_status=EvidenceStatus.OBSERVED.value,
                confidence="HIGH",
                recommendation="Set CURLOPT_SSL_VERIFYHOST => 2 for full hostname verification.",
                metadata={"matched_pattern": val},
            )
        )


def _detect_key_exchange_and_agility(
    content: str, lines: List[str], filename: str, findings: List[MisuseFinding]
) -> None:
    # Hardcoded curve in openssl_pkey_new(['curve_name' => 'secp256r1'])
    ecdh_pattern = re.compile(
        r"""(?i)['"]curve_name['"]\s*=>\s*['"](secp256r1|prime256v1)['"]"""
    )
    for match in ecdh_pattern.finditer(content):
        curve = match.group(1)
        start_idx = match.start()
        line_num, col_num = calculate_line_col(content, start_idx)

        findings.append(
            MisuseFinding(
                rule_id="MISUSE-HARDCODED-ECDH-KEX",
                title=f"Hardcoded Elliptic Curve ({curve}) in PHP",
                description="The cryptographic mechanism appears hardcoded, reducing the ability to migrate to a replacement algorithm without source changes.",
                language="php",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value=f"'curve_name' => '{curve}'",
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
    # openssl_encrypt(..., 'des-cbc', ...), mcrypt_encrypt
    pattern = re.compile(
        r"""(?i)(?:openssl_encrypt\s*\([^,]+,\s*['"](des(?:-[a-z0-9]+)?|des3|rc4)['"]|mcrypt_encrypt\s*\()"""
    )
    for match in pattern.finditer(content):
        start_idx = match.start()
        line_num, col_num = calculate_line_col(content, start_idx)
        val = match.group(0)

        findings.append(
            MisuseFinding(
                rule_id="MISUSE-INSECURE-CIPHER-CONFIG",
                title="Insecure Broken Cipher or Deprecated mcrypt Extension in PHP",
                description=f"Insecure cipher detected: '{val}'. Susceptible to cryptanalytic attacks.",
                language="php",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value=val,
                role=CryptoRole.BULK_ENCRYPTION.value,
                risk=RiskCategory.CLASSICAL_SECURITY.value,
                severity=FindingSeverity.HIGH.value,
                evidence_status=EvidenceStatus.OBSERVED.value,
                confidence="HIGH",
                recommendation="Migrate to openssl_encrypt with 'aes-256-gcm'.",
                metadata={"cipher_call": val},
            )
        )

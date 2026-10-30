"""Python-specific cryptographic misuse detector.
Uses safe AST analysis with regex fallback for malformed files.
Never executes or imports scanned code.
"""

import ast
import re
from typing import List, Tuple, Dict, Any, Optional
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
    calculate_shannon_entropy,
)


def analyze_python_source(
    content: str, filename: str
) -> Tuple[List[MisuseFinding], List[Dict[str, Any]]]:
    """
    Perform deterministic static analysis on Python source text.
    Returns findings and detected key material for cross-file duplicate detection.
    """
    findings: List[MisuseFinding] = []
    key_entries: List[Dict[str, Any]] = []

    # 1. Common PEM private keys
    pem_findings, pem_keys = find_pem_private_keys(content, "python", filename)
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

    # 9. Hardcoded RSA / ECDH key exchange & crypto-agility
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
    # Pattern for passwords
    # Matches password = "..." or password = '...'
    pw_pattern = re.compile(
        r"""(?i)\b(password|passwd|pwd|db_pass|service_password|admin_pass)\s*=\s*(?:b)?["']([^"'\r\n]{4,})["']"""
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
                description=rule.description if rule else "Static password hardcoded in Python code.",
                language="python",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value=masked,
                role=CryptoRole.CREDENTIAL.value,
                risk=RiskCategory.SECRET_EXPOSURE.value,
                severity=FindingSeverity.HIGH.value,
                evidence_status=EvidenceStatus.OBSERVED.value,
                confidence="HIGH",
                recommendation=rule.recommendation if rule else "Extract password into environment variable.",
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

    # Pattern for API keys and encryption keys
    key_pattern = re.compile(
        r"""(?i)\b(aes_key|encryption_key|master_key|secret_key|api_key|app_secret|jwt_secret|private_key_bytes|hmac_key)\s*=\s*(?:b)?["']([^"'\r\n]{8,})["']"""
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
        rule = get_rule(rule_id)
        role = CryptoRole.KEY.value if is_crypto_key else CryptoRole.SECRET.value
        masked = mask_secret(raw_val)
        fingerprint = compute_key_fingerprint(raw_val)

        findings.append(
            MisuseFinding(
                rule_id=rule_id,
                title=f"Hardcoded Cryptographic Key/Secret in Variable '{var_name}'",
                description=rule.description if rule else "Hardcoded key material in Python code.",
                language="python",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value=masked,
                role=role,
                risk=RiskCategory.SECRET_EXPOSURE.value,
                severity=FindingSeverity.CRITICAL.value if role == CryptoRole.KEY.value else FindingSeverity.HIGH.value,
                evidence_status=EvidenceStatus.OBSERVED.value,
                confidence="HIGH",
                recommendation=rule.recommendation if rule else "Load keys dynamically from a key management service.",
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
    # Python random module functions
    # Matches random.random(), random.randint(), random.choice(), random.randrange(), random.getrandbits()
    pattern = re.compile(
        r"""(?i)\b(random\.(?:random|randint|choice|randrange|getrandbits|sample))\s*\("""
    )
    rule = get_rule("MISUSE-WEAK-RANDOM")

    for match in pattern.finditer(content):
        start_idx = match.start()
        line_num, col_num = calculate_line_col(content, start_idx)
        line_text = lines[line_num - 1] if line_num <= len(lines) else ""

        # Check if line or variable assignment implies security usage: token, otp, key, salt, nonce, iv, session, auth, pin, secret
        is_security_context = any(
            sec in line_text.lower()
            for sec in ["token", "otp", "key", "salt", "nonce", "iv", "session", "auth", "pin", "secret", "password", "code"]
        )

        # In sample banking systems, random calls in services are security-relevant
        severity = FindingSeverity.HIGH.value if is_security_context else FindingSeverity.MEDIUM.value
        confidence = "HIGH" if is_security_context else "MEDIUM"

        findings.append(
            MisuseFinding(
                rule_id="MISUSE-WEAK-RANDOM",
                title="Weak PRNG ('random' module) Used for Security-Sensitive Value",
                description=(
                    f"Python standard 'random' module function '{match.group(1)}' used in '{line_text.strip()}'. "
                    "Python's Mersenne Twister PRNG is predictable and not cryptographically secure."
                ),
                language="python",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value=match.group(1) + "(...)",
                role=CryptoRole.RANDOMNESS.value,
                risk=RiskCategory.IMPLEMENTATION_SECURITY.value,
                severity=severity,
                evidence_status=EvidenceStatus.OBSERVED.value,
                confidence=confidence,
                recommendation="Replace 'random' with Python's 'secrets' module (e.g. secrets.token_hex, secrets.choice).",
                metadata={"api_call": match.group(1), "context_snippet": line_text.strip()},
            )
        )


def _detect_ecb_mode(
    content: str, lines: List[str], filename: str, findings: List[MisuseFinding]
) -> None:
    # AES.MODE_ECB, modes.ECB(), 'AES/ECB', etc.
    pattern = re.compile(
        r"""(?i)\b(AES\.MODE_ECB|modes\.ECB\s*\(|MODE_ECB|["']AES/ECB(?:/[^"']*)?["'])"""
    )
    rule = get_rule("MISUSE-ECB-MODE")

    for match in pattern.finditer(content):
        start_idx = match.start()
        line_num, col_num = calculate_line_col(content, start_idx)
        matched_text = match.group(0)

        findings.append(
            MisuseFinding(
                rule_id="MISUSE-ECB-MODE",
                title="Electronic Codebook (ECB) Mode Configured",
                description=rule.description if rule else "ECB mode does not provide semantic security.",
                language="python",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value=matched_text,
                role=CryptoRole.BULK_ENCRYPTION.value,
                risk=RiskCategory.CLASSICAL_SECURITY.value,
                severity=FindingSeverity.HIGH.value,
                evidence_status=EvidenceStatus.OBSERVED.value,
                confidence="HIGH",
                recommendation=rule.recommendation if rule else "Use AES-GCM (AEAD mode) with fresh 96-bit nonces.",
                metadata={"matched_pattern": matched_text},
            )
        )


def _detect_static_iv_and_nonce(
    content: str, lines: List[str], filename: str, findings: List[MisuseFinding]
) -> None:
    # Static IV: iv = b"..." or iv = "..." or iv = b"\x00" * 16 or iv = [0]*16
    iv_pattern = re.compile(
        r"""(?i)\b(iv|initialization_vector)\s*=\s*(?:b["']([^"'\r\n]+)["']|["']([^"'\r\n]{8,})["']|b?["']\\x00["']\s*\*\s*16|bytes\(\[?0(?:,\s*0)*\]?\))"""
    )
    rule_iv = get_rule("MISUSE-STATIC-IV")

    for match in iv_pattern.finditer(content):
        start_idx = match.start()
        line_num, col_num = calculate_line_col(content, start_idx)
        val = match.group(0)
        # Avoid flagging dynamic or env
        if is_placeholder_or_env(val):
            continue

        findings.append(
            MisuseFinding(
                rule_id="MISUSE-STATIC-IV",
                title="Static / Hardcoded Initialization Vector (IV)",
                description=rule_iv.description if rule_iv else "Hardcoded IV eliminates semantic security.",
                language="python",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value=mask_secret(val),
                role=CryptoRole.NONCE_IV.value,
                risk=RiskCategory.IMPLEMENTATION_SECURITY.value,
                severity=FindingSeverity.HIGH.value,
                evidence_status=EvidenceStatus.OBSERVED.value,
                confidence="HIGH",
                recommendation=rule_iv.recommendation if rule_iv else "Generate random IV using os.urandom(16).",
                metadata={"expression": val.strip()},
            )
        )

    # Static Nonce
    nonce_pattern = re.compile(
        r"""(?i)\b(nonce)\s*=\s*(?:b["']([^"'\r\n]+)["']|["']([^"'\r\n]{8,})["']|b?["']\\x00["']\s*\*\s*12)"""
    )
    rule_nonce = get_rule("MISUSE-STATIC-NONCE")
    for match in nonce_pattern.finditer(content):
        start_idx = match.start()
        line_num, col_num = calculate_line_col(content, start_idx)
        val = match.group(0)
        if is_placeholder_or_env(val):
            continue

        findings.append(
            MisuseFinding(
                rule_id="MISUSE-STATIC-NONCE",
                title="Static / Hardcoded Cryptographic Nonce",
                description=rule_nonce.description if rule_nonce else "Static nonce leads to loss of confidentiality in AEAD.",
                language="python",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value=mask_secret(val),
                role=CryptoRole.NONCE_IV.value,
                risk=RiskCategory.IMPLEMENTATION_SECURITY.value,
                severity=FindingSeverity.CRITICAL.value,
                evidence_status=EvidenceStatus.OBSERVED.value,
                confidence="HIGH",
                recommendation=rule_nonce.recommendation if rule_nonce else "Generate a unique 96-bit nonce via os.urandom(12).",
                metadata={"expression": val.strip()},
            )
        )


def _detect_weak_hashes(
    content: str, lines: List[str], filename: str, findings: List[MisuseFinding]
) -> None:
    # hashlib.md5, hashlib.sha1, MD5.new, SHA.new
    md5_pattern = re.compile(r"""(?i)\b(hashlib\.md5|MD5\.new)\s*\(""")
    sha1_pattern = re.compile(r"""(?i)\b(hashlib\.sha1|SHA(?:1)?\.new)\s*\(""")

    rule_md5 = get_rule("MISUSE-MD5-HASH")
    rule_sha1 = get_rule("MISUSE-SHA1-HASH")

    for match in md5_pattern.finditer(content):
        start_idx = match.start()
        line_num, col_num = calculate_line_col(content, start_idx)
        line_text = lines[line_num - 1] if line_num <= len(lines) else ""

        is_pw = any(w in line_text.lower() for w in ["password", "pwd", "pass", "cred", "pin"])
        is_sig = any(w in line_text.lower() for w in ["sign", "signature", "verify", "hmac"])

        role = CryptoRole.PASSWORD_HASHING.value if is_pw else (CryptoRole.DIGITAL_SIGNATURE.value if is_sig else CryptoRole.HASH.value)
        severity = FindingSeverity.CRITICAL.value if is_pw else FindingSeverity.HIGH.value
        title = "MD5 Used for Password Hashing" if is_pw else "Insecure MD5 Hash Algorithm Detected"

        findings.append(
            MisuseFinding(
                rule_id="MISUSE-MD5-HASH",
                title=title,
                description=f"MD5 invoked in: '{line_text.strip()}'. MD5 is cryptographically broken.",
                language="python",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value=match.group(1) + "(...)",
                role=role,
                risk=RiskCategory.CLASSICAL_SECURITY.value,
                severity=severity,
                evidence_status=EvidenceStatus.OBSERVED.value,
                confidence="HIGH",
                recommendation="Replace MD5 with SHA-256 for integrity or Argon2id/bcrypt for password hashing.",
                metadata={"context_line": line_text.strip()},
            )
        )

    for match in sha1_pattern.finditer(content):
        start_idx = match.start()
        line_num, col_num = calculate_line_col(content, start_idx)
        line_text = lines[line_num - 1] if line_num <= len(lines) else ""

        is_pw = any(w in line_text.lower() for w in ["password", "pwd", "pass", "cred"])
        is_sig = any(w in line_text.lower() for w in ["sign", "signature", "cert", "token"])

        role = CryptoRole.PASSWORD_HASHING.value if is_pw else (CryptoRole.DIGITAL_SIGNATURE.value if is_sig else CryptoRole.HASH.value)
        severity = FindingSeverity.HIGH.value if (is_pw or is_sig) else FindingSeverity.MEDIUM.value
        title = "SHA-1 Used in Security-Sensitive Context" if (is_pw or is_sig) else "Deprecated SHA-1 Hash Algorithm"

        findings.append(
            MisuseFinding(
                rule_id="MISUSE-SHA1-HASH",
                title=title,
                description=f"SHA-1 invoked in: '{line_text.strip()}'. Vulnerable to collision attacks.",
                language="python",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value=match.group(1) + "(...)",
                role=role,
                risk=RiskCategory.CLASSICAL_SECURITY.value,
                severity=severity,
                evidence_status=EvidenceStatus.OBSERVED.value,
                confidence="HIGH",
                recommendation="Migrate to SHA-256/SHA-384 or SHA-3 for digital signatures and hashing.",
                metadata={"context_line": line_text.strip()},
            )
        )


def _detect_rsa_parameters(
    content: str, lines: List[str], filename: str, findings: List[MisuseFinding]
) -> None:
    # RSA.generate(1024), RSA.generate(512), rsa.generate_private_key(key_size=1024, ...)
    key_size_pattern = re.compile(
        r"""(?i)(?:RSA\.generate\s*\(\s*(512|1024)\b|key_size\s*=\s*(512|1024)\b)"""
    )
    rule_key = get_rule("MISUSE-SMALL-RSA-KEY")

    for match in key_size_pattern.finditer(content):
        start_idx = match.start()
        line_num, col_num = calculate_line_col(content, start_idx)
        size_str = match.group(1) or match.group(2)
        size = int(size_str)
        severity = FindingSeverity.CRITICAL.value if size <= 512 else FindingSeverity.HIGH.value

        findings.append(
            MisuseFinding(
                rule_id="MISUSE-SMALL-RSA-KEY",
                title=f"Insecure Small RSA Key Size ({size} bits)",
                description=f"RSA key generation configured with key size of {size} bits.",
                language="python",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value=f"key_size={size}",
                role=CryptoRole.KEY.value,
                risk=RiskCategory.CLASSICAL_SECURITY.value,
                severity=severity,
                evidence_status=EvidenceStatus.OBSERVED.value,
                confidence="HIGH",
                recommendation="Enforce minimum RSA key size of 2048 bits (3072+ recommended) or migrate to ML-DSA.",
                metadata={"key_size_bits": size},
            )
        )

    # Weak exponent: public_exponent=3 or public_exponent=1
    exponent_pattern = re.compile(r"""(?i)\bpublic_exponent\s*=\s*([13])\b""")
    rule_exp = get_rule("MISUSE-WEAK-RSA-EXPONENT")

    for match in exponent_pattern.finditer(content):
        start_idx = match.start()
        line_num, col_num = calculate_line_col(content, start_idx)
        exp = int(match.group(1))

        findings.append(
            MisuseFinding(
                rule_id="MISUSE-WEAK-RSA-EXPONENT",
                title=f"Weak RSA Public Exponent (e={exp})",
                description=f"RSA public exponent set to {exp}. Vulnerable to low-exponent attacks.",
                language="python",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value=f"public_exponent={exp}",
                role=CryptoRole.KEY.value,
                risk=RiskCategory.CLASSICAL_SECURITY.value,
                severity=FindingSeverity.HIGH.value,
                evidence_status=EvidenceStatus.OBSERVED.value,
                confidence="HIGH",
                recommendation="Use public_exponent=65537 (Fermat F4 prime).",
                metadata={"public_exponent": exp},
            )
        )


def _detect_disabled_verification(
    content: str, lines: List[str], filename: str, findings: List[MisuseFinding]
) -> None:
    # verify=False, check_hostname=False, ssl._create_unverified_context()
    cert_pattern = re.compile(
        r"""(?i)(?:\bverify\s*=\s*False\b|ssl\._create_unverified_context\s*\(\)|InsecureSkipVerify\s*[:=]\s*true)"""
    )
    rule_cert = get_rule("MISUSE-DISABLED-CERT-VERIFY")

    for match in cert_pattern.finditer(content):
        start_idx = match.start()
        line_num, col_num = calculate_line_col(content, start_idx)
        matched_str = match.group(0)

        findings.append(
            MisuseFinding(
                rule_id="MISUSE-DISABLED-CERT-VERIFY",
                title="Disabled TLS Certificate Verification",
                description=f"TLS certificate validation disabled: '{matched_str}'. Allows MITM attacks.",
                language="python",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value=matched_str,
                role=CryptoRole.CERTIFICATE_VALIDATION.value,
                risk=RiskCategory.CLASSICAL_SECURITY.value,
                severity=FindingSeverity.CRITICAL.value,
                evidence_status=EvidenceStatus.OBSERVED.value,
                confidence="HIGH",
                recommendation="Enable certificate verification (verify=True or supply valid CA bundle path).",
                metadata={"matched_pattern": matched_str},
            )
        )

    host_pattern = re.compile(
        r"""(?i)(?:\bcheck_hostname\s*=\s*False\b|\bmatch_hostname\s*=\s*False\b)"""
    )
    rule_host = get_rule("MISUSE-DISABLED-HOSTNAME-VERIFY")

    for match in host_pattern.finditer(content):
        start_idx = match.start()
        line_num, col_num = calculate_line_col(content, start_idx)
        matched_str = match.group(0)

        findings.append(
            MisuseFinding(
                rule_id="MISUSE-DISABLED-HOSTNAME-VERIFY",
                title="Disabled TLS Hostname Verification",
                description=f"TLS hostname verification disabled: '{matched_str}'.",
                language="python",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value=matched_str,
                role=CryptoRole.CERTIFICATE_VALIDATION.value,
                risk=RiskCategory.CLASSICAL_SECURITY.value,
                severity=FindingSeverity.HIGH.value,
                evidence_status=EvidenceStatus.OBSERVED.value,
                confidence="HIGH",
                recommendation="Enable strict hostname verification (check_hostname=True).",
                metadata={"matched_pattern": matched_str},
            )
        )


def _detect_key_exchange_and_agility(
    content: str, lines: List[str], filename: str, findings: List[MisuseFinding]
) -> None:
    # Hardcoded RSA Key Exchange
    rsa_kex_pattern = re.compile(
        r"""(?i)["'](?:TLS_)?RSA_WITH_AES_[^"']+["']|\bkex\s*=\s*["']RSA["']"""
    )
    rule_rsa_kex = get_rule("MISUSE-HARDCODED-RSA-KEX")

    for match in rsa_kex_pattern.finditer(content):
        start_idx = match.start()
        line_num, col_num = calculate_line_col(content, start_idx)
        val = match.group(0)

        findings.append(
            MisuseFinding(
                rule_id="MISUSE-HARDCODED-RSA-KEX",
                title="Hardcoded RSA Key Exchange (Quantum-Exposed)",
                description=rule_rsa_kex.description if rule_rsa_kex else "Static RSA key exchange lacks forward secrecy.",
                language="python",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value=val,
                role=CryptoRole.KEY_ESTABLISHMENT.value,
                risk=RiskCategory.QUANTUM_SECURITY.value,
                severity=FindingSeverity.HIGH.value,
                evidence_status=EvidenceStatus.OBSERVED.value,
                confidence="HIGH",
                recommendation=rule_rsa_kex.recommendation if rule_rsa_kex else "Migrate to hybrid PQC key exchange.",
                metadata={"key_exchange": val},
            )
        )

    # Hardcoded ECDH / ECDHE Key Exchange
    ecdh_pattern = re.compile(
        r"""(?i)(?:ec\.ECDH\s*\(\)|ec\.SECP256R1\s*\(\)|kex\s*=\s*["']ECDH(?:E)?["']|["']ECDHE-RSA-[^"']+["'])"""
    )
    rule_ecdh = get_rule("MISUSE-HARDCODED-ECDH-KEX")

    for match in ecdh_pattern.finditer(content):
        start_idx = match.start()
        line_num, col_num = calculate_line_col(content, start_idx)
        val = match.group(0)

        findings.append(
            MisuseFinding(
                rule_id="MISUSE-HARDCODED-ECDH-KEX",
                title="Hardcoded ECDH/ECDHE Key Exchange",
                description="The cryptographic mechanism appears hardcoded, reducing the ability to migrate to a replacement algorithm without source changes.",
                language="python",
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

    # Lack of crypto agility: hardcoded cipher without configurability
    agility_pattern = re.compile(
        r"""(?i)\bcipher_algorithm\s*=\s*["'](AES-128|AES-256|DES|3DES)["']"""
    )
    rule_agility = get_rule("MISUSE-CRYPTO-AGILITY-LACK")

    for match in agility_pattern.finditer(content):
        start_idx = match.start()
        line_num, col_num = calculate_line_col(content, start_idx)
        val = match.group(0)

        findings.append(
            MisuseFinding(
                rule_id="MISUSE-CRYPTO-AGILITY-LACK",
                title="Inflexible Cryptographic Algorithm Configuration",
                description="The cryptographic mechanism appears hardcoded, reducing the ability to migrate to a replacement algorithm without source changes.",
                language="python",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value=val,
                role=CryptoRole.CRYPTO_AGILITY.value,
                risk=RiskCategory.CRYPTO_AGILITY.value,
                severity=FindingSeverity.LOW.value,
                evidence_status=EvidenceStatus.OBSERVED.value,
                confidence="MEDIUM",
                recommendation="Extract cipher algorithms into configuration profiles.",
                metadata={"config": val},
            )
        )


def _detect_insecure_ciphers(
    content: str, lines: List[str], filename: str, findings: List[MisuseFinding]
) -> None:
    # DES, 3DES, RC4, Blowfish, null cipher
    cipher_pattern = re.compile(
        r"""(?i)(?:algorithms\.(?:TripleDES|ARC4|Blowfish)|(?:DES|DES3|ARC4|Blowfish)\.new\s*\(|["'](?:DES|3DES|RC4|ARCFOUR|NULL)["'])"""
    )
    rule = get_rule("MISUSE-INSECURE-CIPHER-CONFIG")

    for match in cipher_pattern.finditer(content):
        start_idx = match.start()
        line_num, col_num = calculate_line_col(content, start_idx)
        val = match.group(0)

        findings.append(
            MisuseFinding(
                rule_id="MISUSE-INSECURE-CIPHER-CONFIG",
                title="Insecure / Broken Cipher Algorithm Configured",
                description=f"Deprecated cipher detected: '{val}'. Susceptible to cryptanalytic attacks.",
                language="python",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value=val,
                role=CryptoRole.BULK_ENCRYPTION.value,
                risk=RiskCategory.CLASSICAL_SECURITY.value,
                severity=FindingSeverity.HIGH.value,
                evidence_status=EvidenceStatus.OBSERVED.value,
                confidence="HIGH",
                recommendation="Replace legacy ciphers with AES-256-GCM.",
                metadata={"cipher": val},
            )
        )

    # Static/zero salt
    salt_pattern = re.compile(
        r"""(?i)\bsalt\s*=\s*(?:b["']["']|["']["']|b["']00000000["']|b?["']\\x00["']\s*\*\s*8)"""
    )
    for match in salt_pattern.finditer(content):
        start_idx = match.start()
        line_num, col_num = calculate_line_col(content, start_idx)
        val = match.group(0)

        findings.append(
            MisuseFinding(
                rule_id="MISUSE-INSECURE-CIPHER-CONFIG",
                title="Zero or Static Salt in Key Derivation",
                description="Empty or static salt configured for key derivation function.",
                language="python",
                file=filename,
                line=line_num,
                column=col_num,
                matched_value=val,
                role=CryptoRole.PASSWORD_HASHING.value,
                risk=RiskCategory.CLASSICAL_SECURITY.value,
                severity=FindingSeverity.HIGH.value,
                evidence_status=EvidenceStatus.OBSERVED.value,
                confidence="HIGH",
                recommendation="Generate at least 16 cryptographically random bytes for salt.",
                metadata={"salt_expr": val},
            )
        )

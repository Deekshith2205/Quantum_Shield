"""Cryptographic detection rules for banking configurations.
Applies regex and pattern extractors to find explicit cryptographic facts
and evaluate crypto-agility, evidence provenance, and secret redaction.

HARD INVARIANTS:
1. Do NOT infer TLS 1.3 key exchange merely from TLS 1.3 version.
2. Only report algorithms and parameters explicitly present in configuration.
3. Missing evidence is NOT_OBSERVABLE, never a vulnerability.
4. Secrets (passwords, private key blocks, tokens) are NEVER emitted in plaintext.
"""

import re
from typing import Any, Dict, List, Optional, Tuple, Set

from app.scanners.config_scanner.models import (
    ConfigObservation,
    CryptoAgility,
    CryptoRole,
    EvidenceStatus,
)
from app.scanners.config_scanner.parsers import ParsedEntry


# Secret key terms to detect and redact with boundary protection
SECRET_KEY_EXCLUDE_TERMS = {
    "algorithm", "format", "cipher", "mode", "padding", "path", "file",
    "type", "model", "group", "curve", "version", "provider", "interval",
    "rotation", "wrapping", "block", "length", "size"
}

# Raw PEM private key pattern
PEM_PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|ENCRYPTED)?\s*PRIVATE\s+KEY-----",
    re.IGNORECASE
)

# Explicit TLS versions
TLS_VERSION_PATTERN = re.compile(
    r"\b(?:TLSv?|TLS\s*)(1\.[0-3])\b",
    re.IGNORECASE
)

# Key exchange mechanisms (EXPLICIT ONLY)
KEY_EXCHANGE_PATTERN = re.compile(
    r"\b(X25519MLKEM768|X448MLKEM1024|ML-KEM-1024|ML-KEM-768|ML-KEM-512|ML-KEM|ECDHE|ECDH|X25519|X448|DHE|RSA)\b",
    re.IGNORECASE
)

# PQC algorithms
PQC_ALGORITHM_PATTERN = re.compile(
    r"\b(X25519MLKEM768|X448MLKEM1024|ML-KEM-1024|ML-KEM-768|ML-KEM-512|ML-KEM|ML-DSA-87|ML-DSA-65|ML-DSA-44|ML-DSA|SLH-DSA-[A-Za-z0-9\-]+|SLH-DSA)\b",
    re.IGNORECASE
)

# Symmetric encryption algorithms
SYMMETRIC_ALGORITHM_PATTERN = re.compile(
    r"\b(AES-256-GCM|AES-128-GCM|AES-256-CBC|AES-128-CBC|AES-256-XTS|AES-128-XTS|AES-256-CTR|AES-128-CTR|AES-256|AES-128|3DES|DES-EDE3|DES3|DES|CHACHA20-POLY1305|CHACHA20)\b",
    re.IGNORECASE
)

# Asymmetric algorithms
ASYMMETRIC_ALGORITHM_PATTERN = re.compile(
    r"\b(RSA-4096|RSA-3072|RSA-2048|RSA-1024|RSA|ECDSA|Ed25519|Ed448)\b",
    re.IGNORECASE
)

# Hash and digest algorithms
HASH_ALGORITHM_PATTERN = re.compile(
    r"\b(SHA-512|SHA-384|SHA-256|SHA-224|SHA-1|MD5|SHA1|SHA256|SHA384|SHA512)\b",
    re.IGNORECASE
)

# Elliptic curves
CURVE_PATTERN = re.compile(
    r"\b(secp256r1|secp384r1|secp521r1|prime256v1|P-256|P-384|P-521|X25519|X448|ed25519|curve25519)\b",
    re.IGNORECASE
)

# RSA Key sizes
RSA_KEY_SIZE_PATTERN = re.compile(
    r"\b(1024|2048|3072|4096)\b"
)

# Insecure verification triggers
INSECURE_VERIFICATION_KEYS = re.compile(
    r"(verify_peer|verify_hostname|insecure_skip_verify|trust_all|verify_certificate|ssl_verify|check_hostname|certificate_validation)",
    re.IGNORECASE
)


class ConfigRuleEngine:
    """
    Evaluates parsed configuration entries against cryptographic audit rules.
    Outputs normalized ConfigObservation items.
    """

    def __init__(self, source_file: str):
        self.source_file = source_file

    def evaluate_entry(self, entry: ParsedEntry) -> List[ConfigObservation]:
        """Evaluate a single parsed configuration entry."""
        observations: List[ConfigObservation] = []

        # 1. Check for secret redaction first
        is_secret, sanitized_val = self._check_and_redact_secret(entry.path, entry.value)
        if is_secret:
            observations.append(
                ConfigObservation(
                    file=self.source_file,
                    line=entry.line,
                    path=entry.path,
                    value=sanitized_val,
                    role=CryptoRole.KEY_STORAGE,
                    algorithm=None,
                    evidence_status=EvidenceStatus.OBSERVED,
                    confidence="HIGH",
                    description=f"Secret material identified and redacted at {entry.path}",
                    crypto_agility=CryptoAgility.NOT_OBSERVABLE,
                    secret_redacted=True,
                    metadata={"redacted": True, "field": entry.raw_key}
                )
            )
            return observations

        # 2. System metadata evaluation
        meta_obs = self._evaluate_system_metadata(entry)
        if meta_obs:
            observations.append(meta_obs)

        # 3. TLS Protocol Versions
        tls_obs = self._evaluate_tls_version(entry)
        observations.extend(tls_obs)

        # 4. Cipher Suites
        cipher_obs = self._evaluate_cipher_suites(entry)
        observations.extend(cipher_obs)

        # 5. Key Exchange (Explicit ONLY - never infer from TLS version)
        kex_obs = self._evaluate_key_exchange(entry)
        observations.extend(kex_obs)

        # 6. Certificates & Asymmetric Keys
        cert_obs = self._evaluate_certificates(entry)
        observations.extend(cert_obs)

        # 7. Certificate Validation / Insecure modes
        val_obs = self._evaluate_certificate_validation(entry)
        observations.extend(val_obs)

        # 8. Symmetric bulk encryption
        sym_obs = self._evaluate_symmetric_encryption(entry)
        observations.extend(sym_obs)

        # 9. Key Wrapping & HSM / KMS Storage
        kms_obs = self._evaluate_key_management(entry)
        observations.extend(kms_obs)

        # 10. Hash and Digest algorithms
        hash_obs = self._evaluate_hash_algorithms(entry)
        observations.extend(hash_obs)

        # 11. Post-Quantum Algorithms (ML-KEM, ML-DSA, SLH-DSA)
        pqc_obs = self._evaluate_pqc_algorithms(entry)
        observations.extend(pqc_obs)

        return observations

    # ------------------ DETECTORS ------------------

    def _check_and_redact_secret(self, path: str, val: Any) -> Tuple[bool, Any]:
        """Detect and redact secrets, passwords, or raw private keys."""
        val_str = str(val)
        if PEM_PRIVATE_KEY_PATTERN.search(val_str):
            return True, "[REDACTED_PRIVATE_KEY]"

        parts = [p.lower() for p in re.split(r"[._\-]", path)]
        # If path explicitly names an algorithm, format, or cipher, it is not a secret
        if any(term in parts for term in SECRET_KEY_EXCLUDE_TERMS):
            return False, val

        # Exact or compound secret matches
        if any(term in parts for term in ("password", "passwd", "secret", "api_key", "api_secret", "slot_pin", "auth_secret", "seed")):
            return True, "[REDACTED_SECRET]"
        if "pin" in parts and not any(p in parts for p in ("format", "encryption", "cipher")):
            return True, "[REDACTED_SECRET]"
        if "token" in parts and not any(p in parts for p in ("signing", "tokenization", "service")):
            return True, "[REDACTED_SECRET]"
        if "private" in parts and "key" in parts and not any(p in parts for p in ("path", "file", "cert")):
            return True, "[REDACTED_SECRET]"
        return False, val

    def _evaluate_system_metadata(self, entry: ParsedEntry) -> Optional[ConfigObservation]:
        """Detect explicit banking system metadata."""
        path_lower = entry.path.lower()
        key_lower = entry.raw_key.lower()

        role = CryptoRole.SYSTEM_METADATA
        val = str(entry.value).strip()

        if key_lower in ("system_id", "fleet_id"):
            return ConfigObservation(
                file=self.source_file,
                line=entry.line,
                path=entry.path,
                value=val,
                role=role,
                evidence_status=EvidenceStatus.OBSERVED,
                confidence="HIGH",
                description=f"Declared system ID: {val}",
                metadata={"meta_type": "system_id"}
            )
        elif key_lower in ("criticality", "system_criticality"):
            return ConfigObservation(
                file=self.source_file,
                line=entry.line,
                path=entry.path,
                value=val.upper(),
                role=role,
                evidence_status=EvidenceStatus.OBSERVED,
                confidence="HIGH",
                description=f"Declared criticality: {val}",
                metadata={"meta_type": "criticality"}
            )
        elif key_lower in ("trust_zone", "zone"):
            return ConfigObservation(
                file=self.source_file,
                line=entry.line,
                path=entry.path,
                value=val.upper(),
                role=role,
                evidence_status=EvidenceStatus.OBSERVED,
                confidence="HIGH",
                description=f"Declared trust zone: {val}",
                metadata={"meta_type": "trust_zone"}
            )
        elif key_lower in ("exposure", "asset_exposure"):
            return ConfigObservation(
                file=self.source_file,
                line=entry.line,
                path=entry.path,
                value=val.upper(),
                role=role,
                evidence_status=EvidenceStatus.OBSERVED,
                confidence="HIGH",
                description=f"Declared network exposure: {val}",
                metadata={"meta_type": "exposure"}
            )
        elif key_lower in ("data_sensitivity", "sensitivity"):
            return ConfigObservation(
                file=self.source_file,
                line=entry.line,
                path=entry.path,
                value=val.upper(),
                role=role,
                evidence_status=EvidenceStatus.OBSERVED,
                confidence="HIGH",
                description=f"Declared data sensitivity: {val}",
                metadata={"meta_type": "data_sensitivity"}
            )
        elif key_lower in ("data_lifetime", "retention"):
            return ConfigObservation(
                file=self.source_file,
                line=entry.line,
                path=entry.path,
                value=val.upper(),
                role=role,
                evidence_status=EvidenceStatus.OBSERVED,
                confidence="HIGH",
                description=f"Declared data lifetime: {val}",
                metadata={"meta_type": "data_lifetime"}
            )
        elif key_lower in ("system_type", "asset_type"):
            return ConfigObservation(
                file=self.source_file,
                line=entry.line,
                path=entry.path,
                value=val.upper(),
                role=role,
                evidence_status=EvidenceStatus.OBSERVED,
                confidence="HIGH",
                description=f"Declared banking system type: {val}",
                metadata={"meta_type": "system_type"}
            )
        return None

    def _evaluate_tls_version(self, entry: ParsedEntry) -> List[ConfigObservation]:
        """Detect explicit TLS protocol versions."""
        obs_list: List[ConfigObservation] = []
        path_lower = entry.path.lower()

        # Check if key is related to TLS / SSL version or protocol
        is_tls_key = any(k in path_lower for k in ("tls", "ssl", "protocol", "transport"))
        if not is_tls_key:
            return obs_list

        values_to_check = self._normalize_values(entry.value)
        agility = self._assess_agility(entry, values_to_check)

        for val_str in values_to_check:
            for match in TLS_VERSION_PATTERN.finditer(str(val_str)):
                ver_num = match.group(1)
                full_ver = f"TLS {ver_num}"
                obs_list.append(
                    ConfigObservation(
                        file=self.source_file,
                        line=entry.line,
                        path=entry.path,
                        value=full_ver,
                        role=CryptoRole.TRANSPORT_SECURITY,
                        algorithm=full_ver,
                        evidence_status=EvidenceStatus.OBSERVED,
                        confidence="HIGH",
                        description=f"Explicitly configured TLS version {full_ver}",
                        crypto_agility=agility,
                        metadata={"protocol": "TLS", "version": ver_num}
                    )
                )

        return obs_list

    def _evaluate_cipher_suites(self, entry: ParsedEntry) -> List[ConfigObservation]:
        """Detect explicit cipher configuration suites."""
        obs_list: List[ConfigObservation] = []
        path_lower = entry.path.lower()

        is_cipher_key = any(k in path_lower for k in ("cipher", "ssl_ciphers", "cipher_suites", "ciphers"))
        if not is_cipher_key:
            return obs_list

        values = self._normalize_values(entry.value)
        agility = self._assess_agility(entry, values)

        for val in values:
            val_str = str(val).strip()
            # Split space, colon, or comma separated cipher strings (e.g. nginx format)
            tokens = re.split(r"[:,\s]+", val_str)
            for token in tokens:
                token = token.strip()
                if not token:
                    continue
                # Match common standard cipher suite patterns
                if any(x in token.upper() for x in ("AES", "CHACHA", "3DES", "DES", "GCM", "CBC", "POLY1305", "SHA")):
                    obs_list.append(
                        ConfigObservation(
                            file=self.source_file,
                            line=entry.line,
                            path=entry.path,
                            value=token,
                            role=CryptoRole.TRANSPORT_SECURITY,
                            algorithm=token,
                            evidence_status=EvidenceStatus.OBSERVED,
                            confidence="HIGH",
                            description=f"Configured cipher suite: {token}",
                            crypto_agility=agility,
                            metadata={"cipher_suite": token}
                        )
                    )

        return obs_list

    def _evaluate_key_exchange(self, entry: ParsedEntry) -> List[ConfigObservation]:
        """
        Detect explicit key exchange mechanisms.
        HARD INVARIANT: Do NOT infer TLS 1.3 key exchange merely from TLS 1.3 version.
        """
        obs_list: List[ConfigObservation] = []
        path_lower = entry.path.lower()

        is_kex_key = any(k in path_lower for k in (
            "kex", "key_exchange", "ecdh", "groups", "supported_groups",
            "curves", "elliptic_curve", "ec_curves", "curve"
        ))

        values = self._normalize_values(entry.value)
        agility = self._assess_agility(entry, values)

        for val in values:
            val_str = str(val).strip()
            # Look for explicit key exchange names
            if is_kex_key or "kex" in entry.raw_key.lower():
                matches = KEY_EXCHANGE_PATTERN.finditer(val_str)
                for m in matches:
                    algo = m.group(1).upper()
                    obs_list.append(
                        ConfigObservation(
                            file=self.source_file,
                            line=entry.line,
                            path=entry.path,
                            value=algo,
                            role=CryptoRole.KEY_EXCHANGE,
                            algorithm=algo,
                            evidence_status=EvidenceStatus.OBSERVED,
                            confidence="HIGH",
                            description=f"Explicitly configured key exchange mechanism: {algo}",
                            crypto_agility=agility,
                            metadata={"key_exchange": algo}
                        )
                    )

            # Check explicit curves
            curve_matches = CURVE_PATTERN.finditer(val_str)
            for cm in curve_matches:
                curve_name = cm.group(1)
                # Avoid matching if already captured as algorithm
                obs_list.append(
                    ConfigObservation(
                        file=self.source_file,
                        line=entry.line,
                        path=entry.path,
                        value=curve_name,
                        role=CryptoRole.KEY_EXCHANGE,
                        algorithm=curve_name,
                        evidence_status=EvidenceStatus.OBSERVED,
                        confidence="HIGH",
                        description=f"Configured elliptic curve / group: {curve_name}",
                        crypto_agility=agility,
                        metadata={"curve": curve_name}
                    )
                )

        return obs_list

    def _evaluate_certificates(self, entry: ParsedEntry) -> List[ConfigObservation]:
        """Detect certificate paths, key sizes, and certificate algorithms."""
        obs_list: List[ConfigObservation] = []
        path_lower = entry.path.lower()
        key_lower = (entry.raw_key or entry.path.split(".")[-1]).lower()

        val_str = str(entry.value).strip()

        # Certificate paths
        parts = set(re.split(r"[._\-]", key_lower))
        if any(k in key_lower for k in ("cert", "certificate", "crt", "pem", "ssl_certificate")) and not ("key" in parts or "private" in parts):
            if "/" in val_str or "\\" in val_str or val_str.endswith((".crt", ".pem", ".cer")):
                obs_list.append(
                    ConfigObservation(
                        file=self.source_file,
                        line=entry.line,
                        path=entry.path,
                        value=val_str,
                        role=CryptoRole.CERTIFICATE_AUTHENTICATION,
                        algorithm=None,
                        evidence_status=EvidenceStatus.OBSERVED,
                        confidence="HIGH",
                        description=f"Configured certificate path: {val_str}",
                        crypto_agility=CryptoAgility.NOT_OBSERVABLE,
                        metadata={"certificate_path": val_str}
                    )
                )

        # Private key paths
        if any(k in key_lower for k in ("key_file", "private_key", "ssl_certificate_key", "key_path")):
            if "/" in val_str or "\\" in val_str or val_str.endswith((".key", ".pem")):
                obs_list.append(
                    ConfigObservation(
                        file=self.source_file,
                        line=entry.line,
                        path=entry.path,
                        value=val_str,
                        role=CryptoRole.KEY_STORAGE,
                        algorithm=None,
                        evidence_status=EvidenceStatus.OBSERVED,
                        confidence="HIGH",
                        description=f"Configured private key path: {val_str}",
                        crypto_agility=CryptoAgility.NOT_OBSERVABLE,
                        metadata={"private_key_path": val_str}
                    )
                )

        # Explicit certificate algorithms & RSA key size
        if any(k in path_lower for k in ("cert", "key", "signature")) and "size" in key_lower:
            size_match = RSA_KEY_SIZE_PATTERN.search(val_str)
            if size_match:
                key_size = int(size_match.group(1))
                obs_list.append(
                    ConfigObservation(
                        file=self.source_file,
                        line=entry.line,
                        path=entry.path,
                        value=key_size,
                        role=CryptoRole.CERTIFICATE_AUTHENTICATION,
                        algorithm=f"RSA-{key_size}",
                        evidence_status=EvidenceStatus.OBSERVED,
                        confidence="HIGH",
                        description=f"Configured key size: {key_size} bits",
                        crypto_agility=self._assess_agility(entry, [val_str]),
                        metadata={"key_size": key_size}
                    )
                )

        # Digital signature algorithms (e.g. SHA256withRSA, ECDSA-SHA256, ML-DSA)
        if "signature" in path_lower or "sig" in key_lower:
            obs_list.append(
                ConfigObservation(
                    file=self.source_file,
                    line=entry.line,
                    path=entry.path,
                    value=val_str,
                    role=CryptoRole.DIGITAL_SIGNATURE,
                    algorithm=val_str,
                    evidence_status=EvidenceStatus.OBSERVED,
                    confidence="HIGH",
                    description=f"Configured signature algorithm: {val_str}",
                    crypto_agility=self._assess_agility(entry, [val_str]),
                    metadata={"signature_algorithm": val_str}
                )
            )

        return obs_list

    def _evaluate_certificate_validation(self, entry: ParsedEntry) -> List[ConfigObservation]:
        """
        Detect explicit certificate validation settings:
        verification disabled, hostname verification disabled, trust-all configuration.
        """
        obs_list: List[ConfigObservation] = []
        path_lower = entry.path.lower()
        key_lower = (entry.raw_key or entry.path.split(".")[-1]).lower()

        if INSECURE_VERIFICATION_KEYS.search(key_lower) or INSECURE_VERIFICATION_KEYS.search(path_lower):
            val_str = str(entry.value).strip().lower()
            val_bool = None
            if val_str in ("false", "0", "off", "no", "disabled", "none"):
                val_bool = False
            elif val_str in ("true", "1", "on", "yes", "enabled"):
                val_bool = True

            # Detect insecure validation disabled
            is_insecure = False
            if key_lower in ("verify_peer", "verify_hostname", "verify_certificate", "check_hostname"):
                if val_bool is False:
                    is_insecure = True
            elif key_lower in ("insecure_skip_verify", "trust_all", "trust_all_certs", "insecure_ssl"):
                if val_bool is True:
                    is_insecure = True
            elif "validation" in key_lower and val_str in ("disabled", "none", "off"):
                is_insecure = True

            desc = "Insecure certificate validation disabled" if is_insecure else "Certificate validation policy enabled"
            obs_list.append(
                ConfigObservation(
                    file=self.source_file,
                    line=entry.line,
                    path=entry.path,
                    value=entry.value,
                    role=CryptoRole.CERTIFICATE_VALIDATION,
                    algorithm=None,
                    evidence_status=EvidenceStatus.OBSERVED,
                    confidence="HIGH",
                    description=desc,
                    crypto_agility=CryptoAgility.NOT_OBSERVABLE,
                    metadata={"insecure_validation": is_insecure, "raw_policy": val_str}
                )
            )

        return obs_list

    def _evaluate_symmetric_encryption(self, entry: ParsedEntry) -> List[ConfigObservation]:
        """Detect bulk symmetric encryption algorithms (AES, 3DES, DES, ChaCha20)."""
        obs_list: List[ConfigObservation] = []
        path_lower = entry.path.lower()

        # If it's a transport cipher suite key, handled in cipher suites evaluator
        if any(k in path_lower for k in ("ssl_ciphers", "cipher_suites", "tls")):
            return obs_list

        values = self._normalize_values(entry.value)
        agility = self._assess_agility(entry, values)

        for val in values:
            val_str = str(val).strip()
            matches = SYMMETRIC_ALGORITHM_PATTERN.finditer(val_str)
            for m in matches:
                algo = m.group(1).upper()
                obs_list.append(
                    ConfigObservation(
                        file=self.source_file,
                        line=entry.line,
                        path=entry.path,
                        value=algo,
                        role=CryptoRole.BULK_ENCRYPTION,
                        algorithm=algo,
                        evidence_status=EvidenceStatus.OBSERVED,
                        confidence="HIGH",
                        description=f"Configured bulk encryption algorithm: {algo}",
                        crypto_agility=agility,
                        metadata={"symmetric_algorithm": algo}
                    )
                )

        return obs_list

    def _evaluate_key_management(self, entry: ParsedEntry) -> List[ConfigObservation]:
        """Detect key wrapping, HSM, KMS, and key rotation."""
        obs_list: List[ConfigObservation] = []
        path_lower = entry.path.lower()
        key_lower = (entry.raw_key or entry.path.split(".")[-1]).lower()

        val_str = str(entry.value).strip()

        # Key wrapping
        if "wrap" in path_lower or "kek" in path_lower:
            algo_match = (
                ASYMMETRIC_ALGORITHM_PATTERN.search(val_str) or
                PQC_ALGORITHM_PATTERN.search(val_str) or
                SYMMETRIC_ALGORITHM_PATTERN.search(val_str)
            )
            algo_name = algo_match.group(1).upper() if algo_match else val_str
            obs_list.append(
                ConfigObservation(
                    file=self.source_file,
                    line=entry.line,
                    path=entry.path,
                    value=val_str,
                    role=CryptoRole.KEY_WRAPPING,
                    algorithm=algo_name,
                    evidence_status=EvidenceStatus.OBSERVED,
                    confidence="HIGH",
                    description=f"Configured key wrapping mechanism: {val_str}",
                    crypto_agility=self._assess_agility(entry, [val_str]),
                    metadata={"key_wrapping": val_str}
                )
            )

        # HSM or KMS usage
        if any(k in path_lower for k in ("hsm", "kms", "pkcs11", "key_storage", "vault")):
            role = CryptoRole.KEY_STORAGE
            obs_list.append(
                ConfigObservation(
                    file=self.source_file,
                    line=entry.line,
                    path=entry.path,
                    value=val_str,
                    role=role,
                    algorithm=None,
                    evidence_status=EvidenceStatus.OBSERVED,
                    confidence="HIGH",
                    description=f"Configured key storage/protection facility: {val_str}",
                    crypto_agility=CryptoAgility.NOT_OBSERVABLE,
                    metadata={"key_storage_facility": val_str}
                )
            )

        # Key rotation
        if "rotation" in path_lower or "rotate" in path_lower:
            obs_list.append(
                ConfigObservation(
                    file=self.source_file,
                    line=entry.line,
                    path=entry.path,
                    value=val_str,
                    role=CryptoRole.KEY_ROTATION,
                    algorithm=None,
                    evidence_status=EvidenceStatus.OBSERVED,
                    confidence="HIGH",
                    description=f"Configured key rotation interval: {val_str}",
                    crypto_agility=CryptoAgility.NOT_OBSERVABLE,
                    metadata={"key_rotation": val_str}
                )
            )

        return obs_list

    def _evaluate_hash_algorithms(self, entry: ParsedEntry) -> List[ConfigObservation]:
        """Detect explicit hash / digest algorithms."""
        obs_list: List[ConfigObservation] = []
        path_lower = entry.path.lower()

        # If it's part of a full cipher suite or signature, skip standalone hash to avoid duplicate noise
        if any(k in path_lower for k in ("cipher_suites", "ssl_ciphers", "tls_version")):
            return obs_list

        if any(k in path_lower for k in ("hash", "digest", "mac", "csrf")):
            val_str = str(entry.value).strip()
            matches = HASH_ALGORITHM_PATTERN.finditer(val_str)
            for m in matches:
                algo = m.group(1).upper()
                obs_list.append(
                    ConfigObservation(
                        file=self.source_file,
                        line=entry.line,
                        path=entry.path,
                        value=algo,
                        role=CryptoRole.HASH_FUNCTION,
                        algorithm=algo,
                        evidence_status=EvidenceStatus.OBSERVED,
                        confidence="HIGH",
                        description=f"Configured hash / digest algorithm: {algo}",
                        crypto_agility=self._assess_agility(entry, [val_str]),
                        metadata={"hash_algorithm": algo}
                    )
                )

        return obs_list

    def _evaluate_pqc_algorithms(self, entry: ParsedEntry) -> List[ConfigObservation]:
        """Detect Post-Quantum Cryptography algorithms (ML-KEM, ML-DSA, SLH-DSA)."""
        obs_list: List[ConfigObservation] = []
        values = self._normalize_values(entry.value)
        agility = self._assess_agility(entry, values)

        for val in values:
            val_str = str(val).strip()
            matches = PQC_ALGORITHM_PATTERN.finditer(val_str)
            for m in matches:
                algo = m.group(1).upper()
                # Determine role: ML-KEM is KEM / KEY_EXCHANGE, ML-DSA is SIGNATURE
                if "KEM" in algo:
                    role = CryptoRole.KEY_EXCHANGE
                elif "DSA" in algo or "SPHINCS" in algo:
                    role = CryptoRole.DIGITAL_SIGNATURE
                else:
                    role = CryptoRole.KEY_EXCHANGE

                obs_list.append(
                    ConfigObservation(
                        file=self.source_file,
                        line=entry.line,
                        path=entry.path,
                        value=algo,
                        role=role,
                        algorithm=algo,
                        evidence_status=EvidenceStatus.OBSERVED,
                        confidence="HIGH",
                        description=f"Detected post-quantum cryptographic algorithm: {algo}",
                        crypto_agility=agility,
                        metadata={"pqc_algorithm": algo, "is_pqc": True}
                    )
                )

        return obs_list

    # ------------------ HELPER UTILITIES ------------------

    def _normalize_values(self, val: Any) -> List[Any]:
        if isinstance(val, list):
            return val
        elif isinstance(val, (dict, set)):
            return list(val.values()) if isinstance(val, dict) else list(val)
        return [val]

    def _assess_agility(self, entry: ParsedEntry, values: List[Any]) -> CryptoAgility:
        """
        Determine whether configuration appears CONFIGURABLE, HARDCODED, or NOT_OBSERVABLE.
        Rules:
        - Interpolated string ${VAR} -> CONFIGURABLE
        - List of multiple algorithms -> CONFIGURABLE
        - Single literal value -> HARDCODED
        - Explicit config flag (e.g. crypto_agility = CONFIGURABLE) -> CONFIGURABLE
        """
        if entry.is_interpolated:
            return CryptoAgility.CONFIGURABLE
        if entry.is_list and len(values) > 1:
            return CryptoAgility.CONFIGURABLE
        if len(values) == 1:
            val_str = str(values[0]).strip().upper()
            if val_str in ("CONFIGURABLE", "MULTI-OPTION", "NEGOTIABLE"):
                return CryptoAgility.CONFIGURABLE
            if val_str in ("HARDCODED", "FIXED", "STATIC"):
                return CryptoAgility.HARDCODED
            return CryptoAgility.HARDCODED
        return CryptoAgility.NOT_OBSERVABLE

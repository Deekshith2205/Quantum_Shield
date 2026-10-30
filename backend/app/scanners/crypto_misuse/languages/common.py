"""Shared regex patterns, heuristic filters, and key collection helpers.
Safe, deterministic, and non-executing.
"""

import math
import re
from typing import List, Tuple, Dict, Any, Optional
from app.scanners.crypto_misuse.evidence import (
    calculate_line_col,
    mask_secret,
    compute_key_fingerprint,
)
from app.scanners.crypto_misuse.models import MisuseFinding, EvidenceStatus, CryptoRole, RiskCategory, FindingSeverity
from app.scanners.crypto_misuse.rules import get_rule


# Placeholders that indicate template/environment injection rather than actual hardcoded secret
PLACEHOLDER_SUBSTRINGS = (
    "${", "#{", "{{", "<placeholder", "<enter_", "your_", "todo", "changeme",
    "replace_me", "example", "my-secret-key", "xxxx", "dummy", "sample_password"
)

# Common env access patterns
ENV_CALL_PATTERNS = re.compile(
    r"(?:os\.getenv|os\.environ|process\.env|System\.getenv|getenv|\$_ENV|\$_SERVER|config\(|env\()",
    re.IGNORECASE
)


def calculate_shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    frequencies = {}
    for char in data:
        frequencies[char] = frequencies.get(char, 0) + 1
    for count in frequencies.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def is_placeholder_or_env(val: str, surrounding_line: str = "") -> bool:
    """Determine if a string value is a template placeholder, environment variable lookup, or dummy string."""
    clean = val.strip().strip("'\"`")
    if not clean:
        return True

    lower_val = clean.lower()
    for ph in PLACEHOLDER_SUBSTRINGS:
        if ph in lower_val:
            return True

    if surrounding_line and ENV_CALL_PATTERNS.search(surrounding_line):
        return True

    # Looks like a URL or filesystem path rather than secret
    if lower_val.startswith(("http://", "https://", "/", "./", "../", "c:\\", "file://")):
        return True

    # Pure formatting / config key name
    if clean.isupper() and "_" in clean and not any(c.isdigit() for c in clean):
        return False  # might be constant

    return False


def find_pem_private_keys(content: str, language: str, filename: str) -> Tuple[List[MisuseFinding], List[Dict[str, Any]]]:
    """
    Detect hardcoded PEM private keys across any file format.
    Returns findings and key entries for duplicate tracking.
    """
    findings: List[MisuseFinding] = []
    key_entries: List[Dict[str, Any]] = []

    pattern = re.compile(
        r"-----BEGIN (?:[A-Z0-9 ]+)?PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END (?:[A-Z0-9 ]+)?PRIVATE KEY(?: BLOCK)?-----"
    )

    rule = get_rule("MISUSE-HARDCODED-KEY")

    for match in pattern.finditer(content):
        raw_key = match.group(0)
        start_idx = match.start()
        line, col = calculate_line_col(content, start_idx)
        masked = mask_secret(raw_key)
        fingerprint = compute_key_fingerprint(raw_key)

        finding = MisuseFinding(
            rule_id="MISUSE-HARDCODED-KEY",
            title="Hardcoded Cryptographic Private Key (PEM format)",
            description=rule.description if rule else "Hardcoded private key found in source code.",
            language=language,
            file=filename,
            line=line,
            column=col,
            matched_value=masked,
            value=masked,
            role=CryptoRole.KEY.value,
            risk=RiskCategory.SECRET_EXPOSURE.value,
            severity=FindingSeverity.CRITICAL.value,
            evidence_status=EvidenceStatus.OBSERVED.value,
            confidence="HIGH",
            recommendation=rule.recommendation if rule else "Store private key in a secure keystore.",
            metadata={"fingerprint": fingerprint, "format": "PEM", "key_type": "PRIVATE_KEY"},
        )
        findings.append(finding)
        key_entries.append({
            "fingerprint": fingerprint,
            "raw_material": raw_key,
            "file": filename,
            "line": line,
            "column": col,
            "role": CryptoRole.KEY.value,
        })

    return findings, key_entries


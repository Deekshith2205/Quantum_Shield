"""Master detectors orchestrator and cross-file duplicate key detector.
Deterministic, safe, non-executing.
"""

from typing import List, Dict, Any, Tuple
from collections import defaultdict
from app.scanners.crypto_misuse.models import (
    MisuseFinding,
    EvidenceStatus,
    CryptoRole,
    RiskCategory,
    FindingSeverity,
    SupportedLanguage,
)
from app.scanners.crypto_misuse.rules import get_rule
from app.scanners.crypto_misuse.evidence import mask_secret
from app.scanners.crypto_misuse.languages.python_detector import analyze_python_source
from app.scanners.crypto_misuse.languages.java_detector import analyze_java_source
from app.scanners.crypto_misuse.languages.javascript_detector import analyze_javascript_source
from app.scanners.crypto_misuse.languages.php_detector import analyze_php_source


def detect_file_misuse(
    content: str, language: str, filename: str
) -> Tuple[List[MisuseFinding], List[Dict[str, Any]]]:
    """
    Run static analysis for a specific source file based on language.
    Returns:
        (findings, key_entries_for_duplicate_tracking)
    """
    lang = language.lower()
    if lang == SupportedLanguage.PYTHON.value or lang.endswith(".py"):
        return analyze_python_source(content, filename)
    elif lang == SupportedLanguage.JAVA.value or lang.endswith(".java"):
        return analyze_java_source(content, filename)
    elif lang in (SupportedLanguage.JAVASCRIPT.value, "js", "ts", "typescript") or any(
        lang.endswith(ext) for ext in [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"]
    ):
        return analyze_javascript_source(content, filename)
    elif lang == SupportedLanguage.PHP.value or any(lang.endswith(ext) for ext in [".php", ".phtml"]):
        return analyze_php_source(content, filename)
    else:
        # Unsupported language
        return [], []


def detect_duplicate_keys(
    all_key_entries: List[Dict[str, Any]]
) -> List[MisuseFinding]:
    """
    Analyze accumulated key entries from all scanned files.
    If the same key fingerprint appears across multiple distinct files,
    report deterministic duplicate key findings.
    Never exposes raw key material; uses safe masked snippet and sha256 fingerprint.
    """
    duplicate_findings: List[MisuseFinding] = []
    rule = get_rule("MISUSE-DUPLICATE-KEY")

    # Group entries by fingerprint
    grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for entry in all_key_entries:
        fp = entry.get("fingerprint")
        if fp and fp != "sha256:empty":
            grouped[fp].append(entry)

    # Detect duplicates across distinct files
    for fingerprint, entries in grouped.items():
        distinct_files = sorted(list(set(e["file"] for e in entries)))
        if len(distinct_files) > 1:
            # Duplication confirmed across distinct assets/files
            first_raw = entries[0].get("raw_material", "")
            masked_rep = mask_secret(first_raw)
            all_occurrences = [
                {"file": e["file"], "line": e["line"], "column": e["column"]}
                for e in entries
            ]

            for entry in entries:
                finding = MisuseFinding(
                    rule_id="MISUSE-DUPLICATE-KEY",
                    title="Duplicated Cryptographic Key Material Across Assets",
                    description=(
                        f"Same cryptographic key material appears across multiple assets: "
                        f"{', '.join(distinct_files)}."
                    ),
                    language="multi",
                    file=entry["file"],
                    line=entry["line"],
                    column=entry["column"],
                    matched_value=f"fingerprint:{fingerprint}",
                    role=entry.get("role", CryptoRole.SECRET_STORAGE.value),
                    risk=RiskCategory.SECRET_EXPOSURE.value,
                    severity=FindingSeverity.HIGH.value,
                    evidence_status=EvidenceStatus.OBSERVED.value,
                    confidence="HIGH",
                    recommendation=(
                        rule.recommendation
                        if rule
                        else "Isolate cryptographic keys per asset and environment."
                    ),
                    metadata={
                        "fingerprint": fingerprint,
                        "masked_preview": masked_rep,
                        "affected_files": distinct_files,
                        "occurrences": all_occurrences,
                    },
                )
                duplicate_findings.append(finding)

    return duplicate_findings


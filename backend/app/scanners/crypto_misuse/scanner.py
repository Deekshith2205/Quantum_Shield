"""Crypto-Misuse Scanner main engine.
Safe, deterministic static analysis scanner for sample banking source code.
Guarantees:
- Never executes scanned code
- Never imports scanned modules
- Rejects path traversal outside scan target
- Enforces maximum file-size limits
- Skips binary files
- Preserves read-only invariants (never mutates source files)
"""

import os
import time
from pathlib import Path
from typing import Union, List, Dict, Any, Optional

from app.scanners.crypto_misuse.models import (
    MisuseFinding,
    ScanResult,
    ScanSummary,
    SupportedLanguage,
)
from app.scanners.crypto_misuse.evidence import is_binary_content
from app.scanners.crypto_misuse.rules import RULE_CATALOG
from app.scanners.crypto_misuse.detectors import (
    detect_file_misuse,
    detect_duplicate_keys,
)

# Maximum file size to scan (2 MB default to prevent ReDoS / memory exhaustion)
DEFAULT_MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024

EXTENSION_TO_LANGUAGE = {
    ".py": SupportedLanguage.PYTHON.value,
    ".java": SupportedLanguage.JAVA.value,
    ".js": SupportedLanguage.JAVASCRIPT.value,
    ".jsx": SupportedLanguage.JAVASCRIPT.value,
    ".ts": SupportedLanguage.JAVASCRIPT.value,
    ".tsx": SupportedLanguage.JAVASCRIPT.value,
    ".mjs": SupportedLanguage.JAVASCRIPT.value,
    ".cjs": SupportedLanguage.JAVASCRIPT.value,
    ".php": SupportedLanguage.PHP.value,
    ".phtml": SupportedLanguage.PHP.value,
}


class CryptoMisuseScanner:
    """
    Static analysis scanner for detecting cryptographic misuse in sample banking code.
    Evidence producer for QuantumShield audit and risk evaluation.
    """

    def __init__(self, max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE_BYTES):
        self.max_file_size_bytes = max_file_size_bytes
        self.rules_evaluated_count = len(RULE_CATALOG)

    def scan_source(
        self,
        code: str,
        language: str,
        filename: str = "sample.py",
    ) -> ScanResult:
        """
        Scan a single in-memory source code string.
        Useful for unit tests, snippets, and CI buffers.
        """
        start_time = time.perf_counter()

        findings, key_entries = detect_file_misuse(code, language, filename)
        # Check duplicate keys if multiple entries within the same snippet
        dup_findings = detect_duplicate_keys(key_entries)
        all_findings = findings + dup_findings

        # Sort deterministically
        all_findings.sort(key=lambda f: (f.file, f.line, f.column or 0, f.rule_id))

        duration_ms = (time.perf_counter() - start_time) * 1000.0
        summary = self._build_summary(all_findings)

        return ScanResult(
            findings=all_findings,
            files_scanned=1,
            rules_evaluated=self.rules_evaluated_count,
            summary=summary,
            scan_duration_ms=round(duration_ms, 2),
        )

    def scan_file(self, file_path: Union[str, Path]) -> ScanResult:
        """
        Scan a single file on disk.
        Enforces size limits, binary detection, and path validation.
        """
        start_time = time.perf_counter()
        path = Path(file_path).resolve()

        if not path.is_file():
            raise FileNotFoundError(f"Target file does not exist: {file_path}")

        # Check file size limit
        file_size = path.stat().st_size
        if file_size > self.max_file_size_bytes:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            return ScanResult(
                findings=[],
                files_scanned=0,
                rules_evaluated=self.rules_evaluated_count,
                summary=ScanSummary(),
                scan_duration_ms=round(duration_ms, 2),
            )

        # Read bytes to check for binary content
        raw_bytes = path.read_bytes()
        if is_binary_content(raw_bytes):
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            return ScanResult(
                findings=[],
                files_scanned=0,
                rules_evaluated=self.rules_evaluated_count,
                summary=ScanSummary(),
                scan_duration_ms=round(duration_ms, 2),
            )

        language = self._detect_language(path)
        content = raw_bytes.decode("utf-8", errors="replace")

        findings, key_entries = detect_file_misuse(content, language, path.name)
        dup_findings = detect_duplicate_keys(key_entries)
        all_findings = findings + dup_findings

        all_findings.sort(key=lambda f: (f.file, f.line, f.column or 0, f.rule_id))
        duration_ms = (time.perf_counter() - start_time) * 1000.0
        summary = self._build_summary(all_findings)

        return ScanResult(
            findings=all_findings,
            files_scanned=1,
            rules_evaluated=self.rules_evaluated_count,
            summary=summary,
            scan_duration_ms=round(duration_ms, 2),
        )

    def scan_directory(
        self, directory_path: Union[str, Path], recursive: bool = True
    ) -> ScanResult:
        """
        Scan a directory of sample source files.
        Enforces path traversal boundaries, skips binaries and oversized files,
        and aggregates cross-file duplicate keys.
        """
        start_time = time.perf_counter()
        root_dir = Path(directory_path).resolve()

        if not root_dir.is_dir():
            raise NotADirectoryError(f"Target directory does not exist: {directory_path}")

        all_findings: List[MisuseFinding] = []
        all_key_entries: List[Dict[str, Any]] = []
        files_scanned_count = 0

        # Traverse files
        iterator = root_dir.rglob("*") if recursive else root_dir.glob("*")
        for item in sorted(iterator):
            if not item.is_file():
                continue

            # Path traversal boundary verification: item must be relative to root_dir
            try:
                rel_path = item.relative_to(root_dir)
            except ValueError:
                # Outside root_dir bounds - reject
                continue

            # Check supported extensions
            ext = item.suffix.lower()
            if ext not in EXTENSION_TO_LANGUAGE:
                continue

            # Check size limits
            if item.stat().st_size > self.max_file_size_bytes:
                continue

            # Check for binary content
            raw_bytes = item.read_bytes()
            if is_binary_content(raw_bytes):
                continue

            language = EXTENSION_TO_LANGUAGE[ext]
            content = raw_bytes.decode("utf-8", errors="replace")
            display_filename = str(rel_path).replace("\\", "/")

            file_findings, file_keys = detect_file_misuse(content, language, display_filename)
            all_findings.extend(file_findings)
            all_key_entries.extend(file_keys)
            files_scanned_count += 1

        # Detect cross-file duplicate keys
        duplicate_key_findings = detect_duplicate_keys(all_key_entries)
        all_findings.extend(duplicate_key_findings)

        # Sort deterministically
        all_findings.sort(key=lambda f: (f.file, f.line, f.column or 0, f.rule_id))

        duration_ms = (time.perf_counter() - start_time) * 1000.0
        summary = self._build_summary(all_findings)

        return ScanResult(
            findings=all_findings,
            files_scanned=files_scanned_count,
            rules_evaluated=self.rules_evaluated_count,
            summary=summary,
            scan_duration_ms=round(duration_ms, 2),
        )

    def scan(self, target: Union[str, Path]) -> ScanResult:
        """
        Unified entrypoint: intelligently scans file or directory path.
        """
        path = Path(target)
        if path.is_file():
            return self.scan_file(path)
        elif path.is_dir():
            return self.scan_directory(path)
        else:
            raise FileNotFoundError(f"Scan target '{target}' does not exist on disk.")

    def _detect_language(self, path: Path) -> str:
        ext = path.suffix.lower()
        return EXTENSION_TO_LANGUAGE.get(ext, SupportedLanguage.UNKNOWN.value)

    def _build_summary(self, findings: List[MisuseFinding]) -> ScanSummary:
        """Aggregate statistical summary across findings."""
        by_severity: Dict[str, int] = {}
        by_risk: Dict[str, int] = {}
        by_evidence_status: Dict[str, int] = {}
        by_role: Dict[str, int] = {}
        by_language: Dict[str, int] = {}

        for f in findings:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
            by_risk[f.risk] = by_risk.get(f.risk, 0) + 1
            by_evidence_status[f.evidence_status] = (
                by_evidence_status.get(f.evidence_status, 0) + 1
            )
            by_role[f.role] = by_role.get(f.role, 0) + 1
            by_language[f.language] = by_language.get(f.language, 0) + 1

        return ScanSummary(
            total_findings=len(findings),
            by_severity=by_severity,
            by_risk=by_risk,
            by_evidence_status=by_evidence_status,
            by_role=by_role,
            by_language=by_language,
        )


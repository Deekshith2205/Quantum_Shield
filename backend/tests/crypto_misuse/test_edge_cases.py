"""Edge cases, false-positive resistance, and boundary conditions for CryptoMisuseScanner.
"""

from pathlib import Path
from app.scanners.crypto_misuse.scanner import CryptoMisuseScanner
from app.scanners.crypto_misuse.models import FindingSeverity, CryptoRole


def test_environment_variable_lookups_not_flagged_as_secrets():
    scanner = CryptoMisuseScanner()
    code = """
import os

password = os.getenv("DATABASE_PASSWORD")
api_key = os.environ.get("BANK_API_KEY", "default_safe")
jwt_secret = os.environ["JWT_SECRET_KEY"]
"""
    result = scanner.scan_source(code, "python", "env_config.py")
    # Environment lookups should NOT be flagged as hardcoded secrets
    secret_findings = [f for f in result.findings if f.rule_id in ("MISUSE-HARDCODED-PASSWORD", "MISUSE-HARDCODED-SECRET", "MISUSE-HARDCODED-KEY")]
    assert len(secret_findings) == 0


def test_template_placeholders_not_flagged():
    scanner = CryptoMisuseScanner()
    code = """
const dbPassword = "${DB_PASSWORD}";
const apiKey = "{{API_KEY_PLACEHOLDER}}";
const secret = "<enter_your_secret_here>";
"""
    result = scanner.scan_source(code, "javascript", "template.js")
    secret_findings = [f for f in result.findings if f.rule_id in ("MISUSE-HARDCODED-PASSWORD", "MISUSE-HARDCODED-SECRET")]
    assert len(secret_findings) == 0


def test_cache_hash_vs_password_hash_role_separation():
    scanner = CryptoMisuseScanner()
    code = """
import hashlib

# Cache key generation (not a password)
cache_key = hashlib.md5(url.encode()).hexdigest()
"""
    result = scanner.scan_source(code, "python", "cache.py")
    assert len(result.findings) >= 1
    finding = result.findings[0]
    assert finding.rule_id == "MISUSE-MD5-HASH"
    # Role must be HASH, not PASSWORD_HASHING
    assert finding.role == CryptoRole.HASH.value
    # Severity must be HIGH, not CRITICAL (only passwords get CRITICAL)
    assert finding.severity == FindingSeverity.HIGH.value


def test_unsupported_extensions_ignored_in_directory(tmp_path: Path):
    scanner = CryptoMisuseScanner()

    # Create unsupported files (.txt, .md, .csv)
    (tmp_path / "notes.txt").write_text('password = "SecretPassword123!"', encoding="utf-8")
    (tmp_path / "data.csv").write_text('verify=False', encoding="utf-8")

    result = scanner.scan_directory(tmp_path)
    assert result.files_scanned == 0
    assert len(result.findings) == 0


def test_alternative_javascript_extensions(tmp_path: Path):
    scanner = CryptoMisuseScanner()

    # .ts and .mjs files
    (tmp_path / "auth.ts").write_text('const password = "TypeScriptSecret123!";', encoding="utf-8")
    (tmp_path / "index.mjs").write_text('const iv = Buffer.from("0000000000000000");', encoding="utf-8")

    result = scanner.scan_directory(tmp_path)
    assert result.files_scanned == 2
    assert result.summary.total_findings >= 2


def test_zero_division_or_empty_entropy_safety():
    from app.scanners.crypto_misuse.languages.common import calculate_shannon_entropy
    assert calculate_shannon_entropy("") == 0.0
    assert calculate_shannon_entropy("a" * 100) == 0.0
    assert calculate_shannon_entropy("abcdefghijklmnopqrstuvwxyz") > 4.0


# QuantumShield Crypto-Misuse Scanner Subsystem

**Subsystem Owner:** Backend Engineer 2  
**Target Integration:** Backend Engineer 1 (Audit & Risk Engine Pipeline)  
**Status:** Complete & Independently Tested

---

## 1. Overview

The **Crypto-Misuse Scanner** is a deterministic, static analysis engine designed to inspect banking sample code and configuration files for cryptographic vulnerabilities and post-quantum migration impediments.

It operates strictly on source text without ever executing, importing, compiling, or evaluating the scanned code.

### Supported Languages
- **Python** (`.py`)
- **Java** (`.java`)
- **JavaScript / TypeScript** (`.js`, `.jsx`, `.ts`, `.tsx`, `.mjs`, `.cjs`)
- **PHP** (`.php`, `.phtml`)

---

## 2. Directory Structure

```
backend/app/scanners/crypto_misuse/
├── __init__.py                      # Public API exports
├── models.py                        # Pydantic data models & enums
├── rules.py                         # 20 Misuse rule definitions & catalog
├── evidence.py                      # Line/col tracking, secret masking, SHA-256 fingerprinting
├── detectors.py                     # Master orchestrator & duplicate key tracker
├── scanner.py                       # CryptoMisuseScanner class & path/size boundaries
└── languages/
    ├── __init__.py
    ├── common.py                    # Shared PEM, entropy, placeholder filters
    ├── python_detector.py           # Python static analyzer (AST + regex fallback)
    ├── java_detector.py             # Java static analyzer
    ├── javascript_detector.py       # JavaScript / TypeScript static analyzer
    └── php_detector.py              # PHP static analyzer

backend/tests/fixtures/crypto_misuse/
├── python/                          # Vulnerable & clean Python fixtures
├── java/                            # Vulnerable & clean Java fixtures
├── javascript/                      # Vulnerable & clean JS fixtures
├── php/                             # Vulnerable & clean PHP fixtures
└── cross_system/                    # Cross-system duplicate key fixtures

backend/tests/crypto_misuse/
├── test_scanner_api.py              # API contract, JSON serialization, size & binary filters
├── test_python_rules.py             # Python rule coverage & clean code tests
├── test_java_rules.py               # Java rule coverage & clean code tests
├── test_javascript_rules.py         # JavaScript rule coverage & clean code tests
├── test_php_rules.py                # PHP rule coverage & clean code tests
├── test_duplicate_keys.py           # Cross-file duplicate key detection & safe fingerprints
├── test_quantum_classical_separation.py # Risk dimensions & AES-256 non-quantum verification
├── test_evidence_semantics.py       # EvidenceStatus invariants (NOT_OBSERVABLE != VULNERABLE)
└── test_edge_cases.py               # Environment variables, templates, cache keys, entropy
```

---

## 3. Implemented Misuse Rules (20 Rules)

| Rule ID | Title | Default Role | Risk Category | Severity |
|---|---|---|---|---|
| `MISUSE-HARDCODED-KEY` | Hardcoded Cryptographic Key / Private Key | `KEY` | `SECRET_EXPOSURE` | `CRITICAL` |
| `MISUSE-HARDCODED-SECRET` | Hardcoded API Token / Application Secret | `SECRET` | `SECRET_EXPOSURE` | `HIGH` |
| `MISUSE-HARDCODED-PASSWORD` | Hardcoded Password / Credential | `CREDENTIAL` | `SECRET_EXPOSURE` | `HIGH` |
| `MISUSE-WEAK-RANDOM` | Weak PRNG for Tokens / OTPs / Nonces | `RANDOMNESS` | `IMPLEMENTATION_SECURITY` | `HIGH` |
| `MISUSE-ECB-MODE` | Insecure Electronic Codebook (ECB) Mode | `BULK_ENCRYPTION` | `CLASSICAL_SECURITY` | `HIGH` |
| `MISUSE-STATIC-IV` | Static / Hardcoded Initialization Vector (IV) | `NONCE_IV` | `IMPLEMENTATION_SECURITY` | `HIGH` |
| `MISUSE-REUSED-IV` | Reused IV Across Cipher Invocations | `NONCE_IV` | `IMPLEMENTATION_SECURITY` | `HIGH` |
| `MISUSE-STATIC-NONCE` | Static Nonce in AEAD Schemes | `NONCE_IV` | `IMPLEMENTATION_SECURITY` | `CRITICAL` |
| `MISUSE-REUSED-NONCE` | Reused Nonce in AEAD Encryption | `NONCE_IV` | `IMPLEMENTATION_SECURITY` | `CRITICAL` |
| `MISUSE-MD5-HASH` | Insecure MD5 Hash in Security Context | `HASH` / `PASSWORD_HASHING` | `CLASSICAL_SECURITY` | `HIGH` / `CRITICAL` |
| `MISUSE-SHA1-HASH` | Deprecated SHA-1 Hash in Security Context | `HASH` / `DIGITAL_SIGNATURE` | `CLASSICAL_SECURITY` | `MEDIUM` / `HIGH` |
| `MISUSE-SMALL-RSA-KEY` | Small RSA Key Size (< 2048 bits) | `KEY` | `CLASSICAL_SECURITY` | `HIGH` / `CRITICAL` |
| `MISUSE-WEAK-RSA-EXPONENT` | Weak RSA Public Exponent (e <= 3) | `KEY` | `CLASSICAL_SECURITY` | `HIGH` |
| `MISUSE-DUPLICATE-KEY` | Duplicated Key Material Across Assets | `SECRET_STORAGE` | `SECRET_EXPOSURE` | `HIGH` |
| `MISUSE-DISABLED-CERT-VERIFY` | Disabled TLS Certificate Verification | `CERTIFICATE_VALIDATION` | `CLASSICAL_SECURITY` | `CRITICAL` |
| `MISUSE-DISABLED-HOSTNAME-VERIFY` | Disabled TLS Hostname Verification | `CERTIFICATE_VALIDATION` | `CLASSICAL_SECURITY` | `HIGH` |
| `MISUSE-HARDCODED-RSA-KEX` | Hardcoded RSA Key Exchange (Quantum-Exposed) | `KEY_ESTABLISHMENT` | `QUANTUM_SECURITY` | `HIGH` |
| `MISUSE-HARDCODED-ECDH-KEX` | Hardcoded ECDH/ECDHE Key Exchange | `KEY_ESTABLISHMENT` | `QUANTUM_SECURITY` | `MEDIUM` |
| `MISUSE-CRYPTO-AGILITY-LACK` | Inflexible Algorithm Configuration | `CRYPTO_AGILITY` | `CRYPTO_AGILITY` | `LOW` |
| `MISUSE-INSECURE-CIPHER-CONFIG` | Insecure Legacy Cipher (DES/3DES/RC4/Zero Salt) | `BULK_ENCRYPTION` | `CLASSICAL_SECURITY` | `HIGH` |

---

## 4. Output Contract & Finding Schema

### `scan(target)` API
```python
from app.scanners.crypto_misuse import CryptoMisuseScanner

scanner = CryptoMisuseScanner()
result = scanner.scan("path/to/banking/sample")
```

### JSON Structure
```json
{
  "findings": [
    {
      "rule_id": "MISUSE-ECB-MODE",
      "title": "Electronic Codebook (ECB) Mode Configured",
      "description": "ECB mode does not provide semantic security...",
      "language": "python",
      "file": "payment_service.py",
      "source_file": "payment_service.py",
      "line": 16,
      "line_number": 16,
      "column": 23,
      "matched_value": "AES.MODE_ECB",
      "value": "AES.MODE_ECB",
      "role": "BULK_ENCRYPTION",
      "risk": "CLASSICAL_SECURITY",
      "severity": "HIGH",
      "evidence_status": "OBSERVED",
      "confidence": "HIGH",
      "recommendation": "Use AES-GCM (AEAD mode) with fresh 96-bit nonces.",
      "metadata": {
        "matched_pattern": "AES.MODE_ECB"
      }
    }
  ],
  "files_scanned": 1,
  "rules_evaluated": 20,
  "summary": {
    "total_findings": 1,
    "by_severity": { "HIGH": 1 },
    "by_risk": { "CLASSICAL_SECURITY": 1 },
    "by_evidence_status": { "OBSERVED": 1 },
    "by_role": { "BULK_ENCRYPTION": 1 },
    "by_language": { "python": 1 }
  },
  "scan_duration_ms": 1.45
}
```

---

## 5. Security Guarantees & Invariants

1. **Zero Execution:** Scanned code is treated as untrusted text. No `exec()`, `eval()`, `importlib`, or compilation step is ever executed.
2. **Read-Only Invariant:** Scanner opens files exclusively in read mode (`"r"`). Source files are never modified.
3. **No Secret Disclosure:** Plaintext secrets/keys are masked in findings (e.g. `bank_****5678`), and cross-asset correlation uses deterministic SHA-256 fingerprints (`sha256:1a2b3c4d...`).
4. **Path Traversal Protection:** Resolved paths are checked against scan roots using `relative_to()` to prevent arbitrary file system traversal.
5. **Memory & DoS Protection:** Maximum file size threshold (default 2 MB) and binary null-byte checks skip large binaries and core dumps.
6. **Observability Invariant:** `NOT_OBSERVABLE != VULNERABLE`. If a control or setting cannot be statically observed, it is never converted into an active vulnerability.

---

## 6. Integration Contract for Backend Engineer 1

To integrate the `CryptoMisuseScanner` findings into the core `AuditFinding` model and `BankingRiskEngine`, Engineer 1 can implement an adapter function:

```python
from app.models.audit import AuditFinding, AuditDomain, FindingSeverity, RemediationPriority, ObservabilityState
from app.scanners.crypto_misuse import MisuseFinding

def adapt_misuse_finding_to_audit_finding(finding: MisuseFinding, asset_id: str) -> AuditFinding:
    # Map Risk Category to AuditDomain
    domain_map = {
        "QUANTUM_SECURITY": AuditDomain.QUANTUM_SECURITY,
        "CLASSICAL_SECURITY": AuditDomain.CLASSICAL_SECURITY,
        "SECRET_EXPOSURE": AuditDomain.ACCESS_CONTROL,
        "IMPLEMENTATION_SECURITY": AuditDomain.CRYPTOGRAPHY,
        "CRYPTO_AGILITY": AuditDomain.CONFIGURATION,
    }
    
    # Map Severity to RemediationPriority
    priority_map = {
        "CRITICAL": RemediationPriority.P0,
        "HIGH": RemediationPriority.P1,
        "MEDIUM": RemediationPriority.P2,
        "LOW": RemediationPriority.P3,
        "INFORMATIONAL": RemediationPriority.P3,
    }

    return AuditFinding(
        id=f"misuse-{finding.rule_id.lower()}-{finding.line}",
        asset_id=asset_id,
        domain=domain_map.get(finding.risk, AuditDomain.CRYPTOGRAPHY),
        control=f"Static Misuse Control: {finding.role}",
        title=finding.title,
        severity=FindingSeverity(finding.severity),
        evidence=finding.matched_value,
        evidence_source=f"{finding.file}:{finding.line}",
        observability=ObservabilityState(finding.evidence_status),
        impact=finding.description,
        recommendation=finding.recommendation,
        remediation_priority=priority_map.get(finding.severity, RemediationPriority.P2),
        metadata=finding.metadata,
    )
```


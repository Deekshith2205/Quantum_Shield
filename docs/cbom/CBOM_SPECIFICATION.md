# QuantumShield CBOM Specification

## 1. Overview
The Cryptographic Bill of Materials (CBOM) in QuantumShield is a normalized, deterministic inventory of cryptographic assets extracted from banking system configurations.

Target standard: **CycloneDX 1.7 JSON** (compatible with 1.6).

CRITICAL INVARIANTS:
1. **CBOM is an INVENTORY, NOT a risk engine**: The CBOM module does not assign P0/P1/P2/P3 priority or calculate risk scores. That belongs exclusively to the Banking Risk Engine.
2. **Explicit Evidence Provenance**: Every cryptographic fact tracks source file, line number, config path, and evidence status (`OBSERVED`, `INFERRED`, `NOT_OBSERVABLE`).
3. **NOT_OBSERVABLE != VULNERABLE**: Missing configurations are represented as structured evidence gaps. They are never converted into vulnerabilities.
4. **Secret-Safe**: All passwords, API keys, private key PEM blocks, and sensitive credentials are automatically redacted (`[REDACTED_SECRET]`) and never emitted.
5. **Deterministic Output**: Identical configuration inputs produce identical CBOM documents with reproducible UUIDv5 serial numbers.

---

## 2. CycloneDX Document Structure

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.7",
  "serialNumber": "urn:uuid:6ba7b810-...",
  "version": 1,
  "metadata": {
    "timestamp": "2026-10-30T00:00:00Z",
    "tools": [
      {
        "vendor": "QuantumShield",
        "name": "ConfigScanner-CBOM",
        "version": "1.0.0"
      }
    ],
    "component": {
      "bom-ref": "app-sample-bank-core-04",
      "type": "application",
      "name": "Synthetic Core Banking Ledger & Account Master",
      "version": "1.0.0",
      "properties": [
        {"name": "banking:criticality", "value": "CRITICAL"},
        {"name": "banking:trust_zone", "value": "DATA"},
        {"name": "banking:exposure", "value": "RESTRICTED"},
        {"name": "banking:data_sensitivity", "value": "HIGHLY_SENSITIVE"},
        {"name": "banking:data_lifetime", "value": "VERY_LONG"}
      ]
    }
  },
  "components": [
    {
      "type": "cryptographic-asset",
      "bom-ref": "crypto-sample-bank-core-04-001-bulk-encryption-aes-256-gcm",
      "name": "AES-256-GCM (BULK_ENCRYPTION)",
      "cryptoProperties": {
        "assetType": "algorithm",
        "algorithmProperties": {
          "primitive": "ae",
          "parameterSetIdentifier": "256",
          "mode": "gcm",
          "cryptoFunctions": ["encrypt", "decrypt"],
          "classicalSecurityLevel": 256,
          "nistQuantumSecurityLevel": 3,
          "executionEnvironment": "software-plain-ram"
        }
      },
      "properties": [
        {"name": "quantumshield:source_file", "value": "core_ledger.yaml"},
        {"name": "quantumshield:source_line", "value": "13"},
        {"name": "quantumshield:config_path", "value": "database_encryption.column_encryption"},
        {"name": "quantumshield:evidence_status", "value": "OBSERVED"},
        {"name": "quantumshield:role", "value": "BULK_ENCRYPTION"},
        {"name": "quantumshield:crypto_agility", "value": "HARDCODED"}
      ]
    }
  ],
  "dependencies": [
    {
      "ref": "crypto-sample-bank-core-04-001-bulk-encryption-aes-256-gcm",
      "dependsOn": [
        "crypto-sample-bank-core-04-005-key-wrapping-rsa-2048"
      ]
    }
  ]
}
```

---

## 3. Cryptographic Asset Types
- **algorithm**: Symmetric ciphers (AES, 3DES), asymmetric primitives (RSA, ECDSA), key exchange (ECDHE, X25519, ML-KEM), hash functions (SHA-256, SHA-384).
- **protocol**: Transport security protocols (TLS 1.2, TLS 1.3, IPsec, SSH).
- **certificate**: Digital certificates with subject name, format, and signature algorithm references.
- **related-crypto-material**: Keys and key management references (HSM, KMS, smartcards).

---

## 4. Cryptographic Relationships
Relationships are established only when configuration context establishes connection:
- `Protocol` -> `Cipher Suites` & `Key Exchange` (transport tier)
- `Certificate` -> `Signature Algorithm` (public key tier)
- `Bulk Encryption` -> `Key Wrapping` (data protection tier)
- `Key Wrapping` -> `Key Storage / HSM` (hardware root of trust tier)

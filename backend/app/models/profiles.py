"""Synthetic Banking System Profiles & Configuration Catalog.
Phase 4A - Representative Banking Systems & Configuration Evidence Model

DISCLAIMER:
QuantumShield's banking profiles are representative synthetic environments
used to demonstrate security auditing and migration prioritization.
They do not represent the actual architecture or configuration of any specific bank.
"""

from typing import List, Dict, Optional
from app.models.banking import (
    BankingAsset,
    BankingAssetType,
    AssetCriticality,
    DataSensitivity,
    AssetExposure,
    DataLifetime,
    TrustZone,
    SecurityLayer,
    EvidenceSource,
    EvidenceItem,
    EvidenceGap,
    EvidenceGapType,
    CryptoConfiguration,
    KeyProtectionChain,
)
from app.models.audit import ObservabilityState


SYNTHETIC_DISCLAIMER: str = (
    "QuantumShield's banking profiles are representative synthetic environments "
    "used to demonstrate security auditing and migration prioritization. "
    "They do not represent the actual architecture or configuration of any specific bank."
)


SYNTHETIC_BANKING_PROFILES: List[BankingAsset] = [
    # --------------------------------------------------------------------------
    # Profile 1: Modern Payment Gateway
    # --------------------------------------------------------------------------
    BankingAsset(
        id="BANK-PROF-PAYMENT-GATEWAY",
        name="Modern Payment Gateway",
        asset_type=BankingAssetType.PAYMENT_GATEWAY,
        system_type=BankingAssetType.PAYMENT_GATEWAY,
        description="High-throughput payment gateway processing cardholder operations and inter-bank fund settlements.",
        criticality=AssetCriticality.CRITICAL,
        data_sensitivity=DataSensitivity.HIGHLY_SENSITIVE,
        exposure=AssetExposure.INTERNET,
        data_lifetime=DataLifetime.LONG,
        trust_zone=TrustZone.DMZ,
        tags=["payment", "pci-dss", "pqc-hybrid", "hsm", "critical"],
        cryptography=CryptoConfiguration(
            tls_versions=["TLSv1.3"],
            cipher_suites=["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"],
            key_exchange="X25519MLKEM768",
            certificates=["CN=payments.bank.example, ECDSA-P256 with SHA-384"],
            signature_algorithm="ecdsa-with-SHA384",
            certificate_key_algorithm="ECC",
            certificate_key_size=256,
            data_encryption_algorithm="AES-256-GCM",
            key_wrapping_algorithm="ML-KEM-768",
            key_storage="HSM",
            kms_or_hsm="Thales payShield 10K Hardware Security Module",
            key_chain=KeyProtectionChain(
                data_encryption="AES-256-GCM",
                key_wrapping="ML-KEM-768",
                key_storage="HSM",
                authentication="ECDSA-P256",
            ),
        ),
        key_management={
            "storage_type": "HSM",
            "appliance": "Thales payShield 10K",
            "fips_level": "FIPS 140-3 Level 3",
            "rotation_interval_days": 90,
            "dual_control_enforced": True,
        },
        authentication={
            "api_auth": "Mutual TLS (mTLS) with X.509 Client Certificates",
            "admin_auth": "Hardware Security Key FIDO2/WebAuthn MFA",
            "token_format": "OAuth 2.0 / RFC 7519 JWT (ES256)",
        },
        evidence_items=[
            EvidenceItem(
                id="EV-PG-01",
                control="Perimeter Transport Protocol",
                value="TLSv1.3",
                source=EvidenceSource.CONFIGURATION_FILE,
                observability=ObservabilityState.OBSERVED,
                confidence="HIGH",
                description="Perimeter reverse proxy strictly enforces RFC 8446 TLS 1.3.",
                layer=SecurityLayer.EDGE,
            ),
            EvidenceItem(
                id="EV-PG-02",
                control="Session Key Exchange",
                value="X25519MLKEM768",
                source=EvidenceSource.CONFIGURATION_FILE,
                observability=ObservabilityState.CAPABILITY_PROBED,
                confidence="HIGH",
                description="Negotiates hybrid post-quantum key encapsulation (X25519 + NIST FIPS 203 ML-KEM-768).",
                layer=SecurityLayer.EDGE,
            ),
            EvidenceItem(
                id="EV-PG-03",
                control="Leaf Certificate Authentication",
                value="ECDSA-P256 with SHA-384",
                source=EvidenceSource.CONFIGURATION_FILE,
                observability=ObservabilityState.OBSERVED,
                confidence="HIGH",
                description="Public-key certificate issued by trusted financial enterprise CA.",
                layer=SecurityLayer.EDGE,
            ),
            EvidenceItem(
                id="EV-PG-04",
                control="Merchant Ingress Authentication",
                value="Mutual TLS (mTLS)",
                source=EvidenceSource.CONFIGURATION_FILE,
                observability=ObservabilityState.OBSERVED,
                confidence="HIGH",
                description="Inbound merchant API calls require client certificate mutual TLS validation.",
                layer=SecurityLayer.API_GATEWAY,
            ),
            EvidenceItem(
                id="EV-PG-05",
                control="Internal Service-to-Service Encryption",
                value="Envoy SPIFFE/SPIRE mTLS",
                source=EvidenceSource.CONFIGURATION_FILE,
                observability=ObservabilityState.OBSERVED,
                confidence="HIGH",
                description="Zero Trust service mesh enforces strict short-lived identity mTLS between pods.",
                layer=SecurityLayer.SERVICE_TO_SERVICE,
            ),
            EvidenceItem(
                id="EV-PG-06",
                control="Data Payload Encryption",
                value="AES-256-GCM",
                source=EvidenceSource.CONFIGURATION_FILE,
                observability=ObservabilityState.OBSERVED,
                confidence="HIGH",
                description="Cardholder Primary Account Numbers (PAN) encrypted at rest using AES-256 authenticated Galois/Counter Mode.",
                layer=SecurityLayer.DATA_AND_KEYS,
            ),
            EvidenceItem(
                id="EV-PG-07",
                control="Master Key Protection",
                value="Hardware Security Module (HSM)",
                source=EvidenceSource.OPERATOR_DECLARED,
                observability=ObservabilityState.OBSERVED,
                confidence="HIGH",
                description="Root and Key Encryption Keys (KEK) isolated within tamper-responsive HSM hardware.",
                layer=SecurityLayer.DATA_AND_KEYS,
            ),
            EvidenceItem(
                id="EV-PG-08",
                control="Key Wrapping Mechanism",
                value="ML-KEM-768 Hybrid Key Wrapping",
                source=EvidenceSource.CONFIGURATION_FILE,
                observability=ObservabilityState.OBSERVED,
                confidence="HIGH",
                description="Data encryption keys wrapped using quantum-safe hybrid KEM before internal distribution.",
                layer=SecurityLayer.DATA_AND_KEYS,
            ),
            EvidenceItem(
                id="EV-PG-09",
                control="Privileged Operator Authentication",
                value="Hardware Token MFA (FIDO2)",
                source=EvidenceSource.OPERATOR_DECLARED,
                observability=ObservabilityState.OBSERVED,
                confidence="HIGH",
                description="Administrative access mandates hardware security key phishing-resistant MFA.",
                layer=SecurityLayer.ADMINISTRATIVE,
            ),
        ],
        evidence_gaps=[
            EvidenceGap(
                gap_type=EvidenceGapType.INTERNAL_MTLS,
                layer=SecurityLayer.SERVICE_TO_SERVICE,
                control="Backend Service-to-Service mTLS",
                description="Internal mesh mTLS communication between payment microservices cannot be verified from perimeter scans.",
                evidence_needed="Service mesh configuration manifest (e.g. Istio PeerAuthentication / SPIFFE attestation)",
            ),
            EvidenceGap(
                gap_type=EvidenceGapType.HSM_USAGE,
                layer=SecurityLayer.DATA_AND_KEYS,
                control="Physical HSM Attestation",
                description="Physical HSM hardware tamper state and firmware certification cannot be probed externally.",
                evidence_needed="FIPS 140-3 certificate and vendor HSM cryptographic inventory audit statement",
            ),
        ],
        metadata={
            "synthetic_profile_version": "1.0",
            "pqc_posture": "HYBRID_READY",
            "compliance_targets": ["PCI-DSS v4.0", "NIST SP 800-207", "NIST FIPS 203"],
        },
    ),

    # --------------------------------------------------------------------------
    # Profile 2: Legacy Core Banking
    # --------------------------------------------------------------------------
    BankingAsset(
        id="BANK-PROF-CORE-BANKING",
        name="Legacy Core Banking System",
        asset_type=BankingAssetType.CORE_BANKING,
        system_type=BankingAssetType.CORE_BANKING,
        description="Mainframe-backed general ledger, deposit engine, and account master record database.",
        criticality=AssetCriticality.CRITICAL,
        data_sensitivity=DataSensitivity.HIGHLY_SENSITIVE,
        exposure=AssetExposure.INTERNAL,
        data_lifetime=DataLifetime.VERY_LONG,
        trust_zone=TrustZone.DATA,
        tags=["core-banking", "mainframe", "ledger", "legacy-crypto", "critical"],
        cryptography=CryptoConfiguration(
            tls_versions=["TLSv1.2"],
            cipher_suites=["ECDHE-RSA-AES256-GCM-SHA384"],
            key_exchange="ECDHE",
            certificates=["CN=corebanking.internal.bank, RSA-2048 with SHA-256"],
            signature_algorithm="sha256WithRSAEncryption",
            certificate_key_algorithm="RSA",
            certificate_key_size=2048,
            data_encryption_algorithm="AES-256",
            key_wrapping_algorithm="RSA-2048",
            key_storage="HSM",
            kms_or_hsm="IBM z16 Crypto Express 8S HSM",
            key_chain=KeyProtectionChain(
                data_encryption="AES-256",
                key_wrapping="RSA-2048",
                key_storage="HSM",
                authentication="RSA-2048",
            ),
        ),
        key_management={
            "storage_type": "HSM",
            "appliance": "IBM Crypto Express",
            "key_wrapping": "RSA-2048 PKCS#1 v1.5",
            "rotation_interval_days": 365,
        },
        authentication={
            "inter_service_auth": "Static API Keys / Kerberos Service Tickets",
            "admin_auth": "Password + SMS OTP (Legacy)",
        },
        evidence_items=[
            EvidenceItem(
                id="EV-CB-01",
                control="Transport Protocol",
                value="TLSv1.2",
                source=EvidenceSource.CONFIGURATION_FILE,
                observability=ObservabilityState.OBSERVED,
                confidence="HIGH",
                description="Core banking endpoints enforce TLS 1.2 with classical forward secrecy.",
                layer=SecurityLayer.SERVICE_TO_SERVICE,
            ),
            EvidenceItem(
                id="EV-CB-02",
                control="Key Exchange Mechanism",
                value="ECDHE (secp256r1)",
                source=EvidenceSource.CONFIGURATION_FILE,
                observability=ObservabilityState.CLASSICAL_ONLY_OBSERVED,
                confidence="HIGH",
                description="Uses classical elliptic-curve Diffie-Hellman without hybrid post-quantum support.",
                layer=SecurityLayer.SERVICE_TO_SERVICE,
            ),
            EvidenceItem(
                id="EV-CB-03",
                control="Certificate Authentication",
                value="RSA-2048 with SHA-256",
                source=EvidenceSource.CONFIGURATION_FILE,
                observability=ObservabilityState.OBSERVED,
                confidence="HIGH",
                description="Leaf and intermediate certificates use 2048-bit RSA keys vulnerable to Shor's algorithm.",
                layer=SecurityLayer.SERVICE_TO_SERVICE,
            ),
            EvidenceItem(
                id="EV-CB-04",
                control="Database at Rest Encryption",
                value="AES-256",
                source=EvidenceSource.CONFIGURATION_FILE,
                observability=ObservabilityState.OBSERVED,
                confidence="HIGH",
                description="Database tablespace encryption enforces 256-bit symmetric encryption.",
                layer=SecurityLayer.DATA_AND_KEYS,
            ),
            EvidenceItem(
                id="EV-CB-05",
                control="Key Protection & Wrapping",
                value="RSA-2048 Key Wrapping",
                source=EvidenceSource.CONFIGURATION_FILE,
                observability=ObservabilityState.OBSERVED,
                confidence="HIGH",
                description="Master Key wraps table encryption keys using classical 2048-bit RSA encryption.",
                layer=SecurityLayer.DATA_AND_KEYS,
            ),
        ],
        evidence_gaps=[
            EvidenceGap(
                gap_type=EvidenceGapType.KEY_WRAPPING,
                layer=SecurityLayer.DATA_AND_KEYS,
                control="Post-Quantum Key Wrapping",
                description="Key encapsulation mechanisms cannot be observed from external network perimeters.",
                evidence_needed="Database KMS/HSM key wrapping policy configuration audit",
            ),
            EvidenceGap(
                gap_type=EvidenceGapType.INTERNAL_CERTIFICATE_POLICY,
                layer=SecurityLayer.SERVICE_TO_SERVICE,
                control="Internal PKI Migration Roadmap",
                description="Internal CA trust anchors and root rotation schedules are maintained internally.",
                evidence_needed="Enterprise PKI Certificate Policy and Certification Practice Statement (CP/CPS)",
            ),
        ],
        metadata={
            "synthetic_profile_version": "1.0",
            "pqc_posture": "CLASSICAL_ONLY",
            "migration_difficulty": "HIGH",
        },
    ),

    # --------------------------------------------------------------------------
    # Profile 3: Customer / KYC Database
    # --------------------------------------------------------------------------
    BankingAsset(
        id="BANK-PROF-KYC-DB",
        name="Customer & KYC Records Vault",
        asset_type=BankingAssetType.CUSTOMER_DATABASE,
        system_type=BankingAssetType.CUSTOMER_DATABASE,
        description="High-assurance vault holding customer PII, tax identifiers, identity documents, and KYC biometrics.",
        criticality=AssetCriticality.CRITICAL,
        data_sensitivity=DataSensitivity.HIGHLY_SENSITIVE,
        exposure=AssetExposure.RESTRICTED,
        data_lifetime=DataLifetime.VERY_LONG,
        trust_zone=TrustZone.DATA,
        tags=["database", "pii", "kyc", "gdpr", "kms", "critical"],
        cryptography=CryptoConfiguration(
            tls_versions=["TLSv1.3"],
            cipher_suites=["TLS_AES_256_GCM_SHA384"],
            key_exchange="X25519",
            certificates=["CN=kycvault.internal.bank, ECDSA-P384"],
            data_encryption_algorithm="AES-256-GCM",
            key_wrapping_algorithm="RSA-2048",
            key_storage="KMS",
            kms_or_hsm="AWS KMS Customer Managed Key (CMK)",
            key_chain=KeyProtectionChain(
                data_encryption="AES-256-GCM",
                key_wrapping="RSA-2048",
                key_storage="KMS",
                authentication="RSA-3072",
            ),
        ),
        key_management={
            "storage_type": "KMS",
            "provider": "Cloud KMS",
            "automatic_rotation": True,
            "rotation_interval_days": 365,
        },
        authentication={
            "access_control": "Role-Based Access Control (RBAC) via IAM",
            "connection_security": "Mandatory TLS 1.3 with client cert verification",
        },
        evidence_items=[
            EvidenceItem(
                id="EV-KYC-01",
                control="At-Rest Encryption",
                value="AES-256-GCM",
                source=EvidenceSource.CONFIGURATION_FILE,
                observability=ObservabilityState.OBSERVED,
                confidence="HIGH",
                description="All table partitions and encrypted blob storage use AES-256-GCM authenticated encryption.",
                layer=SecurityLayer.DATA_AND_KEYS,
            ),
            EvidenceItem(
                id="EV-KYC-02",
                control="Key Management Service",
                value="Cloud KMS Customer Managed Key",
                source=EvidenceSource.OPERATOR_DECLARED,
                observability=ObservabilityState.OBSERVED,
                confidence="HIGH",
                description="Encryption keys managed through dedicated enterprise Key Management Service.",
                layer=SecurityLayer.DATA_AND_KEYS,
            ),
            EvidenceItem(
                id="EV-KYC-03",
                control="Key Wrapping (Envelope Encryption)",
                value="RSA-2048 Key Wrapping",
                source=EvidenceSource.CONFIGURATION_FILE,
                observability=ObservabilityState.OBSERVED,
                confidence="HIGH",
                description="Envelope encryption uses 2048-bit RSA key encapsulation vulnerable to quantum cryptanalysis.",
                layer=SecurityLayer.DATA_AND_KEYS,
            ),
            EvidenceItem(
                id="EV-KYC-04",
                control="Ingress Transport Protocol",
                value="TLSv1.3",
                source=EvidenceSource.CONFIGURATION_FILE,
                observability=ObservabilityState.OBSERVED,
                confidence="HIGH",
                description="Application microservice access to database requires TLS 1.3.",
                layer=SecurityLayer.SERVICE_TO_SERVICE,
            ),
        ],
        evidence_gaps=[
            EvidenceGap(
                gap_type=EvidenceGapType.DATABASE_ENCRYPTION_AT_REST,
                layer=SecurityLayer.DATA_AND_KEYS,
                control="At-Rest Tablespace Key Hierarchy",
                description="Database data-at-rest encryption algorithms cannot be inspected externally.",
                evidence_needed="Database encryption configuration export (e.g. Oracle TDE or PostgreSQL pgcrypto parameters)",
            ),
            EvidenceGap(
                gap_type=EvidenceGapType.KMS_USAGE,
                layer=SecurityLayer.DATA_AND_KEYS,
                control="KMS Key Policy & Permissions",
                description="KMS key policy permissions, key generation entropy, and rotation cannot be externally verified.",
                evidence_needed="Cloud KMS key policy JSON export",
            ),
        ],
        metadata={
            "synthetic_profile_version": "1.0",
            "pqc_posture": "WEAKEST_LINK_KEY_WRAPPING",
            "sndl_risk": "CRITICAL_PII_LONG_LIFETIME",
        },
    ),

    # --------------------------------------------------------------------------
    # Profile 4: Net Banking Portal
    # --------------------------------------------------------------------------
    BankingAsset(
        id="BANK-PROF-NET-BANKING",
        name="Retail Net Banking Portal",
        asset_type=BankingAssetType.NET_BANKING_PORTAL,
        system_type=BankingAssetType.NET_BANKING_PORTAL,
        description="Customer-facing internet banking portal offering retail account management, fund transfers, and bill payments.",
        criticality=AssetCriticality.HIGH,
        data_sensitivity=DataSensitivity.CONFIDENTIAL,
        exposure=AssetExposure.INTERNET,
        data_lifetime=DataLifetime.MEDIUM,
        trust_zone=TrustZone.DMZ,
        tags=["web-banking", "retail", "waf", "dmz", "high-criticality"],
        cryptography=CryptoConfiguration(
            tls_versions=["TLSv1.3"],
            cipher_suites=["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"],
            key_exchange="X25519",
            certificates=["CN=online.bank.example, ECDSA-P256 with SHA-256"],
            signature_algorithm="ecdsa-with-SHA256",
            certificate_key_algorithm="ECC",
            certificate_key_size=256,
            data_encryption_algorithm="AES-256-GCM",
            key_wrapping_algorithm="ECDH-P256",
            key_storage="KMS",
            key_chain=KeyProtectionChain(
                data_encryption="AES-256-GCM",
                key_wrapping="ECDH-P256",
                key_storage="KMS",
                authentication="ECDSA-P256",
            ),
        ),
        key_management={
            "storage_type": "KMS",
            "rotation_interval_days": 180,
        },
        authentication={
            "user_auth": "Password + Push-based Authenticator MFA",
            "session_management": "Encrypted secure HTTP-only cookies with SameSite=Strict",
        },
        evidence_items=[
            EvidenceItem(
                id="EV-NB-01",
                control="Perimeter Protocol",
                value="TLSv1.3",
                source=EvidenceSource.EXTERNAL_SCAN,
                observability=ObservabilityState.OBSERVED,
                confidence="HIGH",
                description="External TLS handshake successfully negotiated TLS 1.3.",
                layer=SecurityLayer.EDGE,
            ),
            EvidenceItem(
                id="EV-NB-02",
                control="Default Key Exchange",
                value="X25519",
                source=EvidenceSource.EXTERNAL_SCAN,
                observability=ObservabilityState.CLASSICAL_ONLY_OBSERVED,
                confidence="HIGH",
                description="Default TLS 1.3 KeyShare negotiated classical X25519; hybrid PQC not active.",
                layer=SecurityLayer.EDGE,
            ),
            EvidenceItem(
                id="EV-NB-03",
                control="Certificate Authentication",
                value="ECDSA-P256 with SHA-256",
                source=EvidenceSource.EXTERNAL_SCAN,
                observability=ObservabilityState.OBSERVED,
                confidence="HIGH",
                description="Public certificate uses 256-bit ECDSA public key.",
                layer=SecurityLayer.EDGE,
            ),
            EvidenceItem(
                id="EV-NB-04",
                control="User Multi-Factor Authentication",
                value="Push Authenticator / SMS Fallback",
                source=EvidenceSource.OPERATOR_DECLARED,
                observability=ObservabilityState.OBSERVED,
                confidence="MEDIUM",
                description="Retail customers must authenticate with second factor for sensitive transactions.",
                layer=SecurityLayer.ADMINISTRATIVE,
            ),
        ],
        evidence_gaps=[
            EvidenceGap(
                gap_type=EvidenceGapType.MFA_POLICY,
                layer=SecurityLayer.ADMINISTRATIVE,
                control="Step-up Authentication Policy",
                description="Customer step-up MFA challenge enforcement logic is internal to the application.",
                evidence_needed="Application security architecture document / Auth0/Okta policy export",
            ),
            EvidenceGap(
                gap_type=EvidenceGapType.INTERNAL_MTLS,
                layer=SecurityLayer.API_GATEWAY,
                control="Reverse Proxy to App Gateway mTLS",
                description="Reverse proxy connection to upstream web servers cannot be verified from external scans.",
                evidence_needed="NGINX / Cloudflare upstream TLS configuration manifest",
            ),
        ],
        metadata={
            "synthetic_profile_version": "1.0",
            "pqc_posture": "CLASSICAL_TRANSITION_CANDIDATE",
        },
    ),

    # --------------------------------------------------------------------------
    # Profile 5: ATM Network
    # --------------------------------------------------------------------------
    BankingAsset(
        id="BANK-PROF-ATM-NETWORK",
        name="ATM Transaction Processing Network",
        asset_type=BankingAssetType.ATM_NETWORK,
        system_type=BankingAssetType.ATM_NETWORK,
        description="Dedicated ATM endpoint communication network managing ISO 8583 message streams and PIN block encipherment.",
        criticality=AssetCriticality.HIGH,
        data_sensitivity=DataSensitivity.HIGHLY_SENSITIVE,
        exposure=AssetExposure.RESTRICTED,
        data_lifetime=DataLifetime.LONG,
        trust_zone=TrustZone.APPLICATION,
        tags=["atm", "iso8583", "pin-block", "des-migration", "hardware-crypto"],
        cryptography=CryptoConfiguration(
            tls_versions=["TLSv1.2"],
            cipher_suites=["ECDHE-RSA-AES128-GCM-SHA256"],
            key_exchange="ECDHE",
            certificates=["CN=atm-switch.internal.bank, RSA-2048"],
            signature_algorithm="sha256WithRSAEncryption",
            certificate_key_algorithm="RSA",
            certificate_key_size=2048,
            data_encryption_algorithm="AES-128-CBC",
            key_wrapping_algorithm="3DES-EDE-KW",
            key_storage="HSM",
            kms_or_hsm="Host Security Module (PIN Block Encryption)",
            key_chain=KeyProtectionChain(
                data_encryption="AES-128-CBC",
                key_wrapping="3DES-EDE-KW",
                key_storage="HSM",
                authentication="RSA-2048",
            ),
        ),
        key_management={
            "storage_type": "HSM",
            "appliance": "Dedicated PIN Pad HSM",
            "key_scheme": "DUKPT (Derived Unique Key Per Transaction)",
            "base_derivation_key": "3DES Double-Length BDK",
        },
        authentication={
            "device_auth": "MAC (Message Authentication Code) based on ISO 9797-1",
            "operator_auth": "Dual Physical Key Turn + Smartcard PIN",
        },
        evidence_items=[
            EvidenceItem(
                id="EV-ATM-01",
                control="Transport Protocol",
                value="TLSv1.2",
                source=EvidenceSource.CONFIGURATION_FILE,
                observability=ObservabilityState.OBSERVED,
                confidence="HIGH",
                description="ATM controller connections wrapped in TLS 1.2 on private cellular/leased-line APNs.",
                layer=SecurityLayer.EDGE,
            ),
            EvidenceItem(
                id="EV-ATM-02",
                control="PIN Block Encryption",
                value="3DES / DUKPT",
                source=EvidenceSource.CONFIGURATION_FILE,
                observability=ObservabilityState.OBSERVED,
                confidence="HIGH",
                description="PIN block enciphered using ISO 9564-1 Format 0 with DUKPT key derivation.",
                layer=SecurityLayer.DATA_AND_KEYS,
            ),
            EvidenceItem(
                id="EV-ATM-03",
                control="Key Protection & Translation",
                value="Host Security Module (HSM)",
                source=EvidenceSource.OPERATOR_DECLARED,
                observability=ObservabilityState.OBSERVED,
                confidence="HIGH",
                description="PIN translation between Zone Master Key (ZMK) and Terminal Master Key (TMK) occurs solely inside HSM.",
                layer=SecurityLayer.DATA_AND_KEYS,
            ),
            EvidenceItem(
                id="EV-ATM-04",
                control="ATM Master Key Wrapping",
                value="3DES-EDE Key Wrapping",
                source=EvidenceSource.CONFIGURATION_FILE,
                observability=ObservabilityState.OBSERVED,
                confidence="HIGH",
                description="Terminal keys wrapped with legacy 3DES key encrypting keys.",
                layer=SecurityLayer.DATA_AND_KEYS,
            ),
        ],
        evidence_gaps=[
            EvidenceGap(
                gap_type=EvidenceGapType.KEY_ROTATION,
                layer=SecurityLayer.DATA_AND_KEYS,
                control="DUKPT Base Derivation Key (BDK) Rotation",
                description="Atmosphere and cycle of DUKPT BDK lifecycle cannot be observed across network channels.",
                evidence_needed="ATM Switch key custodianship and key-injection facility audit report",
            ),
            EvidenceGap(
                gap_type=EvidenceGapType.SERVICE_IDENTITY,
                layer=SecurityLayer.EDGE,
                control="Physical ATM Hardware Attestation",
                description="Cryptographic hardware coprocessor integrity and anti-skimming sensors operate in isolated firmware.",
                evidence_needed="ATM terminal management system inventory and firmware attestation logs",
            ),
        ],
        metadata={
            "synthetic_profile_version": "1.0",
            "pqc_posture": "LEGACY_HIGH_EFFORT_MIGRATION",
            "risk_vector": "3DES_DEPRECATION_AND_SNDL",
        },
    ),
]


def get_synthetic_banking_profiles() -> List[BankingAsset]:
    """Returns the full catalog of representative synthetic banking system profiles."""
    return SYNTHETIC_BANKING_PROFILES


def get_synthetic_profile_by_id(profile_id: str) -> Optional[BankingAsset]:
    """Retrieves a synthetic profile by identifier."""
    clean_id = profile_id.strip().upper()
    for prof in SYNTHETIC_BANKING_PROFILES:
        if prof.id.upper() == clean_id:
            return prof
    return None

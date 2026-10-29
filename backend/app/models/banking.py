"""Banking domain asset model, security profiles, and configuration evidence.
Phase 4A - Banking System Profiles & Configuration Evidence Model

Establishes a normalized representation for:
- Representative banking systems (Core Banking, Payment Gateway, ATM Network, etc.)
- Multi-layer security architecture (EDGE, API_GATEWAY, SERVICE_TO_SERVICE, DATA_AND_KEYS, ADMINISTRATIVE)
- Explicit evidence provenance (EXTERNAL_SCAN, OPERATOR_DECLARED, CONFIGURATION_FILE, INFERRED)
- Key protection chains (Data Encryption -> Key Wrapping -> Key Storage -> Authentication)
- Structured evidence gaps (enforcing NOT_OBSERVABLE != VULNERABLE)
"""

from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, model_validator
from app.models.audit import ObservabilityState


class BankingAssetType(str, Enum):
    # Core Phase 4A Representative Banking Systems
    NET_BANKING_PORTAL = "NET_BANKING_PORTAL"
    MOBILE_BANKING_API = "MOBILE_BANKING_API"
    PAYMENT_GATEWAY = "PAYMENT_GATEWAY"
    UPI_PAYMENT_SERVICE = "UPI_PAYMENT_SERVICE"
    CARD_PROCESSING = "CARD_PROCESSING"
    CORE_BANKING = "CORE_BANKING"
    CUSTOMER_DATABASE = "CUSTOMER_DATABASE"
    PAYMENT_DATABASE = "PAYMENT_DATABASE"
    INTER_BANK_GATEWAY = "INTER_BANK_GATEWAY"
    ATM_NETWORK = "ATM_NETWORK"
    ADMIN_PORTAL = "ADMIN_PORTAL"
    AUTHENTICATION_SERVICE = "AUTHENTICATION_SERVICE"
    NOTIFICATION_SERVICE = "NOTIFICATION_SERVICE"
    INTERNAL_SERVICE = "INTERNAL_SERVICE"

    # Backwards-compatible legacy Phase 0 types
    PUBLIC_WEBSITE = "PUBLIC_WEBSITE"
    WEB_BANKING = "WEB_BANKING"
    MOBILE_API = "MOBILE_API"
    API_GATEWAY = "API_GATEWAY"
    PAYMENT_SERVICE = "PAYMENT_SERVICE"
    TRANSACTION_SERVICE = "TRANSACTION_SERVICE"
    ACCOUNT_SERVICE = "ACCOUNT_SERVICE"
    OTHER = "OTHER"


class AssetCriticality(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DataSensitivity(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    HIGHLY_SENSITIVE = "HIGHLY_SENSITIVE"


class AssetExposure(str, Enum):
    INTERNET = "INTERNET"
    PARTNER = "PARTNER"
    INTERNAL = "INTERNAL"
    RESTRICTED = "RESTRICTED"


class DataLifetime(str, Enum):
    SHORT = "SHORT"
    MEDIUM = "MEDIUM"
    LONG = "LONG"
    VERY_LONG = "VERY_LONG"


class TrustZone(str, Enum):
    PUBLIC = "PUBLIC"
    DMZ = "DMZ"
    APPLICATION = "APPLICATION"
    DATA = "DATA"
    ADMIN = "ADMIN"
    THIRD_PARTY = "THIRD_PARTY"


class SecurityLayer(str, Enum):
    """Normalized banking system architecture layers."""
    EDGE = "EDGE"
    API_GATEWAY = "API_GATEWAY"
    SERVICE_TO_SERVICE = "SERVICE_TO_SERVICE"
    DATA_AND_KEYS = "DATA_AND_KEYS"
    ADMINISTRATIVE = "ADMINISTRATIVE"


class EvidenceSource(str, Enum):
    """
    Evidence provenance classification.
    Explicitly distinguishes externally observed vs operator declared vs configuration evidence.
    """
    EXTERNAL_SCAN = "EXTERNAL_SCAN"
    OPERATOR_DECLARED = "OPERATOR_DECLARED"
    CONFIGURATION_FILE = "CONFIGURATION_FILE"
    INFERRED = "INFERRED"


class EvidenceGapType(str, Enum):
    """Standardized banking evidence gap controls that cannot be determined externally."""
    INTERNAL_MTLS = "INTERNAL_MTLS"
    HSM_USAGE = "HSM_USAGE"
    KMS_USAGE = "KMS_USAGE"
    KEY_ROTATION = "KEY_ROTATION"
    DATABASE_ENCRYPTION_AT_REST = "DATABASE_ENCRYPTION_AT_REST"
    PRIVILEGED_ACCESS_POLICY = "PRIVILEGED_ACCESS_POLICY"
    MFA_POLICY = "MFA_POLICY"
    SERVICE_IDENTITY = "SERVICE_IDENTITY"
    LEAST_PRIVILEGE = "LEAST_PRIVILEGE"
    CONTINUOUS_VERIFICATION = "CONTINUOUS_VERIFICATION"
    KEY_WRAPPING = "KEY_WRAPPING"
    INTERNAL_CERTIFICATE_POLICY = "INTERNAL_CERTIFICATE_POLICY"


class KeyProtectionChain(BaseModel):
    """
    Normalized structure tracing cryptographic key hierarchies:
    Data Encryption -> Key Wrapping -> Key Storage -> Authentication / Master Key.
    """
    data_encryption: Optional[str] = Field(default=None, description="Data at-rest encryption algorithm (e.g. AES-256-GCM)")
    key_wrapping: Optional[str] = Field(default=None, description="Key wrapping / encapsulation algorithm (e.g. RSA-2048, ML-KEM-768)")
    key_storage: Optional[str] = Field(default=None, description="Key storage facility (e.g. HSM, KMS, PLAINTEXT_CONFIGURATION)")
    authentication: Optional[str] = Field(default=None, description="Root/master key authentication algorithm (e.g. ECDSA-P256, RSA-3072)")


class CryptoConfiguration(BaseModel):
    """Normalized cryptographic control parameters for transport, storage, and key management."""
    tls_versions: List[str] = Field(default_factory=list, description="Supported or configured TLS versions")
    cipher_suites: List[str] = Field(default_factory=list, description="Configured symmetric/asymmetric cipher suites")
    key_exchange: Optional[str] = Field(default=None, description="Key exchange mechanism or KeyShare group")
    certificates: List[str] = Field(default_factory=list, description="Certificate identities or thumbprints")
    signature_algorithm: Optional[str] = Field(default=None, description="Digital signature algorithm")
    certificate_key_algorithm: Optional[str] = Field(default=None, description="Public key algorithm for certificate")
    certificate_key_size: Optional[int] = Field(default=None, description="Public key size in bits")
    data_encryption_algorithm: Optional[str] = Field(default=None, description="Symmetric bulk data encryption algorithm")
    key_wrapping_algorithm: Optional[str] = Field(default=None, description="Key wrapping / KEK algorithm")
    key_storage: Optional[str] = Field(default=None, description="Key storage medium: HSM, KMS, PLAINTEXT")
    kms_or_hsm: Optional[str] = Field(default=None, description="Identifier of KMS provider or HSM appliance")
    key_chain: Optional[KeyProtectionChain] = Field(default=None, description="Normalized key hierarchy chain")


class EvidenceItem(BaseModel):
    """
    Reusable, provenance-aware security evidence object.
    Explicitly tracks origin (EXTERNAL_SCAN, OPERATOR_DECLARED, CONFIGURATION_FILE, INFERRED)
    and observability state (OBSERVED, NOT_OBSERVABLE, etc.).
    """
    id: str = Field(..., description="Unique evidence item identifier")
    control: str = Field(..., description="Control name or requirement (e.g. TLS Transport, Key Wrapping)")
    value: str = Field(..., description="Observed, declared, or configured value")
    source: EvidenceSource = Field(..., description="Evidence provenance")
    observability: ObservabilityState = Field(default=ObservabilityState.OBSERVED, description="Observability classification")
    confidence: str = Field(default="HIGH", description="Confidence level: HIGH, MEDIUM, LOW, UNCONFIRMED")
    description: str = Field(default="", description="Technical narrative or measurement detail")
    layer: Optional[SecurityLayer] = Field(default=None, description="Associated security architecture layer")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Supplementary technical metadata")


class EvidenceGap(BaseModel):
    """
    Explicit representation of unobservable internal security controls.
    Enforces core invariant: NOT_OBSERVABLE != VULNERABLE.
    """
    gap_type: EvidenceGapType = Field(..., description="Standardized banking evidence gap identifier")
    layer: SecurityLayer = Field(..., description="Security architecture layer")
    control: str = Field(..., description="Security control with unobservable state")
    description: str = Field(..., description="Explanation of why this cannot be determined externally")
    evidence_needed: str = Field(..., description="Internal telemetry or configuration required")
    observability: ObservabilityState = Field(default=ObservabilityState.NOT_OBSERVABLE)
    source: EvidenceSource = Field(default=EvidenceSource.EXTERNAL_SCAN)


class BankingAsset(BaseModel):
    """
    Core Banking Asset & Security Profile model.
    Represents financial institution systems with full business criticality, trust architecture,
    security layers, and cryptographic configuration evidence.
    """
    id: str = Field(..., description="Unique asset identifier")
    name: str = Field(..., description="Asset name or service identifier")
    asset_type: BankingAssetType = Field(
        default=BankingAssetType.PUBLIC_WEBSITE,
        description="Functional classification of the banking asset"
    )
    system_type: Optional[BankingAssetType] = Field(
        default=None,
        description="Alias for asset_type representing banking system classification"
    )
    description: str = Field(default="", description="Asset functional description")
    criticality: AssetCriticality = Field(
        default=AssetCriticality.MEDIUM,
        description="Business criticality level (distinct from finding severity)"
    )
    data_sensitivity: DataSensitivity = Field(
        default=DataSensitivity.CONFIDENTIAL,
        description="Classification of data handled by this asset"
    )
    exposure: AssetExposure = Field(
        default=AssetExposure.INTERNET,
        description="Network exposure level"
    )
    data_lifetime: DataLifetime = Field(
        default=DataLifetime.LONG,
        description="Required confidentiality lifetime (quantum SNDL threat horizon)"
    )
    trust_zone: TrustZone = Field(
        default=TrustZone.DMZ,
        description="Network trust architecture segment"
    )
    layers: Dict[SecurityLayer, List[EvidenceItem]] = Field(
        default_factory=dict,
        description="Layered security evidence (EDGE, API_GATEWAY, SERVICE_TO_SERVICE, etc.)"
    )
    cryptography: Optional[CryptoConfiguration] = Field(
        default=None,
        description="Normalized cryptographic configuration"
    )
    key_management: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Key management lifecycle parameters"
    )
    authentication: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Identity and authentication configuration"
    )
    evidence_items: List[EvidenceItem] = Field(
        default_factory=list,
        description="Flat collection of all evidence items associated with this system"
    )
    evidence_gaps: List[EvidenceGap] = Field(
        default_factory=list,
        description="Identified evidence gaps where external observability is impossible"
    )
    tags: List[str] = Field(default_factory=list, description="Categorization tags")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Supplementary system metadata")

    @model_validator(mode="after")
    def sync_types_and_evidence(self) -> "BankingAsset":
        """Ensures system_type mirrors asset_type and layers mirror evidence_items."""
        if self.system_type is None:
            self.system_type = self.asset_type
        elif self.asset_type == BankingAssetType.PUBLIC_WEBSITE and self.system_type != BankingAssetType.PUBLIC_WEBSITE:
            self.asset_type = self.system_type

        # If evidence_items are provided but layers is empty, populate layers
        if self.evidence_items and not self.layers:
            grouped: Dict[SecurityLayer, List[EvidenceItem]] = {}
            for item in self.evidence_items:
                layer = item.layer or SecurityLayer.EDGE
                if layer not in grouped:
                    grouped[layer] = []
                grouped[layer].append(item)
            self.layers = grouped

        return self


# BankingSystemProfile is a direct alias for BankingAsset, fulfilling Phase 4A requirements
BankingSystemProfile = BankingAsset


def infer_default_banking_asset(domain: str) -> BankingAsset:
    """
    Infers an initial banking asset profile from a hostname.
    Provides realistic default banking context before custom asset configuration.
    """
    clean_domain = domain.lower().strip()
    domain_hash = hex(abs(hash(clean_domain)))[2:10].upper()
    asset_id = f"BANK-ASSET-{domain_hash}"

    # Contextual inference based on banking naming conventions
    if any(k in clean_domain for k in ["api", "gateway", "rest", "grpc"]):
        return BankingAsset(
            id=asset_id,
            name=f"Banking API Gateway ({clean_domain})",
            asset_type=BankingAssetType.API_GATEWAY,
            system_type=BankingAssetType.API_GATEWAY,
            description="External Financial API Gateway exposing transactional endpoints to partners/apps.",
            criticality=AssetCriticality.HIGH,
            data_sensitivity=DataSensitivity.CONFIDENTIAL,
            exposure=AssetExposure.INTERNET,
            data_lifetime=DataLifetime.LONG,
            trust_zone=TrustZone.DMZ,
            tags=["banking", "api", "fintech", "gateway"]
        )
    elif any(k in clean_domain for k in ["pay", "checkout", "card", "swift", "transfer"]):
        return BankingAsset(
            id=asset_id,
            name=f"Payment Gateway / Service ({clean_domain})",
            asset_type=BankingAssetType.PAYMENT_SERVICE,
            system_type=BankingAssetType.PAYMENT_GATEWAY,
            description="Core payment processing interface handling cardholder and fund transfer payloads.",
            criticality=AssetCriticality.CRITICAL,
            data_sensitivity=DataSensitivity.HIGHLY_SENSITIVE,
            exposure=AssetExposure.INTERNET,
            data_lifetime=DataLifetime.VERY_LONG,
            trust_zone=TrustZone.DMZ,
            tags=["banking", "payment", "pci-dss", "critical"]
        )
    elif any(k in clean_domain for k in ["ebanking", "online", "portal", "login", "auth", "secure"]):
        return BankingAsset(
            id=asset_id,
            name=f"Online Banking Portal ({clean_domain})",
            asset_type=BankingAssetType.WEB_BANKING,
            system_type=BankingAssetType.NET_BANKING_PORTAL,
            description="Customer-facing retail and commercial internet banking web application.",
            criticality=AssetCriticality.CRITICAL,
            data_sensitivity=DataSensitivity.CONFIDENTIAL,
            exposure=AssetExposure.INTERNET,
            data_lifetime=DataLifetime.VERY_LONG,
            trust_zone=TrustZone.DMZ,
            tags=["banking", "web-banking", "retail", "critical"]
        )
    else:
        return BankingAsset(
            id=asset_id,
            name=f"Public Financial Host ({clean_domain})",
            asset_type=BankingAssetType.PUBLIC_WEBSITE,
            system_type=BankingAssetType.PUBLIC_WEBSITE,
            description="Public-facing institution website and external TLS edge terminating user traffic.",
            criticality=AssetCriticality.MEDIUM,
            data_sensitivity=DataSensitivity.PUBLIC,
            exposure=AssetExposure.INTERNET,
            data_lifetime=DataLifetime.MEDIUM,
            trust_zone=TrustZone.PUBLIC,
            tags=["banking", "public-web", "marketing"]
        )

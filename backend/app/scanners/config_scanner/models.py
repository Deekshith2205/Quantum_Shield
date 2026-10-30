"""Models for Configuration Evidence and Cryptographic Inventory.
Enforces explicit provenance and the core invariant: NOT_OBSERVABLE != VULNERABLE.
"""

from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class EvidenceStatus(str, Enum):
    """Classification of how a cryptographic fact was ascertained."""
    OBSERVED = "OBSERVED"          # Explicitly present in configuration file
    INFERRED = "INFERRED"          # Logically derived from an observed configuration setting
    NOT_OBSERVABLE = "NOT_OBSERVABLE"  # Control is absent or unobservable; NEVER a vulnerability


class CryptoAgility(str, Enum):
    """Assessment of whether an algorithm/parameter is configurable or hardcoded."""
    CONFIGURABLE = "CONFIGURABLE"      # Multi-option list, dynamic variable, or explicit flag
    HARDCODED = "HARDCODED"            # Single fixed literal without substitution
    NOT_OBSERVABLE = "NOT_OBSERVABLE"  # Insufficient evidence to determine agility


class CryptoRole(str, Enum):
    """Functional role of the cryptographic mechanism in banking systems."""
    TRANSPORT_SECURITY = "TRANSPORT_SECURITY"
    BULK_ENCRYPTION = "BULK_ENCRYPTION"
    KEY_EXCHANGE = "KEY_EXCHANGE"
    KEY_WRAPPING = "KEY_WRAPPING"
    DIGITAL_SIGNATURE = "DIGITAL_SIGNATURE"
    CERTIFICATE_AUTHENTICATION = "CERTIFICATE_AUTHENTICATION"
    KEY_STORAGE = "KEY_STORAGE"
    HASH_FUNCTION = "HASH_FUNCTION"
    CERTIFICATE_VALIDATION = "CERTIFICATE_VALIDATION"
    KEY_ROTATION = "KEY_ROTATION"
    SYSTEM_METADATA = "SYSTEM_METADATA"


class ConfigObservation(BaseModel):
    """
    Provenance-aware record of a cryptographic observation from configuration.
    
    CRITICAL INVARIANT:
    If a configuration does not expose a property, it must be marked NOT_OBSERVABLE
    or recorded as an evidence gap. Never turn missing evidence into a vulnerability.
    """
    file: str = Field(..., description="Source configuration file path (relative or base)")
    line: Optional[int] = Field(default=None, description="1-indexed line number in source configuration")
    path: str = Field(..., description="Configuration key path (e.g., tls.cipher_suites)")
    value: Any = Field(..., description="Observed or sanitized value")
    role: CryptoRole = Field(..., description="Cryptographic or security role")
    algorithm: Optional[str] = Field(default=None, description="Normalized algorithm name if applicable")
    evidence_status: EvidenceStatus = Field(default=EvidenceStatus.OBSERVED, description="Provenance status")
    confidence: str = Field(default="HIGH", description="Confidence level: HIGH, MEDIUM, LOW")
    description: str = Field(default="", description="Detailed narrative of finding")
    crypto_agility: CryptoAgility = Field(default=CryptoAgility.NOT_OBSERVABLE, description="Crypto-agility classification")
    secret_redacted: bool = Field(default=False, description="True if value was redacted to prevent secret leakage")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Supplementary technical metadata")


class NormalizedCryptoAsset(BaseModel):
    """
    Normalized cryptographic asset suitable for CBOM conversion and inventory query.
    Answers: 'What cryptographic mechanisms exist in this banking system?'
    """
    asset_id: str = Field(..., description="Unique asset identifier within inventory")
    name: str = Field(..., description="Human-readable asset name")
    asset_type: str = Field(..., description="Asset type: algorithm, protocol, certificate, related-crypto-material, storage")
    algorithm: Optional[str] = Field(default=None, description="Normalized algorithm name")
    role: str = Field(..., description="Cryptographic role: BULK_ENCRYPTION, KEY_WRAPPING, etc.")
    key_size: Optional[int] = Field(default=None, description="Key size in bits")
    curve: Optional[str] = Field(default=None, description="Elliptic curve name if applicable")
    mode: Optional[str] = Field(default=None, description="Cipher mode: GCM, CBC, etc.")
    padding: Optional[str] = Field(default=None, description="Padding scheme: OAEP, PKCS1v15, PSS, etc.")
    protocol: Optional[str] = Field(default=None, description="Protocol name if applicable: TLS, SSH, IPsec")
    protocol_version: Optional[str] = Field(default=None, description="Protocol version: 1.2, 1.3, etc.")
    evidence_status: EvidenceStatus = Field(default=EvidenceStatus.OBSERVED, description="Evidence status")
    crypto_agility: CryptoAgility = Field(default=CryptoAgility.NOT_OBSERVABLE, description="Crypto-agility classification")
    source_file: str = Field(..., description="Source configuration file")
    source_line: Optional[int] = Field(default=None, description="Source line number")
    source_path: str = Field(..., description="Configuration path")
    description: str = Field(default="", description="Asset technical description")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Supplementary asset metadata")


class EvidenceGapRecord(BaseModel):
    """Explicit representation of an unobservable control in configuration."""
    control: str = Field(..., description="Control name: HSM_USAGE, KEY_ROTATION, KEY_WRAPPING, etc.")
    role: str = Field(..., description="Cryptographic role")
    description: str = Field(default="Control not observable in inspected configuration", description="Detail")
    evidence_status: EvidenceStatus = Field(default=EvidenceStatus.NOT_OBSERVABLE, description="NOT_OBSERVABLE")


class NormalizedCryptoInventory(BaseModel):
    """
    Normalized Cryptographic Inventory of a banking system.
    Strictly an inventory representation — does NOT perform risk scoring.
    """
    system_id: str = Field(..., description="Banking system unique identifier")
    system_name: str = Field(..., description="Banking system name")
    system_type: Optional[str] = Field(default=None, description="Banking system type: NET_BANKING_PORTAL, etc.")
    criticality: Optional[str] = Field(default=None, description="System criticality if declared")
    trust_zone: Optional[str] = Field(default=None, description="Banking trust zone if declared")
    exposure: Optional[str] = Field(default=None, description="Network exposure if declared")
    data_sensitivity: Optional[str] = Field(default=None, description="Data sensitivity level if declared")
    data_lifetime: Optional[str] = Field(default=None, description="Data retention / lifetime if declared")
    components: List[NormalizedCryptoAsset] = Field(default_factory=list, description="Extracted cryptographic assets")
    observations: List[ConfigObservation] = Field(default_factory=list, description="Underlying raw observations")
    evidence_gaps: List[EvidenceGapRecord] = Field(default_factory=list, description="Explicit unobservable controls")
    scan_metadata: Dict[str, Any] = Field(default_factory=dict, description="Metadata regarding the scan process")

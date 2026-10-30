"""CycloneDX 1.7-compatible Cryptographic Bill of Materials (CBOM) Models.
Conforms to the CycloneDX CBOM specification for cryptographic assets.

Key elements:
- Root: bomFormat, specVersion, serialNumber, version, metadata, components, dependencies
- Components: type="cryptographic-asset", bom-ref, name, cryptoProperties, properties
- cryptoProperties: assetType ("algorithm", "certificate", "protocol", "related-crypto-material")
- Provenance tracking via quantumshield properties.
- Secret-safe: never stores sensitive key material or credentials.
"""

from typing import Any, Dict, List, Optional, Literal
from pydantic import BaseModel, ConfigDict, Field


class CBOMProperty(BaseModel):
    """Generic name-value property for CycloneDX components and metadata."""
    name: str
    value: str

    model_config = ConfigDict(populate_by_name=True)


class CBOMTool(BaseModel):
    """Tool metadata describing the generator."""
    vendor: str = "QuantumShield"
    name: str = "ConfigScanner-CBOM"
    version: str = "1.0.0"

    model_config = ConfigDict(populate_by_name=True)


class CBOMRootComponent(BaseModel):
    """Root application component representing the audited banking system."""
    bom_ref: str = Field(..., alias="bom-ref")
    type: str = "application"
    name: str
    version: str = "1.0.0"
    description: Optional[str] = None
    properties: List[CBOMProperty] = Field(default_factory=list)

    model_config = ConfigDict(populate_by_name=True)


class CBOMMetadata(BaseModel):
    """Metadata block for the CycloneDX CBOM document."""
    timestamp: str
    tools: List[CBOMTool] = Field(default_factory=lambda: [CBOMTool()])
    component: Optional[CBOMRootComponent] = None
    properties: List[CBOMProperty] = Field(default_factory=list)

    model_config = ConfigDict(populate_by_name=True)


class AlgorithmProperties(BaseModel):
    """Detailed cryptographic properties for algorithm assets."""
    primitive: Optional[str] = Field(
        default=None,
        description="Cryptographic primitive (e.g. block-cipher, signature, kem, hash, mac, key-agree, ae)"
    )
    parameterSetIdentifier: Optional[str] = Field(default=None, description="Parameter set or key size (e.g. 256, 2048, 768)")
    curve: Optional[str] = Field(default=None, description="Elliptic curve identifier (e.g. secp256r1, X25519)")
    executionEnvironment: Optional[str] = Field(default=None, description="Execution environment: software-plain-ram, hardware-hsm")
    implementationPlatform: Optional[str] = Field(default=None, description="Platform identifier")
    certificationLevel: Optional[str] = Field(default=None, description="Security certification (e.g. FIPS 140-3 L3)")
    mode: Optional[str] = Field(default=None, description="Cipher mode (e.g. gcm, cbc, ctr)")
    padding: Optional[str] = Field(default=None, description="Padding algorithm (e.g. oaep, pkcs1v15, pss)")
    cryptoFunctions: Optional[List[str]] = Field(default=None, description="Supported operations: encrypt, decrypt, sign, verify, kem")
    classicalSecurityLevel: Optional[int] = Field(default=None, description="Classical security strength in bits")
    nistQuantumSecurityLevel: Optional[int] = Field(default=None, description="NIST PQC Security Category: 0, 1, 3, 5")

    model_config = ConfigDict(populate_by_name=True)


class CertificateProperties(BaseModel):
    """Cryptographic properties for digital certificate assets."""
    subjectName: Optional[str] = Field(default=None, description="Subject Distinguished Name")
    issuerName: Optional[str] = Field(default=None, description="Issuer Distinguished Name")
    notValidBefore: Optional[str] = None
    notValidAfter: Optional[str] = None
    signatureAlgorithmRef: Optional[str] = Field(default=None, description="bom-ref to the signature algorithm component")
    subjectPublicKeyRef: Optional[str] = Field(default=None, description="bom-ref to the subject public key component")
    certificateFormat: Optional[str] = "X.509"

    model_config = ConfigDict(populate_by_name=True)


class ProtocolCipherSuite(BaseModel):
    """Cipher suite associated with a protocol."""
    name: str

    model_config = ConfigDict(populate_by_name=True)


class ProtocolProperties(BaseModel):
    """Cryptographic properties for secure network protocols."""
    type: Optional[str] = Field(default="tls", description="Protocol type: tls, ipsec, ssh")
    version: Optional[str] = Field(default=None, description="Protocol version: 1.2, 1.3")
    cipherSuites: Optional[List[ProtocolCipherSuite]] = Field(default=None, description="Negotiated or permitted cipher suites")
    ikeVersion: Optional[str] = None

    model_config = ConfigDict(populate_by_name=True)


class RelatedCryptoMaterialProperties(BaseModel):
    """Cryptographic properties for keys and key material (never raw secrets)."""
    type: Optional[str] = Field(default=None, description="Material type: public-key, private-key, secret-key")
    format: Optional[str] = Field(default=None, description="Format: pem, der, raw")
    size: Optional[int] = Field(default=None, description="Key length in bits")
    securedBy: Optional[Dict[str, Any]] = Field(default=None, description="Key protection mechanism (e.g. {'mechanism': 'hsm'})")

    model_config = ConfigDict(populate_by_name=True)


class CryptoProperties(BaseModel):
    """CycloneDX CBOM cryptoProperties block."""
    assetType: Literal["algorithm", "certificate", "protocol", "related-crypto-material"]
    algorithmProperties: Optional[AlgorithmProperties] = None
    certificateProperties: Optional[CertificateProperties] = None
    protocolProperties: Optional[ProtocolProperties] = None
    relatedCryptoMaterialProperties: Optional[RelatedCryptoMaterialProperties] = None
    oid: Optional[str] = None

    model_config = ConfigDict(populate_by_name=True)


class CBOMComponent(BaseModel):
    """
    Cryptographic component asset conforming to CycloneDX 1.7 CBOM.
    """
    type: Literal["cryptographic-asset"] = "cryptographic-asset"
    bom_ref: str = Field(..., alias="bom-ref")
    name: str
    description: Optional[str] = None
    cryptoProperties: CryptoProperties
    properties: List[CBOMProperty] = Field(default_factory=list)

    model_config = ConfigDict(populate_by_name=True)


class CBOMDependency(BaseModel):
    """Cryptographic component relationship dependency."""
    ref: str
    dependsOn: List[str] = Field(default_factory=list)

    model_config = ConfigDict(populate_by_name=True)


class CycloneDXDocument(BaseModel):
    """
    Full CycloneDX 1.7 Cryptographic Bill of Materials (CBOM) document.
    """
    bomFormat: Literal["CycloneDX"] = "CycloneDX"
    specVersion: str = "1.7"
    serialNumber: str
    version: int = 1
    metadata: CBOMMetadata
    components: List[CBOMComponent] = Field(default_factory=list)
    dependencies: List[CBOMDependency] = Field(default_factory=list)

    model_config = ConfigDict(populate_by_name=True)

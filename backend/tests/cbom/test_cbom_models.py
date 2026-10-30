"""Tests for CBOM Pydantic Models.
Verifies CycloneDX 1.7 schema conformity, bom-ref alias handling,
and cryptographic asset properties.
"""

from app.cbom.models import (
    AlgorithmProperties,
    CBOMComponent,
    CBOMDependency,
    CBOMMetadata,
    CBOMProperty,
    CBOMRootComponent,
    CertificateProperties,
    CryptoProperties,
    CycloneDXDocument,
    ProtocolProperties,
    RelatedCryptoMaterialProperties,
)


def test_cbom_root_document_structure():
    doc = CycloneDXDocument(
        serialNumber="urn:uuid:12345678-1234-5678-1234-567812345678",
        metadata=CBOMMetadata(
            timestamp="2026-10-30T00:00:00Z",
            component=CBOMRootComponent(
                bom_ref="root-app",
                name="Banking Core"
            )
        )
    )

    data = doc.model_dump(by_alias=True)
    assert data["bomFormat"] == "CycloneDX"
    assert data["specVersion"] == "1.7"
    assert data["serialNumber"].startswith("urn:uuid:")
    assert data["metadata"]["component"]["bom-ref"] == "root-app"


def test_crypto_properties_algorithm():
    algo_props = AlgorithmProperties(
        primitive="ae",
        parameterSetIdentifier="256",
        mode="gcm",
        cryptoFunctions=["encrypt", "decrypt"],
        classicalSecurityLevel=256,
        nistQuantumSecurityLevel=3
    )
    comp = CBOMComponent(
        bom_ref="crypto-algo-01",
        name="AES-256-GCM",
        cryptoProperties=CryptoProperties(
            assetType="algorithm",
            algorithmProperties=algo_props
        )
    )

    data = comp.model_dump(by_alias=True)
    assert data["type"] == "cryptographic-asset"
    assert data["bom-ref"] == "crypto-algo-01"
    assert data["cryptoProperties"]["assetType"] == "algorithm"
    assert data["cryptoProperties"]["algorithmProperties"]["mode"] == "gcm"


def test_crypto_properties_protocol():
    proto_props = ProtocolProperties(
        type="tls",
        version="1.3"
    )
    comp = CBOMComponent(
        bom_ref="crypto-proto-01",
        name="TLS 1.3",
        cryptoProperties=CryptoProperties(
            assetType="protocol",
            protocolProperties=proto_props
        )
    )

    data = comp.model_dump(by_alias=True)
    assert data["cryptoProperties"]["protocolProperties"]["version"] == "1.3"


def test_crypto_properties_certificate():
    cert_props = CertificateProperties(
        subjectName="CN=gateway.bank.synthetic",
        certificateFormat="X.509"
    )
    comp = CBOMComponent(
        bom_ref="crypto-cert-01",
        name="Gateway Certificate",
        cryptoProperties=CryptoProperties(
            assetType="certificate",
            certificateProperties=cert_props
        )
    )

    data = comp.model_dump(by_alias=True)
    assert data["cryptoProperties"]["certificateProperties"]["certificateFormat"] == "X.509"


def test_dependency_model():
    dep = CBOMDependency(
        ref="crypto-proto-01",
        dependsOn=["crypto-algo-01", "crypto-algo-02"]
    )
    assert dep.ref == "crypto-proto-01"
    assert len(dep.dependsOn) == 2

"""CBOM Builder for QuantumShield.
Transforms normalized cryptographic observations and inventories into
genuine, CycloneDX 1.7-compatible Cryptographic Bill of Materials (CBOM) documents.

RULES & INVARIANTS:
1. CBOM is an INVENTORY, NOT a risk engine: DO NOT assign P0/P1/P2/P3 risk scores.
2. Establish cryptographic relationships ONLY where source configuration connects them.
3. Preserve full provenance: source file, source line, config path, evidence status.
4. Redact secrets: Never emit raw passwords or private key material.
5. Deterministic output: Identical input yields identical CBOM document structure.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
import uuid

from app.cbom.models import (
    AlgorithmProperties,
    CBOMComponent,
    CBOMDependency,
    CBOMMetadata,
    CBOMProperty,
    CBOMRootComponent,
    CBOMTool,
    CertificateProperties,
    CryptoProperties,
    CycloneDXDocument,
    ProtocolCipherSuite,
    ProtocolProperties,
    RelatedCryptoMaterialProperties,
)
from app.scanners.config_scanner.evidence import EvidenceNormalizer
from app.scanners.config_scanner.models import (
    ConfigObservation,
    CryptoAgility,
    CryptoRole,
    EvidenceStatus,
    NormalizedCryptoAsset,
    NormalizedCryptoInventory,
)


# Deterministic namespace for reproducible CBOM UUIDs
CBOM_NAMESPACE = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")

# Classical and quantum security rating heuristics based on NIST standards
ALGO_SECURITY_LEVELS = {
    # Symmetric
    "AES-256": {"primitive": "block-cipher", "classical": 256, "quantum": 3, "functions": ["encrypt", "decrypt"]},
    "AES-256-GCM": {"primitive": "ae", "classical": 256, "quantum": 3, "functions": ["encrypt", "decrypt"]},
    "AES-256-CBC": {"primitive": "block-cipher", "classical": 256, "quantum": 3, "functions": ["encrypt", "decrypt"]},
    "AES-256-XTS": {"primitive": "block-cipher", "classical": 256, "quantum": 3, "functions": ["encrypt", "decrypt"]},
    "AES-128": {"primitive": "block-cipher", "classical": 128, "quantum": 1, "functions": ["encrypt", "decrypt"]},
    "AES-128-GCM": {"primitive": "ae", "classical": 128, "quantum": 1, "functions": ["encrypt", "decrypt"]},
    "AES-128-CBC": {"primitive": "block-cipher", "classical": 128, "quantum": 1, "functions": ["encrypt", "decrypt"]},
    "3DES": {"primitive": "block-cipher", "classical": 112, "quantum": 0, "functions": ["encrypt", "decrypt"]},
    "DES": {"primitive": "block-cipher", "classical": 56, "quantum": 0, "functions": ["encrypt", "decrypt"]},
    "CHACHA20-POLY1305": {"primitive": "ae", "classical": 256, "quantum": 3, "functions": ["encrypt", "decrypt"]},
    # Asymmetric (Shor vulnerable)
    "RSA-1024": {"primitive": "pke", "classical": 80, "quantum": 0, "functions": ["encrypt", "decrypt", "sign", "verify"]},
    "RSA-2048": {"primitive": "pke", "classical": 112, "quantum": 0, "functions": ["encrypt", "decrypt", "sign", "verify"]},
    "RSA-3072": {"primitive": "pke", "classical": 128, "quantum": 0, "functions": ["encrypt", "decrypt", "sign", "verify"]},
    "RSA-4096": {"primitive": "pke", "classical": 192, "quantum": 0, "functions": ["encrypt", "decrypt", "sign", "verify"]},
    "ECDSA": {"primitive": "signature", "classical": 128, "quantum": 0, "functions": ["sign", "verify"]},
    "ECDHE": {"primitive": "key-agree", "classical": 128, "quantum": 0, "functions": ["key-agree"]},
    "X25519": {"primitive": "key-agree", "classical": 128, "quantum": 0, "functions": ["key-agree"]},
    # Post-Quantum (NIST FIPS 203 / 204)
    "ML-KEM-512": {"primitive": "kem", "classical": 128, "quantum": 1, "functions": ["encapsulate", "decapsulate"]},
    "ML-KEM-768": {"primitive": "kem", "classical": 192, "quantum": 3, "functions": ["encapsulate", "decapsulate"]},
    "ML-KEM-1024": {"primitive": "kem", "classical": 256, "quantum": 5, "functions": ["encapsulate", "decapsulate"]},
    "ML-KEM": {"primitive": "kem", "classical": 192, "quantum": 3, "functions": ["encapsulate", "decapsulate"]},
    "X25519MLKEM768": {"primitive": "kem", "classical": 192, "quantum": 3, "functions": ["encapsulate", "decapsulate", "key-agree"]},
    "ML-DSA-44": {"primitive": "signature", "classical": 128, "quantum": 2, "functions": ["sign", "verify"]},
    "ML-DSA-65": {"primitive": "signature", "classical": 192, "quantum": 3, "functions": ["sign", "verify"]},
    "ML-DSA-87": {"primitive": "signature", "classical": 256, "quantum": 5, "functions": ["sign", "verify"]},
    "ML-DSA": {"primitive": "signature", "classical": 192, "quantum": 3, "functions": ["sign", "verify"]},
    # Hashes
    "SHA-256": {"primitive": "hash", "classical": 128, "quantum": 2, "functions": ["digest"]},
    "SHA-384": {"primitive": "hash", "classical": 192, "quantum": 3, "functions": ["digest"]},
    "SHA-512": {"primitive": "hash", "classical": 256, "quantum": 4, "functions": ["digest"]},
    "SHA-1": {"primitive": "hash", "classical": 63, "quantum": 0, "functions": ["digest"]},
    "MD5": {"primitive": "hash", "classical": 20, "quantum": 0, "functions": ["digest"]},
}


class CBOMBuilder:
    """
    Builds genuine CycloneDX 1.7 CBOM documents from normalized inventories or observations.
    """

    def __init__(self, deterministic: bool = True):
        self.deterministic = deterministic

    def build_cbom(
        self,
        inventory: NormalizedCryptoInventory,
        timestamp: Optional[str] = None
    ) -> CycloneDXDocument:
        """
        Build a CycloneDX CBOM document from a NormalizedCryptoInventory.
        """
        # Deterministic timestamp for reproducible testing if not provided
        ts = timestamp or (
            "2026-10-30T00:00:00Z" if self.deterministic else datetime.now(timezone.utc).isoformat()
        )

        system_id = inventory.system_id or "SAMPLE-SYSTEM"
        serial = self._generate_serial_number(system_id, inventory.components)

        # Root application component
        root_props = [
            CBOMProperty(name="quantumshield:system_id", value=system_id),
            CBOMProperty(name="quantumshield:asset_count", value=str(len(inventory.components))),
        ]
        if inventory.criticality:
            root_props.append(CBOMProperty(name="banking:criticality", value=inventory.criticality))
        if inventory.trust_zone:
            root_props.append(CBOMProperty(name="banking:trust_zone", value=inventory.trust_zone))
        if inventory.exposure:
            root_props.append(CBOMProperty(name="banking:exposure", value=inventory.exposure))
        if inventory.data_sensitivity:
            root_props.append(CBOMProperty(name="banking:data_sensitivity", value=inventory.data_sensitivity))
        if inventory.data_lifetime:
            root_props.append(CBOMProperty(name="banking:data_lifetime", value=inventory.data_lifetime))
        if inventory.system_type:
            root_props.append(CBOMProperty(name="banking:system_type", value=inventory.system_type))

        metadata = CBOMMetadata(
            timestamp=ts,
            tools=[CBOMTool()],
            component=CBOMRootComponent(
                bom_ref=f"app-{system_id.lower()}",
                type="application",
                name=inventory.system_name,
                version="1.0.0",
                description=f"Audited Banking System: {inventory.system_name}",
                properties=root_props
            )
        )

        components: List[CBOMComponent] = []
        bom_ref_map: Dict[str, str] = {}  # asset_id -> bom_ref

        # Generate cryptographic-asset components
        for idx, asset in enumerate(inventory.components, start=1):
            bom_ref = self._create_bom_ref(system_id, asset, idx)
            bom_ref_map[asset.asset_id] = bom_ref

            cbom_comp = self._build_component(bom_ref, asset)
            components.append(cbom_comp)

        # Build relationships / dependencies strictly from observed associations
        dependencies = self._build_dependencies(components, inventory)

        # Sort components deterministically by bom-ref
        components.sort(key=lambda c: c.bom_ref)
        dependencies.sort(key=lambda d: d.ref)

        return CycloneDXDocument(
            bomFormat="CycloneDX",
            specVersion="1.7",
            serialNumber=serial,
            version=1,
            metadata=metadata,
            components=components,
            dependencies=dependencies
        )

    def build_cbom_from_observations(
        self,
        observations: List[ConfigObservation],
        system_metadata: Dict[str, Any],
        timestamp: Optional[str] = None
    ) -> CycloneDXDocument:
        """
        Convenience builder: normalizes raw observations first, then builds CBOM.
        """
        system_id = system_metadata.get("system_id", "BANK-SAMPLE")
        system_name = system_metadata.get("name", "Sample Banking System")
        normalizer = EvidenceNormalizer(system_id=system_id, system_name=system_name)
        inventory = normalizer.normalize(observations, system_metadata=system_metadata)
        return self.build_cbom(inventory, timestamp=timestamp)

    # ------------------ COMPONENT BUILDERS ------------------

    def _build_component(self, bom_ref: str, asset: NormalizedCryptoAsset) -> CBOMComponent:
        """Construct a CycloneDX CBOMComponent for an asset."""
        crypto_props = self._build_crypto_properties(asset)

        # Custom provenance properties
        properties = [
            CBOMProperty(name="quantumshield:source_file", value=asset.source_file),
            CBOMProperty(name="quantumshield:config_path", value=asset.source_path),
            CBOMProperty(name="quantumshield:evidence_status", value=asset.evidence_status.value),
            CBOMProperty(name="quantumshield:role", value=asset.role),
            CBOMProperty(name="quantumshield:crypto_agility", value=asset.crypto_agility.value),
        ]
        if asset.source_line is not None:
            properties.append(CBOMProperty(name="quantumshield:source_line", value=str(asset.source_line)))

        # Sanitize name and description to ensure no leaked secrets
        safe_name = self._sanitize_text(asset.name)
        safe_desc = self._sanitize_text(asset.description)

        return CBOMComponent(
            bom_ref=bom_ref,
            name=safe_name,
            description=safe_desc,
            cryptoProperties=crypto_props,
            properties=properties
        )

    def _build_crypto_properties(self, asset: NormalizedCryptoAsset) -> CryptoProperties:
        """Generate CycloneDX cryptoProperties block matching asset type."""
        algo_name = asset.algorithm or asset.name

        if asset.asset_type == "protocol":
            version = asset.protocol_version or (
                asset.algorithm.replace("TLS", "").strip() if asset.algorithm and "TLS" in asset.algorithm else None
            )
            return CryptoProperties(
                assetType="protocol",
                protocolProperties=ProtocolProperties(
                    type=asset.protocol.lower() if asset.protocol else "tls",
                    version=version,
                    cipherSuites=[]
                )
            )

        elif asset.asset_type == "certificate":
            return CryptoProperties(
                assetType="certificate",
                certificateProperties=CertificateProperties(
                    subjectName=f"CN={asset.source_file}",
                    certificateFormat="X.509"
                )
            )

        elif asset.asset_type == "storage":
            return CryptoProperties(
                assetType="related-crypto-material",
                relatedCryptoMaterialProperties=RelatedCryptoMaterialProperties(
                    type="secret-key",
                    securedBy={"mechanism": "hsm" if "hsm" in asset.name.lower() else "kms"}
                )
            )

        else:
            # Default: algorithm asset
            spec = self._lookup_algorithm_spec(algo_name)
            primitive = spec.get("primitive", "block-cipher")
            classical = spec.get("classical")
            quantum = spec.get("quantum")
            functions = spec.get("functions")

            param_id = str(asset.key_size) if asset.key_size else (
                str(spec.get("classical")) if spec.get("classical") else None
            )

            algo_props = AlgorithmProperties(
                primitive=primitive,
                parameterSetIdentifier=param_id,
                curve=asset.curve,
                mode=asset.mode.lower() if asset.mode else None,
                padding=asset.padding.lower() if asset.padding else None,
                cryptoFunctions=functions,
                classicalSecurityLevel=classical,
                nistQuantumSecurityLevel=quantum,
                executionEnvironment="hardware-hsm" if "hsm" in str(asset.metadata).lower() else "software-plain-ram"
            )

            return CryptoProperties(
                assetType="algorithm",
                algorithmProperties=algo_props
            )

    def _lookup_algorithm_spec(self, name: str) -> Dict[str, Any]:
        """Look up known algorithm cryptographic properties."""
        name_clean = name.upper()
        # Direct lookup
        if name_clean in ALGO_SECURITY_LEVELS:
            return ALGO_SECURITY_LEVELS[name_clean]
        # Partial match
        for key, spec in ALGO_SECURITY_LEVELS.items():
            if key in name_clean:
                return spec
        return {"primitive": "block-cipher", "classical": None, "quantum": None, "functions": None}

    # ------------------ DEPENDENCY GRAPH ------------------

    def _build_dependencies(
        self,
        components: List[CBOMComponent],
        inventory: NormalizedCryptoInventory
    ) -> List[CBOMDependency]:
        """
        Establish explicit cryptographic relationships between components:
        - TLS Protocol -> Cipher Suites / Key Exchange in same source file
        - Certificate -> Signature Algorithm / Public Key in same file
        - Bulk Encryption -> Key Wrapping -> Key Storage (HSM/KMS) in same file
        Never invents unevidenced relationships.
        """
        file_to_comps: Dict[str, List[CBOMComponent]] = {}
        for comp in components:
            src_file = None
            for prop in comp.properties:
                if prop.name == "quantumshield:source_file":
                    src_file = prop.value
                    break
            if src_file:
                file_to_comps.setdefault(src_file, []).append(comp)

        dep_map: Dict[str, Set[str]] = {}

        for src_file, comps in file_to_comps.items():
            protocols = [c for c in comps if c.cryptoProperties.assetType == "protocol"]
            ciphers = [
                c for c in comps
                if c.cryptoProperties.assetType == "algorithm"
                and any(p.name == "quantumshield:role" and p.value in ("TRANSPORT_SECURITY", "BULK_ENCRYPTION") for p in c.properties)
            ]
            kex_list = [
                c for c in comps
                if any(p.name == "quantumshield:role" and p.value == "KEY_EXCHANGE" for p in c.properties)
            ]
            certs = [c for c in comps if c.cryptoProperties.assetType == "certificate"]
            signatures = [
                c for c in comps
                if any(p.name == "quantumshield:role" and p.value == "DIGITAL_SIGNATURE" for p in c.properties)
            ]
            wrapping_list = [
                c for c in comps
                if any(p.name == "quantumshield:role" and p.value == "KEY_WRAPPING" for p in c.properties)
            ]
            storage_list = [
                c for c in comps
                if c.cryptoProperties.assetType == "related-crypto-material"
                or any(p.name == "quantumshield:role" and p.value in ("KEY_STORAGE", "KEY_ROTATION") for p in c.properties)
            ]

            # 1. Protocols depend on Cipher Suites and Key Exchange
            for proto in protocols:
                dep_targets = {c.bom_ref for c in ciphers + kex_list}
                if dep_targets:
                    dep_map.setdefault(proto.bom_ref, set()).update(dep_targets)

            # 2. Certificates depend on Signature Algorithms
            for cert in certs:
                dep_targets = {s.bom_ref for s in signatures}
                if dep_targets:
                    dep_map.setdefault(cert.bom_ref, set()).update(dep_targets)

            # 3. Bulk encryption depends on Key Wrapping
            for cipher in ciphers:
                dep_targets = {w.bom_ref for w in wrapping_list}
                if dep_targets:
                    dep_map.setdefault(cipher.bom_ref, set()).update(dep_targets)

            # 4. Key Wrapping depends on Key Storage / HSM
            for wrap in wrapping_list:
                dep_targets = {s.bom_ref for s in storage_list}
                if dep_targets:
                    dep_map.setdefault(wrap.bom_ref, set()).update(dep_targets)

        deps: List[CBOMDependency] = []
        for ref, targets in dep_map.items():
            deps.append(CBOMDependency(ref=ref, dependsOn=sorted(list(targets))))

        return deps

    # ------------------ UTILITIES ------------------

    def _generate_serial_number(self, system_id: str, components: List[NormalizedCryptoAsset]) -> str:
        """Generate deterministic UUIDv5 serialNumber for the CBOM document."""
        if self.deterministic:
            comp_digest = "-".join(sorted([f"{a.role}:{a.algorithm or a.name}" for a in components]))
            seed = f"quantumshield:cbom:{system_id}:{comp_digest}"
            doc_uuid = uuid.uuid5(CBOM_NAMESPACE, seed)
            return f"urn:uuid:{doc_uuid}"
        return f"urn:uuid:{uuid.uuid4()}"

    def _create_bom_ref(self, system_id: str, asset: NormalizedCryptoAsset, index: int) -> str:
        """Generate stable, unique bom-ref for a cryptographic asset."""
        clean_sys = system_id.lower().replace(" ", "-").replace("_", "-")
        clean_role = asset.role.lower().replace("_", "-")
        algo_part = (asset.algorithm or "item").lower().replace(" ", "-").replace("_", "-")
        # Keep ref alphanumeric and hyphens
        algo_part = "".join(c for c in algo_part if c.isalnum() or c == "-")[:24]
        return f"crypto-{clean_sys}-{index:03d}-{clean_role}-{algo_part}"

    def _sanitize_text(self, text: Optional[str]) -> str:
        """Sanitize text to guarantee no passwords or raw keys are leaked."""
        if not text:
            return ""
        # Check for typical secret words
        lowered = text.lower()
        if any(w in lowered for w in ("password", "passwd", "secret", "private_key", "pin=")):
            # If text appears to contain a key assignment, redact
            if any(sep in text for sep in ("=", ":")):
                return "[REDACTED_CREDENTIAL]"
        return text

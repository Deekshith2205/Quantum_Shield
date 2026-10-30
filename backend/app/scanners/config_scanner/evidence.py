"""Evidence management and normalization for configuration scanner.
Translates raw ConfigObservation items into normalized inventory assets,
maintains evidence status (OBSERVED, INFERRED, NOT_OBSERVABLE), and records
explicit banking evidence gaps without turning missing data into vulnerabilities.
"""

from typing import Dict, List, Optional, Set, Any
from app.scanners.config_scanner.models import (
    ConfigObservation,
    CryptoAgility,
    CryptoRole,
    EvidenceGapRecord,
    EvidenceStatus,
    NormalizedCryptoAsset,
    NormalizedCryptoInventory,
)


# Standard banking security controls checked for observability
STANDARD_BANKING_CONTROLS = [
    ("HSM_USAGE", "KEY_STORAGE", "Hardware Security Module integration not observable in inspected files"),
    ("KEY_ROTATION", "KEY_ROTATION", "Automated cryptographic key rotation schedule not declared"),
    ("KEY_WRAPPING", "KEY_WRAPPING", "Key Encrypting Key (KEK) wrapping hierarchy not observable"),
    ("INTERNAL_MTLS", "TRANSPORT_SECURITY", "Mutual TLS / internal peer certificate enforcement not observable"),
    ("CRYPTO_AGILITY", "SYSTEM_METADATA", "Algorithm migration agility parameter not observable"),
]


class EvidenceNormalizer:
    """
    Normalizes configuration observations into structured inventory components
    and identifies explicit unobservable gaps.
    """

    def __init__(self, system_id: str, system_name: str):
        self.system_id = system_id
        self.system_name = system_name

    def normalize(
        self,
        observations: List[ConfigObservation],
        system_metadata: Optional[Dict[str, Any]] = None
    ) -> NormalizedCryptoInventory:
        """
        Normalize observations into a NormalizedCryptoInventory.
        Deterministic sorting applied to assets and observations.
        """
        metadata = system_metadata or {}
        components: List[NormalizedCryptoAsset] = []
        observed_roles: Set[CryptoRole] = set()

        # Deduplicate and normalize assets from observations
        asset_counter = 0
        seen_keys: Set[str] = set()

        for obs in observations:
            observed_roles.add(obs.role)
            # Skip pure system metadata or pure secret redactions from asset list
            if obs.role == CryptoRole.SYSTEM_METADATA:
                continue

            asset_type = self._determine_asset_type(obs)
            asset_key = f"{obs.role.value}:{obs.algorithm or obs.value}:{obs.file}"
            if asset_key in seen_keys:
                continue
            seen_keys.add(asset_key)

            asset_counter += 1
            asset_id = f"asset-{self.system_id.lower()}-{asset_counter:03d}"
            name = self._generate_asset_name(obs)

            # Extract key size, curve, mode from observation metadata
            key_size = obs.metadata.get("key_size")
            curve = obs.metadata.get("curve")
            mode = obs.metadata.get("mode") or self._extract_mode(obs.algorithm or str(obs.value))
            padding = obs.metadata.get("padding")

            asset = NormalizedCryptoAsset(
                asset_id=asset_id,
                name=name,
                asset_type=asset_type,
                algorithm=obs.algorithm,
                role=obs.role.value,
                key_size=key_size,
                curve=curve,
                mode=mode,
                padding=padding,
                protocol=obs.metadata.get("protocol"),
                protocol_version=obs.metadata.get("version"),
                evidence_status=obs.evidence_status,
                crypto_agility=obs.crypto_agility,
                source_file=obs.file,
                source_line=obs.line,
                source_path=obs.path,
                description=obs.description,
                metadata=obs.metadata
            )
            components.append(asset)

        # Sort components deterministically by role, algorithm, source_file, line
        components.sort(key=lambda a: (a.role, str(a.algorithm), a.source_file, a.source_line or 0))

        # Build explicit evidence gaps
        evidence_gaps = self._build_evidence_gaps(observed_roles, observations)

        return NormalizedCryptoInventory(
            system_id=metadata.get("system_id", self.system_id),
            system_name=metadata.get("name", self.system_name),
            system_type=metadata.get("system_type"),
            criticality=metadata.get("criticality"),
            trust_zone=metadata.get("trust_zone"),
            exposure=metadata.get("exposure"),
            data_sensitivity=metadata.get("data_sensitivity"),
            data_lifetime=metadata.get("data_lifetime"),
            components=components,
            observations=observations,
            evidence_gaps=evidence_gaps,
            scan_metadata={
                "total_observations": len(observations),
                "total_assets": len(components),
                "total_gaps": len(evidence_gaps)
            }
        )

    def _determine_asset_type(self, obs: ConfigObservation) -> str:
        """Map ConfigObservation role to asset type."""
        if obs.role == CryptoRole.TRANSPORT_SECURITY and obs.metadata.get("protocol") == "TLS":
            return "protocol"
        elif obs.role == CryptoRole.CERTIFICATE_AUTHENTICATION:
            return "certificate"
        elif obs.role in (CryptoRole.KEY_STORAGE, CryptoRole.KEY_ROTATION):
            return "storage"
        elif obs.role == CryptoRole.KEY_WRAPPING:
            return "algorithm"
        return "algorithm"

    def _generate_asset_name(self, obs: ConfigObservation) -> str:
        """Generate human-readable name for component asset."""
        if obs.algorithm:
            return f"{obs.algorithm} ({obs.role.value})"
        elif obs.role == CryptoRole.CERTIFICATE_AUTHENTICATION:
            return f"Certificate ({obs.value})"
        elif obs.role == CryptoRole.KEY_STORAGE:
            return f"Key Facility ({obs.value})"
        return f"{obs.role.value} Asset ({obs.value})"

    def _extract_mode(self, text: str) -> Optional[str]:
        """Extract cipher mode if present."""
        text_upper = text.upper()
        for mode in ("GCM", "CBC", "CTR", "XTS", "POLY1305", "CFB", "OFB", "ECB"):
            if mode in text_upper:
                return mode
        return None

    def _build_evidence_gaps(
        self,
        observed_roles: Set[CryptoRole],
        observations: List[ConfigObservation]
    ) -> List[EvidenceGapRecord]:
        """
        Identify unobservable controls to satisfy the invariant:
        NOT_OBSERVABLE != VULNERABLE.
        """
        gaps: List[EvidenceGapRecord] = []

        # Check HSM usage
        has_hsm = any(
            obs.role == CryptoRole.KEY_STORAGE and ("hsm" in str(obs.value).lower() or "kms" in str(obs.value).lower())
            for obs in observations
        )
        if not has_hsm:
            gaps.append(
                EvidenceGapRecord(
                    control="HSM_USAGE",
                    role="KEY_STORAGE",
                    description="HSM or Cloud KMS hardware backing not observable in configuration",
                    evidence_status=EvidenceStatus.NOT_OBSERVABLE
                )
            )

        # Check key rotation
        has_rotation = any(obs.role == CryptoRole.KEY_ROTATION for obs in observations)
        if not has_rotation:
            gaps.append(
                EvidenceGapRecord(
                    control="KEY_ROTATION",
                    role="KEY_ROTATION",
                    description="Key rotation policy or automated schedule not observable in configuration",
                    evidence_status=EvidenceStatus.NOT_OBSERVABLE
                )
            )

        # Check key wrapping
        has_wrapping = any(obs.role == CryptoRole.KEY_WRAPPING for obs in observations)
        if not has_wrapping:
            gaps.append(
                EvidenceGapRecord(
                    control="KEY_WRAPPING",
                    role="KEY_WRAPPING",
                    description="Key wrapping hierarchy / KEK not observable in configuration",
                    evidence_status=EvidenceStatus.NOT_OBSERVABLE
                )
            )

        return gaps

"""Validators for CycloneDX 1.7 Cryptographic Bill of Materials (CBOM).
Enforces structural conformity, referential integrity, and absence of leaked secrets.
"""

from dataclasses import dataclass, field
import re
from typing import Any, Dict, List, Set, Union

from app.cbom.models import CycloneDXDocument


SECRET_LEAKAGE_REGEX = re.compile(
    r"(-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH)?\s*PRIVATE\s+KEY-----|password\s*[:=]|secret\s*[:=]|api_key\s*[:=])",
    re.IGNORECASE
)


@dataclass
class ValidationReport:
    """Report detailing CBOM document validation outcome."""
    is_valid: bool
    issues: List[str] = field(default_factory=list)
    component_count: int = 0
    dependency_count: int = 0


class CBOMValidator:
    """
    Validates CycloneDX CBOM documents against specification requirements.
    """

    ALLOWED_SPEC_VERSIONS = {"1.6", "1.7"}
    ALLOWED_ASSET_TYPES = {"algorithm", "certificate", "protocol", "related-crypto-material"}

    def validate(self, document: Union[CycloneDXDocument, Dict[str, Any]]) -> ValidationReport:
        """
        Validate CycloneDX document or raw dictionary.
        Returns a ValidationReport.
        """
        issues: List[str] = []

        if isinstance(document, CycloneDXDocument):
            data = document.model_dump(by_alias=True, exclude_none=True)
        elif isinstance(document, dict):
            data = document
        else:
            return ValidationReport(is_valid=False, issues=["Document must be CycloneDXDocument or dict"])

        # 1. Root structure checks
        if data.get("bomFormat") != "CycloneDX":
            issues.append(f"Invalid bomFormat: expected 'CycloneDX', got '{data.get('bomFormat')}'")

        spec_ver = str(data.get("specVersion"))
        if spec_ver not in self.ALLOWED_SPEC_VERSIONS:
            issues.append(f"Unsupported specVersion '{spec_ver}'. Expected one of {self.ALLOWED_SPEC_VERSIONS}")

        serial = str(data.get("serialNumber", ""))
        if not serial.startswith("urn:uuid:"):
            issues.append(f"Invalid serialNumber '{serial}': must start with 'urn:uuid:'")

        version = data.get("version")
        if not isinstance(version, int) or version < 1:
            issues.append(f"Invalid document version '{version}': must be integer >= 1")

        # 2. Metadata checks
        metadata = data.get("metadata", {})
        if not metadata.get("timestamp"):
            issues.append("Missing metadata.timestamp")

        # 3. Component checks
        components = data.get("components", [])
        if not isinstance(components, list):
            issues.append("components must be a list")
            components = []

        known_refs: Set[str] = set()

        for idx, comp in enumerate(components):
            if not isinstance(comp, dict):
                issues.append(f"Component at index {idx} is not a dictionary")
                continue

            comp_type = comp.get("type")
            if comp_type != "cryptographic-asset":
                issues.append(f"Component '{comp.get('name')}' has invalid type '{comp_type}': expected 'cryptographic-asset'")

            bom_ref = comp.get("bom-ref")
            if not bom_ref:
                issues.append(f"Component at index {idx} missing required 'bom-ref'")
            elif bom_ref in known_refs:
                issues.append(f"Duplicate bom-ref '{bom_ref}' found at component index {idx}")
            else:
                known_refs.add(bom_ref)

            crypto_props = comp.get("cryptoProperties")
            if not crypto_props or not isinstance(crypto_props, dict):
                issues.append(f"Component '{bom_ref}' missing valid cryptoProperties")
            else:
                asset_type = crypto_props.get("assetType")
                if asset_type not in self.ALLOWED_ASSET_TYPES:
                    issues.append(f"Component '{bom_ref}' has unsupported assetType '{asset_type}'")

        # 4. Dependency referential integrity
        dependencies = data.get("dependencies", [])
        for dep in dependencies:
            if not isinstance(dep, dict):
                continue
            parent_ref = dep.get("ref")
            if parent_ref and parent_ref not in known_refs:
                issues.append(f"Dependency parent ref '{parent_ref}' does not exist in components")
            for target_ref in dep.get("dependsOn", []):
                if target_ref not in known_refs:
                    issues.append(f"Dependency target ref '{target_ref}' (from '{parent_ref}') does not exist in components")

        # 5. Secret Leakage Check
        doc_str = str(data)
        if SECRET_LEAKAGE_REGEX.search(doc_str):
            issues.append("CRITICAL: Secret leakage detected in CBOM content (unredacted password or private key)")

        return ValidationReport(
            is_valid=(len(issues) == 0),
            issues=issues,
            component_count=len(components),
            dependency_count=len(dependencies)
        )

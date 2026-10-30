"""CBOM Serializer for QuantumShield.
Produces deterministic, CycloneDX 1.7-compliant JSON representations.
"""

import json
from typing import Any, Dict
from app.cbom.models import CycloneDXDocument


class CBOMSerializer:
    """
    Serializes CycloneDX CBOM documents to JSON and dictionary formats.
    Ensures bom-ref field name aliasing and deterministic key sorting.
    """

    def __init__(self, sort_keys: bool = True, indent: int = 2):
        self.sort_keys = sort_keys
        self.indent = indent

    def to_dict(self, document: CycloneDXDocument) -> Dict[str, Any]:
        """
        Convert CycloneDXDocument to standard dictionary using CycloneDX aliases (e.g. bom-ref).
        Excludes None fields for cleaner CycloneDX output.
        """
        return document.model_dump(by_alias=True, exclude_none=True)

    def to_json(self, document: CycloneDXDocument) -> str:
        """
        Serialize CycloneDXDocument to deterministic JSON string.
        """
        data = self.to_dict(document)
        return json.dumps(
            data,
            indent=self.indent,
            sort_keys=self.sort_keys,
            ensure_ascii=False
        )

    def serialize(self, document: CycloneDXDocument) -> str:
        """Alias for to_json."""
        return self.to_json(document)

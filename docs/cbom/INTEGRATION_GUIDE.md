# QuantumShield Integration Guide: Config Scanner & CBOM

This document defines the integration interface for **Engineer 1** to incorporate the Configuration Scanner and CBOM module into QuantumShield's Banking Risk Engine, What-If Simulator, and FastAPI routes without modifying underlying scanner invariants.

---

## 1. Module Imports

```python
from app.scanners.config_scanner import (
    BankingConfigScanner,
    NormalizedCryptoInventory,
    ConfigObservation,
    CryptoRole,
    EvidenceStatus,
    CryptoAgility,
)
from app.cbom import (
    CBOMBuilder,
    CBOMSerializer,
    CBOMValidator,
    CycloneDXDocument,
)
```

---

## 2. Scanning Configurations

### Scan a Banking System Directory
```python
scanner = BankingConfigScanner(root_dir=Path("backend/sample_data/banking"))
inventory: NormalizedCryptoInventory = scanner.scan_directory(
    dir_path=Path("backend/sample_data/banking/core_banking")
)

# Access extracted system metadata
print(inventory.system_id)        # e.g. "SAMPLE-BANK-CORE-04"
print(inventory.criticality)      # e.g. "CRITICAL"
print(inventory.trust_zone)       # e.g. "DATA"
print(inventory.exposure)         # e.g. "RESTRICTED"

# Access normalized crypto components
for asset in inventory.components:
    print(asset.name, asset.role, asset.algorithm, asset.evidence_status)

# Access unobservable controls
for gap in inventory.evidence_gaps:
    print(gap.control, gap.evidence_status)  # NOT_OBSERVABLE
```

### Scan All Sample Banking Environments
```python
all_inventories = scanner.scan_all_banking_samples(Path("backend/sample_data/banking"))
for system_key, inv in all_inventories.items():
    print(system_key, inv.system_id, len(inv.components))
```

---

## 3. Generating and Serializing CBOM

```python
builder = CBOMBuilder(deterministic=True)
serializer = CBOMSerializer(sort_keys=True, indent=2)

# Generate CycloneDX 1.7 CBOM
cbom_doc: CycloneDXDocument = builder.build_cbom(inventory)

# Serialize to JSON string or Dict
cbom_json: str = serializer.to_json(cbom_doc)
cbom_dict: dict = serializer.to_dict(cbom_doc)

# Validate CBOM
validator = CBOMValidator()
report = validator.validate(cbom_doc)
assert report.is_valid
```

---

## 4. Bridging CBOM to Banking Risk Engine

Engineer 1 can map `NormalizedCryptoInventory.components` to existing `BankingAsset` or `KeyProtectionChain`:

```python
from app.models.banking import KeyProtectionChain, CryptoConfiguration

# Extract data encryption and key wrapping from inventory
data_enc = next((c.algorithm for c in inventory.components if c.role == "BULK_ENCRYPTION"), None)
key_wrap = next((c.algorithm for c in inventory.components if c.role == "KEY_WRAPPING"), None)
key_stor = next((c.name for c in inventory.components if c.role == "KEY_STORAGE"), None)

chain = KeyProtectionChain(
    data_encryption=data_enc,
    key_wrapping=key_wrap,
    key_storage=key_stor,
)
```

---

## 5. Suggested FastAPI Route Additions (For Engineer 1)

```python
@router.get("/banking/systems/{system_id}/cbom", response_model=dict)
def get_banking_cbom(system_id: str):
    """Retrieve CycloneDX 1.7 CBOM for a sample banking system."""
    ...
```

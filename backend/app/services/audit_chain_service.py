"""Audit Hash Chain Service.
Implements tamper-evident cryptographic history for assessments and reports.
Uses SHA-256 over RFC 8785 compliant canonical JSON representations.
"""

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Union
from app.models.audit_chain import AuditRecord, AuditVerificationResult

GENESIS_PREVIOUS_HASH: str = "0" * 64


def canonicalize_json(data: Any) -> str:
    """
    Produces deterministic, RFC 8785 canonical JSON serialization:
    - Sorts dictionary keys lexicographically
    - Uses compact formatting (no indentation, no extra whitespace after ':' or ',')
    - Handles nested dictionaries, lists, and primitives consistently
    """
    if hasattr(data, "model_dump"):
        data = data.model_dump(mode="json")
    elif hasattr(data, "dict"):
        data = data.dict()

    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    )


def compute_sha256(data_str: str) -> str:
    """Computes SHA-256 hexadecimal digest of UTF-8 encoded string."""
    return hashlib.sha256(data_str.encode("utf-8")).hexdigest()


class AuditChainService:
    """Manages creation, storage, and cryptographic verification of tamper-evident audit records."""

    def __init__(self):
        self._ledger: List[AuditRecord] = []

    def get_latest_hash(self) -> str:
        """Returns the current_hash of the latest record or GENESIS_PREVIOUS_HASH."""
        if not self._ledger:
            return GENESIS_PREVIOUS_HASH
        return self._ledger[-1].current_hash

    def create_audit_record(
        self,
        assessment_data: Any,
        assessment_id: str,
        previous_hash: Optional[str] = None,
        store: bool = True,
    ) -> AuditRecord:
        """
        Creates a new tamper-evident audit record:
        1. canonical_json = canonicalize_json(assessment_data)
        2. assessment_hash = SHA256(canonical_json)
        3. current_hash = SHA256(canonical_json + previous_hash)
        """
        canonical = canonicalize_json(assessment_data)
        a_hash = compute_sha256(canonical)

        prev = previous_hash if previous_hash is not None else self.get_latest_hash()
        c_hash = compute_sha256(canonical + prev)

        record = AuditRecord(
            record_id=str(uuid.uuid4()),
            assessment_id=assessment_id,
            assessment_hash=a_hash,
            previous_hash=prev,
            current_hash=c_hash,
            timestamp=datetime.now(timezone.utc).isoformat(),
            schema_version="1.0.0",
            canonical_payload=canonical,
        )

        if store:
            self._ledger.append(record)

        return record

    def verify_audit_record(
        self,
        record: AuditRecord,
        assessment_data: Optional[Any] = None,
    ) -> AuditVerificationResult:
        """
        Verifies the cryptographic integrity of a single audit record.
        Detects:
        - Payload tampering (assessment_hash mismatch)
        - Current hash mismatch
        """
        try:
            # Step 1: Verify canonical payload against assessment_data if provided
            if assessment_data is not None:
                recalculated_canonical = canonicalize_json(assessment_data)
                recalculated_a_hash = compute_sha256(recalculated_canonical)
                if recalculated_a_hash != record.assessment_hash:
                    return AuditVerificationResult(
                        valid=False,
                        record_id=record.record_id,
                        error=f"Assessment data tampering detected! Recalculated hash {recalculated_a_hash} != recorded hash {record.assessment_hash}",
                        details={"expected_hash": record.assessment_hash, "computed_hash": recalculated_a_hash},
                    )
            elif record.canonical_payload:
                recalculated_a_hash = compute_sha256(record.canonical_payload)
                if recalculated_a_hash != record.assessment_hash:
                    return AuditVerificationResult(
                        valid=False,
                        record_id=record.record_id,
                        error="Canonical payload does not match assessment_hash. Record modified in storage.",
                        details={"expected_hash": record.assessment_hash, "computed_hash": recalculated_a_hash},
                    )

            # Step 2: Verify current_hash = SHA256(canonical_payload + previous_hash)
            payload = record.canonical_payload or (canonicalize_json(assessment_data) if assessment_data is not None else "")
            recalculated_current = compute_sha256(payload + record.previous_hash)

            if recalculated_current != record.current_hash:
                return AuditVerificationResult(
                    valid=False,
                    record_id=record.record_id,
                    error=f"Cryptographic hash chain signature invalid! Recalculated current_hash {recalculated_current} != {record.current_hash}",
                    details={"expected_hash": record.current_hash, "computed_hash": recalculated_current},
                )

            return AuditVerificationResult(
                valid=True,
                record_id=record.record_id,
                records_checked=1,
                details={"assessment_hash": record.assessment_hash, "current_hash": record.current_hash},
            )
        except Exception as e:
            return AuditVerificationResult(
                valid=False,
                record_id=record.record_id,
                error=f"Malformed audit record: {str(e)}",
            )

    def verify_audit_chain(self, records: List[AuditRecord]) -> AuditVerificationResult:
        """
        Verifies an entire sequence of chained audit records.
        Verifies:
        1. Each record's internal hash integrity.
        2. Sequence continuity (record[i].previous_hash == record[i-1].current_hash).
        """
        if not records:
            return AuditVerificationResult(valid=True, records_checked=0, details={"message": "Empty chain is valid"})

        for i, rec in enumerate(records):
            # Verify internal record validity
            res = self.verify_audit_record(rec)
            if not res.valid:
                return AuditVerificationResult(
                    valid=False,
                    record_id=rec.record_id,
                    error=f"Record #{i} ({rec.record_id}) verification failed: {res.error}",
                    records_checked=i,
                )

            # Check chain continuity
            if i > 0:
                prev_rec = records[i - 1]
                if rec.previous_hash != prev_rec.current_hash:
                    return AuditVerificationResult(
                        valid=False,
                        record_id=rec.record_id,
                        error=f"Broken audit hash chain at index {i}! Record previous_hash {rec.previous_hash} != prior record current_hash {prev_rec.current_hash}",
                        records_checked=i,
                        details={"index": i, "expected_prev": prev_rec.current_hash, "actual_prev": rec.previous_hash},
                    )

        return AuditVerificationResult(
            valid=True,
            records_checked=len(records),
            details={
                "chain_length": len(records),
                "head_hash": records[-1].current_hash,
                "genesis_hash": records[0].previous_hash,
            },
        )

    def get_ledger(self) -> List[AuditRecord]:
        """Returns the in-memory audit ledger."""
        return list(self._ledger)


# Default singleton instance
DEFAULT_AUDIT_CHAIN_SERVICE = AuditChainService()

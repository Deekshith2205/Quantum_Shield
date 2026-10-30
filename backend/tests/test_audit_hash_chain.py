"""Integration tests for Audit Hash Chain & Verifiable Integrity."""

import pytest
import json
from app.services.audit_chain_service import (
    AuditChainService,
    canonicalize_json,
    compute_sha256,
    GENESIS_PREVIOUS_HASH,
)
from app.models.audit_chain import AuditRecord


def test_canonicalize_json_dictionary_order_independence():
    """Canonical JSON must produce identical strings regardless of dict key insertion order."""
    d1 = {"z": 100, "a": "hello", "m": [3, 2, 1], "nested": {"b": True, "a": False}}
    d2 = {"a": "hello", "nested": {"a": False, "b": True}, "z": 100, "m": [3, 2, 1]}

    c1 = canonicalize_json(d1)
    c2 = canonicalize_json(d2)

    assert c1 == c2
    assert " " not in c1.replace('"hello"', "")  # compact delimiters (no extra spaces)
    assert compute_sha256(c1) == compute_sha256(c2)


def test_create_and_verify_single_audit_record():
    """A freshly created audit record must cryptographically verify successfully."""
    svc = AuditChainService()
    assessment = {"system_id": "SYS-01", "risk_score": 85, "priority": "P0"}

    record = svc.create_audit_record(assessment, assessment_id="SYS-01")
    assert record.record_id
    assert record.assessment_hash
    assert record.previous_hash == GENESIS_PREVIOUS_HASH
    assert len(record.assessment_hash) == 64
    assert len(record.current_hash) == 64

    # Verify without explicit external payload
    res = svc.verify_audit_record(record)
    assert res.valid is True
    assert res.record_id == record.record_id

    # Verify with explicit assessment data
    res_ext = svc.verify_audit_record(record, assessment_data=assessment)
    assert res_ext.valid is True


def test_tampering_detection_modified_payload():
    """Altering the assessment payload must cause verification failure."""
    svc = AuditChainService()
    original_assessment = {"system_id": "SYS-01", "risk_score": 85, "priority": "P0"}
    record = svc.create_audit_record(original_assessment, assessment_id="SYS-01")

    # Attacker tries to pass tampered assessment (lower risk score)
    tampered_assessment = {"system_id": "SYS-01", "risk_score": 20, "priority": "P3"}
    res = svc.verify_audit_record(record, assessment_data=tampered_assessment)

    assert res.valid is False
    assert "tampering detected" in res.error.lower()


def test_tampering_detection_modified_hash():
    """Modifying the assessment_hash or current_hash in the record must fail verification."""
    svc = AuditChainService()
    assessment = {"system_id": "SYS-01", "score": 90}
    record = svc.create_audit_record(assessment, assessment_id="SYS-01")

    # Attacker modifies stored hash
    corrupted_record = record.model_copy(update={"assessment_hash": "a" * 64})
    res = svc.verify_audit_record(corrupted_record)

    assert res.valid is False
    assert "modified in storage" in res.error.lower() or "invalid" in res.error.lower()


def test_verify_multi_record_audit_chain():
    """A series of sequentially linked audit records must verify as a valid chain."""
    svc = AuditChainService()
    r1 = svc.create_audit_record({"scan": 1, "target": "bank-a"}, assessment_id="SYS-A")
    r2 = svc.create_audit_record({"scan": 2, "target": "bank-b"}, assessment_id="SYS-B")
    r3 = svc.create_audit_record({"scan": 3, "target": "bank-c"}, assessment_id="SYS-C")

    assert r2.previous_hash == r1.current_hash
    assert r3.previous_hash == r2.current_hash

    chain = [r1, r2, r3]
    res = svc.verify_audit_chain(chain)
    assert res.valid is True
    assert res.records_checked == 3


def test_detect_broken_chain_link():
    """If an intermediate record is swapped, omitted, or modified, verify_audit_chain must fail."""
    svc = AuditChainService()
    r1 = svc.create_audit_record({"scan": 1}, assessment_id="SYS-1")
    r2 = svc.create_audit_record({"scan": 2}, assessment_id="SYS-2")
    r3 = svc.create_audit_record({"scan": 3}, assessment_id="SYS-3")

    # Break link between r1 and r2
    tampered_r2 = r2.model_copy(update={"previous_hash": "b" * 64})
    broken_chain = [r1, tampered_r2, r3]

    res = svc.verify_audit_chain(broken_chain)
    assert res.valid is False
    assert "broken audit hash chain" in res.error.lower() or "invalid" in res.error.lower()

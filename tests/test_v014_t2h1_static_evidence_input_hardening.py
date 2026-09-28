from __future__ import annotations

import pytest

from sentinel import beta14_lab_evidence_importer as b143
from sentinel import beta14_t2_static_real_sample_evidence as b147


def _record(index: int = 1) -> dict:
    return b147._fixture(
        index,
        result=b147.RESULT_DETECTED,
        category=b147.CATEGORY_TROJAN,
    )


@pytest.mark.parametrize(
    "bad",
    [float("nan"), float("inf"), float("-inf"), 10**5000, True],
    ids=["nan", "pos-inf", "neg-inf", "huge-int", "bool"],
)
def test_t2_latency_pathological_values_fail_closed(bad):
    record = _record()
    record["detection_latency_ms"] = bad
    failures = b147.validate_record(record)
    assert "b147:detection_latency_invalid" in failures


@pytest.mark.parametrize(
    ("field", "bad", "failure"),
    [
        ("malware_category", [], "b147:malware_category_invalid"),
        ("malware_category", {}, "b147:malware_category_invalid"),
        ("authorization_class", [], "b147:authorization_class_invalid"),
        ("scan_mode", [], "b147:scan_mode_invalid"),
        ("result", {}, "b147:result_invalid"),
        ("detection_layer", [], "b147:detection_layer_invalid"),
    ],
    ids=[
        "category-list",
        "category-dict",
        "auth-list",
        "scan-list",
        "result-dict",
        "layer-list",
    ],
)
def test_t2_unhashable_enum_values_fail_closed(field, bad, failure):
    record = _record()
    record[field] = bad
    assert failure in b147.validate_record(record)


@pytest.mark.parametrize(
    "bad",
    [
        "checkpoint/" + ("x" * 300),
        "checkpoint/good\nforged",
        "checkpoint/good\rforged",
        "checkpoint/good\x00forged",
        [],
    ],
    ids=["oversized", "newline", "carriage-return", "nul", "list"],
)
def test_t2_checkpoint_identity_is_bounded_and_single_line(bad):
    record = _record()
    record["engine_checkpoint"] = bad
    assert "b147:engine_checkpoint_invalid" in b147.validate_record(record)


def test_t2_batch_keeps_original_index_for_malformed_record():
    first = _record(1)
    third = _record(3)
    report = b147.summarize_batch((first, None, third))
    assert report["passed"] is False
    assert report["sample_count"] == 3
    assert report["accepted_count"] == 2
    assert "record[1]:b147:not_object" in report["failures"]


def test_t2_batch_all_malformed_records_are_not_reported_as_empty():
    report = b147.summarize_batch((None, [], "raw"))
    assert report["passed"] is False
    assert report["sample_count"] == 3
    assert report["accepted_count"] == 0
    assert "b147:batch_empty" not in report["failures"]
    assert "record[0]:b147:not_object" in report["failures"]
    assert "record[1]:b147:not_object" in report["failures"]
    assert "record[2]:b147:not_object" in report["failures"]


def test_t2_bridge_rejects_non_mapping_without_conversion_crash():
    with pytest.raises(ValueError, match="b147:not_object"):
        b147.to_b143_record(None)  # type: ignore[arg-type]


def test_b143_import_batch_keeps_original_index_and_count():
    valid = b147.to_b143_record(_record(1))
    report = b143.import_batch((valid, None))
    assert report["passed"] is False
    assert report["record_count"] == 2
    assert report["accepted_count"] == 1
    assert "record[1]:b143:not_object" in report["failures"]


@pytest.mark.parametrize(
    "bad",
    [
        "checkpoint/" + ("x" * 300),
        "checkpoint/good\nforged",
        "checkpoint/good\x00forged",
    ],
    ids=["oversized", "newline", "nul"],
)
def test_b143_checkpoint_identity_is_bounded(bad):
    record = b147.to_b143_record(_record())
    record["engine_checkpoint"] = bad
    assert "b143:engine_checkpoint_invalid" in b143.validate_record(record)


def test_valid_t2_record_still_bridges_authoritatively():
    record = _record()
    assert b147.validate_record(record) == ()
    bridged = b147.to_b143_record(record)
    assert b143.validate_record(bridged) == ()
    report = b143.import_batch((bridged,))
    assert report["passed"] is True
    assert report["accepted_count"] == 1
    assert report["authoritative_count"] == 1
    assert report["sample_bytes_imported"] is False

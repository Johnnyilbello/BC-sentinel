from __future__ import annotations

from sentinel import beta14_t2_static_real_sample_evidence as b147


def _record(index: int = 1, *, result: str = b147.RESULT_DETECTED, category: str = b147.CATEGORY_TROJAN) -> dict:
    return b147._fixture(index, result=result, category=category)


def test_b147_binds_exact_b146_checkpoint() -> None:
    report = b147.self_check()
    assert report["passed"] is True
    assert report["source_checkpoint"] == "checkpoint/v014-b146-pass"
    assert report["source_checkpoint_commit"] == "98a702e178e8ef07da2c25751efcf5d1a7c2006f"


def test_b147_accepts_authorized_static_real_sample_metadata() -> None:
    record = _record()
    assert b147.validate_record(record) == ()
    bridged = b147.to_b143_record(record)
    assert bridged["sample_kind"] == "MALWARE"
    assert bridged["environment_classification"] == "STATIC_QUARANTINE_ONLY"
    assert bridged["real_sample_executed"] is False
    assert bridged["network_mode"] == "NONE"


def test_b147_rejects_any_real_sample_execution() -> None:
    record = _record()
    record["real_sample_executed"] = True
    assert "b147:sample_execution_forbidden" in b147.validate_record(record)


def test_b147_rejects_networked_t2_scan() -> None:
    record = _record()
    record["network_mode"] = "INETSIM"
    assert "b147:network_must_be_none" in b147.validate_record(record)


def test_b147_requires_authorized_research_or_vendor_lab_source() -> None:
    record = _record()
    record["authorization_class"] = "INTERNAL_SAFE_ARTIFACT"
    assert "b147:authorization_class_invalid" in b147.validate_record(record)

    record = _record()
    record["sample_authorized"] = False
    assert "b147:sample_authorization_required" in b147.validate_record(record)


def test_b147_requires_static_quarantine_environment() -> None:
    record = _record()
    record["environment_classification"] = "ISOLATED_DISPOSABLE_LAB"
    assert "b147:static_environment_required" in b147.validate_record(record)


def test_b147_rejects_raw_and_sensitive_exports() -> None:
    for field in (
        "raw_sample_bytes_exported",
        "raw_paths_exported",
        "command_lines_exported",
        "usernames_exported",
        "credentials_exported",
        "file_contents_exported",
    ):
        record = _record()
        record[field] = True
        assert f"b147:{field}_forbidden" in b147.validate_record(record)


def test_b147_detected_record_requires_detection_layer() -> None:
    record = _record(result=b147.RESULT_DETECTED)
    record["detection_layer"] = "NONE"
    assert "b147:detection_layer_required" in b147.validate_record(record)


def test_b147_miss_and_error_must_not_fake_detection_layer() -> None:
    for result in (b147.RESULT_MISSED, b147.RESULT_ERROR):
        record = _record(result=result)
        record["detection_layer"] = "STATIC"
        assert "b147:non_detection_layer_must_be_none" in b147.validate_record(record)


def test_b147_batch_reports_detected_missed_error_without_hiding_misses() -> None:
    records = (
        _record(1, result=b147.RESULT_DETECTED, category=b147.CATEGORY_RANSOMWARE),
        _record(2, result=b147.RESULT_DETECTED, category=b147.CATEGORY_TROJAN),
        _record(3, result=b147.RESULT_MISSED, category=b147.CATEGORY_INFOSTEALER),
        _record(4, result=b147.RESULT_ERROR, category=b147.CATEGORY_SCRIPT_MACRO),
    )
    report = b147.summarize_batch(records)
    assert report["passed"] is True
    assert report["result_counts"][b147.RESULT_DETECTED] == 2
    assert report["result_counts"][b147.RESULT_MISSED] == 1
    assert report["result_counts"][b147.RESULT_ERROR] == 1
    assert report["static_detection_rate"] == 2 / 3


def test_b147_batch_rejects_duplicate_sample_hashes() -> None:
    first = _record(1)
    second = _record(2)
    second["sample_sha256"] = first["sample_sha256"]
    report = b147.summarize_batch((first, second))
    assert report["passed"] is False
    assert any("duplicate_sample_sha256" in item for item in report["failures"])


def test_b147_batch_rejects_duplicate_run_ids() -> None:
    first = _record(1)
    second = _record(2)
    second["run_id"] = first["run_id"]
    report = b147.summarize_batch((first, second))
    assert report["passed"] is False
    assert any("duplicate_run_id" in item for item in report["failures"])


def test_b147_bridge_routes_every_valid_record_through_b143() -> None:
    records = (
        _record(1),
        _record(2, category=b147.CATEGORY_RANSOMWARE),
        _record(3, result=b147.RESULT_MISSED, category=b147.CATEGORY_INFOSTEALER),
    )
    report = b147.summarize_batch(records)
    assert report["b143_import_passed"] is True
    assert report["b143_import_accepted_count"] == 3
    assert report["b143_import_authoritative_count"] == 3


def test_b147_no_sample_handling_capability_and_no_coverage_promotion() -> None:
    report = b147.self_check()
    assert report["sample_download_capability"] is False
    assert report["sample_storage_capability"] is False
    assert report["sample_transfer_capability"] is False
    assert report["sample_unpack_capability"] is False
    assert report["real_sample_executed"] is False
    assert report["network_io"] is False
    assert report["raw_sample_bytes_imported"] is False
    assert report["coverage_promoted"] is False
    assert report["authority_expanded"] is False
    assert report["independent_certification_claimed"] is False


def test_b147_preserves_canonical_coverage() -> None:
    report = b147.self_check()
    assert report["source_coverage"] == {"PARTIAL": 4, "GAP": 0, "VERIFIED": 7}


def test_b147_contract_is_deterministic() -> None:
    first = b147.self_check()
    second = b147.self_check()
    assert first["passed"] is True
    assert first["deterministic_contract"] is True
    assert first["contract_digest"] == second["contract_digest"]

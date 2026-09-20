from __future__ import annotations

from sentinel import beta14_t3_isolated_dynamic_evidence as b148


def _record(index: int = 1, *, result: str = b148.RESULT_DETECTED, category: str = b148.CATEGORY_TROJAN) -> dict:
    return b148._fixture(index, result=result, category=category)


def test_b148_binds_exact_b147_checkpoint() -> None:
    report = b148.self_check()
    assert report["passed"] is True
    assert report["source_checkpoint"] == "checkpoint/v014-b147-pass"
    assert report["source_checkpoint_commit"] == "4b4bcb4d11ee1ac6847f1dba3a353f6976c959b2"


def test_b148_accepts_authorized_isolated_dynamic_metadata() -> None:
    record = _record()
    assert b148.validate_record(record) == ()
    bridged = b148.to_b143_record(record)
    assert bridged["sample_kind"] == "MALWARE"
    assert bridged["environment_classification"] == "ISOLATED_DISPOSABLE_LAB"
    assert bridged["real_sample_executed"] is True
    assert bridged["network_mode"] in {"NONE", "FAKE_SERVICES", "INETSIM"}


def test_b148_requires_real_sample_execution_in_isolated_lab() -> None:
    record = _record()
    record["real_sample_executed"] = False
    assert "b148:real_sample_execution_required" in b148.validate_record(record)

    record = _record()
    record["environment_classification"] = "STATIC_QUARANTINE_ONLY"
    assert "b148:isolated_environment_required" in b148.validate_record(record)


def test_b148_rejects_direct_internet_observation() -> None:
    record = _record()
    record["direct_internet_observed"] = True
    assert "b148:direct_internet_forbidden" in b148.validate_record(record)


def test_b148_accepts_only_none_fake_or_inetsim_network_modes() -> None:
    for mode in ("NONE", "FAKE_SERVICES", "INETSIM"):
        record = _record()
        record["network_mode"] = mode
        assert b148.validate_record(record) == ()

    record = _record()
    record["network_mode"] = "DIRECT_INTERNET"
    assert "b148:network_mode_invalid" in b148.validate_record(record)


def test_b148_requires_snapshot_revert_and_one_sample_cycle() -> None:
    record = _record()
    record["snapshot_revert_confirmed"] = False
    assert "b148:snapshot_revert_required" in b148.validate_record(record)

    record = _record()
    record["one_sample_cycle_confirmed"] = False
    assert "b148:one_sample_cycle_required" in b148.validate_record(record)


def test_b148_rejects_escape_propagation_or_real_data_contact() -> None:
    for field in (
        "propagation_beyond_guest",
        "host_escape_observed",
        "real_user_data_touched",
        "host_credentials_exposed",
        "credential_material_exported",
        "security_control_impairment_succeeded",
    ):
        record = _record()
        record[field] = True
        assert f"b148:{field}_forbidden" in b148.validate_record(record)


def test_b148_rejects_raw_and_sensitive_exports() -> None:
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
        assert f"b148:{field}_forbidden" in b148.validate_record(record)


def test_b148_detected_or_blocked_requires_primary_detection_layer() -> None:
    for result in (b148.RESULT_BLOCKED, b148.RESULT_DETECTED, b148.RESULT_REVIEW):
        record = _record(result=result)
        record["primary_detection_layer"] = "NONE"
        assert "b148:detection_layer_required" in b148.validate_record(record)


def test_b148_miss_or_error_must_not_fake_detection_layer() -> None:
    for result in (b148.RESULT_MISSED, b148.RESULT_ERROR):
        record = _record(result=result)
        record["primary_detection_layer"] = "BEHAVIOR"
        assert "b148:non_detection_layer_must_be_none" in b148.validate_record(record)


def test_b148_batch_reports_blocked_detected_review_missed_error() -> None:
    records = (
        _record(1, result=b148.RESULT_BLOCKED, category=b148.CATEGORY_RANSOMWARE),
        _record(2, result=b148.RESULT_DETECTED, category=b148.CATEGORY_TROJAN),
        _record(3, result=b148.RESULT_REVIEW, category=b148.CATEGORY_BACKDOOR),
        _record(4, result=b148.RESULT_MISSED, category=b148.CATEGORY_INFOSTEALER),
        _record(5, result=b148.RESULT_ERROR, category=b148.CATEGORY_SCRIPT_MACRO),
    )
    report = b148.summarize_batch(records)
    assert report["passed"] is True
    assert report["result_counts"][b148.RESULT_BLOCKED] == 1
    assert report["result_counts"][b148.RESULT_DETECTED] == 1
    assert report["result_counts"][b148.RESULT_REVIEW] == 1
    assert report["result_counts"][b148.RESULT_MISSED] == 1
    assert report["result_counts"][b148.RESULT_ERROR] == 1
    assert report["dynamic_protection_rate"] == 2 / 3


def test_b148_batch_counts_behavior_and_network_metadata() -> None:
    records = (
        _record(1, result=b148.RESULT_BLOCKED, category=b148.CATEGORY_RANSOMWARE),
        _record(2, result=b148.RESULT_DETECTED, category=b148.CATEGORY_TROJAN),
    )
    report = b148.summarize_batch(records)
    assert report["behavior_counts"][b148.BEHAVIOR_RANSOMWARE] == 1
    assert report["behavior_counts"][b148.BEHAVIOR_PROCESS_TREE] == 1
    assert report["network_mode_counts"]["INETSIM"] == 2


def test_b148_batch_rejects_duplicate_hashes_and_run_ids() -> None:
    first = _record(1)
    second = _record(2)
    second["sample_sha256"] = first["sample_sha256"]
    report = b148.summarize_batch((first, second))
    assert report["passed"] is False
    assert any("duplicate_sample_sha256" in item for item in report["failures"])

    first = _record(1)
    second = _record(2)
    second["run_id"] = first["run_id"]
    report = b148.summarize_batch((first, second))
    assert report["passed"] is False
    assert any("duplicate_run_id" in item for item in report["failures"])


def test_b148_bridge_routes_valid_dynamic_records_through_b143() -> None:
    records = (
        _record(1),
        _record(2, result=b148.RESULT_BLOCKED, category=b148.CATEGORY_RANSOMWARE),
        _record(3, result=b148.RESULT_MISSED, category=b148.CATEGORY_INFOSTEALER),
    )
    report = b148.summarize_batch(records)
    assert report["b143_import_passed"] is True
    assert report["b143_import_accepted_count"] == 3
    assert report["b143_import_authoritative_count"] == 3


def test_b148_module_has_no_sample_or_route_authority() -> None:
    report = b148.self_check()
    assert report["sample_execution_capability_in_module"] is False
    assert report["sample_download_capability_in_module"] is False
    assert report["sample_storage_capability_in_module"] is False
    assert report["sample_transfer_capability_in_module"] is False
    assert report["sample_unpack_capability_in_module"] is False
    assert report["network_route_creation_capability_in_module"] is False


def test_b148_preserves_coverage_and_claim_boundaries() -> None:
    report = b148.self_check()
    assert report["source_coverage"] == {"PARTIAL": 4, "GAP": 0, "VERIFIED": 7}
    assert report["coverage_promoted"] is False
    assert report["authority_expanded"] is False
    assert report["independent_certification_claimed"] is False


def test_b148_contract_is_deterministic() -> None:
    first = b148.self_check()
    second = b148.self_check()
    assert first["passed"] is True
    assert first["deterministic_contract"] is True
    assert first["contract_digest"] == second["contract_digest"]

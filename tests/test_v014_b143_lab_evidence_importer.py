from __future__ import annotations

from sentinel import beta14_lab_evidence_importer as b143


def _dynamic_record() -> dict:
    return b143._fixture(
        run_id="test-dynamic-001",
        sample_id="malware-sample-001",
        sample_sha256="d" * 64,
        sample_kind=b143.SAMPLE_MALWARE,
        environment=b143.ENVIRONMENT_ISOLATED,
        result=b143.RESULT_DETECTED,
        layer="BEHAVIOR",
        real_sample_executed=True,
        authorization_class=b143.AUTH_APPROVED_RESEARCH,
    )


def test_b143_binds_exact_b142_checkpoint() -> None:
    report = b143.self_check()
    assert report["passed"] is True
    assert report["source_checkpoint"] == "checkpoint/v014-b142-pass"
    assert report["source_checkpoint_commit"] == "346f3d2ffb61db09437d82c3762991b3c25c45b7"


def test_b143_accepts_authorized_isolated_dynamic_evidence() -> None:
    record = _dynamic_record()
    assert b143.validate_record(record) == ()
    assert b143.authoritative_for_internal_lab(record) is True
    summary = b143.sanitized_summary(record)
    assert summary["passed"] is True
    assert summary["authoritative_internal_lab_evidence"] is True


def test_b143_rejects_direct_internet_mode() -> None:
    record = _dynamic_record()
    record["network_mode"] = "DIRECT_INTERNET"
    assert "b143:network_mode_invalid" in b143.validate_record(record)


def test_b143_rejects_dynamic_real_sample_outside_isolated_lab() -> None:
    record = _dynamic_record()
    record["environment_classification"] = b143.ENVIRONMENT_STATIC
    assert "b143:real_sample_requires_isolated_lab" in b143.validate_record(record)


def test_b143_rejects_unauthorized_sample() -> None:
    record = _dynamic_record()
    record["sample_authorized"] = False
    assert "b143:sample_authorization_required" in b143.validate_record(record)


def test_b143_rejects_missing_cleanup_revert() -> None:
    record = _dynamic_record()
    record["cleanup_revert_confirmed"] = False
    assert "b143:cleanup_revert_required" in b143.validate_record(record)


def test_b143_rejects_raw_sample_bytes_and_sensitive_exports() -> None:
    fields = (
        "raw_sample_bytes_included",
        "raw_paths_included",
        "command_lines_included",
        "usernames_included",
        "credentials_included",
        "file_contents_included",
    )
    for field in fields:
        record = _dynamic_record()
        record[field] = True
        failures = b143.validate_record(record)
        assert f"b143:{field}_forbidden" in failures


def test_b143_static_malware_miss_must_be_explicit() -> None:
    record = b143._fixture(
        run_id="test-static-001",
        sample_id="malware-static-001",
        sample_sha256="e" * 64,
        sample_kind=b143.SAMPLE_MALWARE,
        environment=b143.ENVIRONMENT_STATIC,
        result=b143.RESULT_CLEAN,
        layer="NONE",
        real_sample_executed=False,
        authorization_class=b143.AUTH_APPROVED_RESEARCH,
    )
    assert "b143:malware_static_clean_must_be_missed" in b143.validate_record(record)
    record["result"] = b143.RESULT_MISSED
    assert b143.validate_record(record) == ()


def test_b143_detection_requires_detection_layer() -> None:
    record = _dynamic_record()
    record["detection_layer"] = "NONE"
    assert "b143:detection_layer_required" in b143.validate_record(record)


def test_b143_miss_must_not_fake_detection_layer() -> None:
    record = _dynamic_record()
    record["result"] = b143.RESULT_MISSED
    record["detection_layer"] = "BEHAVIOR"
    assert "b143:non_detection_layer_must_be_none" in b143.validate_record(record)


def test_b143_batch_rejects_duplicate_run_ids() -> None:
    first = _dynamic_record()
    second = dict(first)
    second["sample_id"] = "malware-sample-002"
    second["sample_sha256"] = "f" * 64
    batch = b143.import_batch((first, second))
    assert batch["passed"] is False
    assert any("duplicate_run_id" in item for item in batch["failures"])


def test_b143_batch_never_imports_sample_bytes_or_promotes_coverage() -> None:
    record = _dynamic_record()
    batch = b143.import_batch((record,))
    assert batch["passed"] is True
    assert batch["sample_bytes_imported"] is False
    assert batch["coverage_promoted"] is False
    assert batch["authority_expanded"] is False


def test_b143_summary_is_privacy_minimal() -> None:
    summary = b143.sanitized_summary(_dynamic_record())
    forbidden = {
        "raw_sample_bytes_included",
        "raw_paths_included",
        "command_lines_included",
        "usernames_included",
        "credentials_included",
        "file_contents_included",
    }
    assert forbidden.isdisjoint(summary)
    assert summary["privacy_minimal"] is True


def test_b143_evidence_digest_is_stable_and_hash_bound() -> None:
    record = _dynamic_record()
    first = b143.evidence_digest(record)
    second = b143.evidence_digest(record)
    assert first == second
    changed = dict(record)
    changed["sample_sha256"] = "a" * 64
    assert b143.evidence_digest(changed) != first


def test_b143_importer_has_no_execution_storage_or_transfer_authority() -> None:
    report = b143.self_check()
    assert report["sample_execution_capability_in_importer"] is False
    assert report["sample_storage_capability_in_importer"] is False
    assert report["sample_transfer_capability_in_importer"] is False
    assert report["coverage_promoted"] is False
    assert report["authority_expanded"] is False


def test_b143_contract_is_deterministic() -> None:
    first = b143.self_check()
    second = b143.self_check()
    assert first["passed"] is True
    assert first["deterministic_contract"] is True
    assert first["contract_digest"] == second["contract_digest"]

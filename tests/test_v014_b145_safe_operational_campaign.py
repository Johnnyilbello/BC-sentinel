from __future__ import annotations

from sentinel import beta14_safe_operational_campaign as b145


def _campaign() -> dict:
    controls = [
        b145.make_control_result(
            control_id=spec["control_id"],
            evidence_digest=b145._digest({"evidence": spec["control_id"]}),
            source_summary_digest=b145._digest({"summary": spec["control_id"]}),
            source_summary_passed=True,
            cleanup_confirmed=True,
        )
        for spec in b145.CONTROL_SPECS
    ]
    return {
        "schema": b145.SCHEMA,
        "profile": b145.PROFILE,
        "source_checkpoint": b145.SOURCE_CHECKPOINT,
        "source_checkpoint_commit": b145.SOURCE_CHECKPOINT_COMMIT,
        "controls": controls,
        "boundaries": dict(b145.BOUNDARIES),
    }


def test_b145_binds_exact_b144_checkpoint() -> None:
    report = b145.self_check()
    assert report["passed"] is True
    assert report["source_checkpoint"] == "checkpoint/v014-b144-pass"
    assert report["source_checkpoint_commit"] == "bbaec9bfbe52c43483054185501239351781d29a"


def test_b145_has_five_live_controls_across_t0_t1() -> None:
    report = b145.summarize(_campaign())
    assert report["passed"] is True
    assert report["live_control_count"] == 5
    assert report["t0_control_count"] == 1
    assert report["t1_control_count"] == 4


def test_b145_expected_scenario_inventory() -> None:
    report = b145.summarize(_campaign())
    assert set(report["scenario_ids"]) == {
        "B12-SCRIPT-ABUSE-001",
        "B12-AUTOSTART-LINK-001",
        "B12-PROCESS-TREE-001",
        "B12-LOCAL-REPUTATION-001",
        "B7-RANSOMWARE-001",
    }


def test_b145_all_controls_bridge_through_b143() -> None:
    report = b145.summarize(_campaign())
    assert report["b143_import_passed"] is True
    assert report["b143_import_accepted_count"] == 5
    assert report["b143_import_authoritative_count"] == 5


def test_b145_failed_source_summary_is_rejected() -> None:
    campaign = _campaign()
    campaign["controls"][0]["source_summary_passed"] = False
    assert any("source_summary_failed" in item for item in b145.validate_campaign(campaign))


def test_b145_missing_cleanup_is_rejected() -> None:
    campaign = _campaign()
    campaign["controls"][1]["cleanup_confirmed"] = False
    assert any("cleanup_required" in item for item in b145.validate_campaign(campaign))


def test_b145_real_malware_flag_is_rejected() -> None:
    campaign = _campaign()
    campaign["controls"][2]["real_malware_executed"] = True
    assert any("real_malware_executed_forbidden" in item for item in b145.validate_campaign(campaign))


def test_b145_network_activity_is_rejected() -> None:
    campaign = _campaign()
    campaign["controls"][3]["network_io"] = True
    assert any("network_io_forbidden" in item for item in b145.validate_campaign(campaign))


def test_b145_campaign_preserves_privacy_and_authority_boundaries() -> None:
    report = b145.summarize(_campaign())
    assert report["real_malware_executed"] is False
    assert report["network_io"] is False
    assert report["credential_access"] is False
    assert report["real_persistence_mutation"] is False
    assert report["security_control_impairment"] is False
    assert report["user_file_access"] is False
    assert report["coverage_promoted"] is False
    assert report["authority_expanded"] is False


def test_b145_preserves_canonical_coverage() -> None:
    report = b145.summarize(_campaign())
    assert report["source_coverage"] == {"PARTIAL": 4, "GAP": 0, "VERIFIED": 7}
    assert report["coverage_promoted"] is False


def test_b145_import_records_are_test_artifacts_not_malware() -> None:
    records = b145.build_import_records(_campaign())
    assert len(records) == 5
    assert all(record["sample_kind"] == "TEST_ARTIFACT" for record in records)
    assert all(record["real_sample_executed"] is False for record in records)
    assert all(record["network_mode"] == "NONE" for record in records)


def test_b145_contract_is_deterministic() -> None:
    first = b145.self_check()
    second = b145.self_check()
    assert first["passed"] is True
    assert first["deterministic_contract"] is True
    assert first["contract_digest"] == second["contract_digest"]

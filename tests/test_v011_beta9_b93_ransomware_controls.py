from __future__ import annotations

import copy

import pytest

from sentinel import beta9_ransomware_controls as b93


def _control(control_id: str) -> dict:
    base = {
        "control_id": control_id,
        "live_observation": True,
        "sandbox_scope": "DEDICATED_TEMP_DIRECTORY",
        "observer_backend": "WATCHDOG_LOCAL_FILESYSTEM",
        "write_event_count": 24,
        "rename_event_count": 18,
        "entropy_delta": 0.91,
        "extension_changed": True,
        "canary_touched": False,
        "known_backup_workflow": False,
        "user_initiated_bulk_operation": False,
        "started_at_utc": "2026-09-16T12:00:00Z",
        "completed_at_utc": "2026-09-16T12:00:02Z",
        "cleanup_state": "CLEAN",
    }
    if control_id == "positive-ransomware-like":
        base["canary_touched"] = True
    elif control_id == "administrative-backup-like":
        base["known_backup_workflow"] = True
        base["user_initiated_bulk_operation"] = True
    elif control_id == "benign-save":
        base["write_event_count"] = 2
        base["rename_event_count"] = 0
        base["entropy_delta"] = 0.0
        base["extension_changed"] = False
    return base


def _valid() -> dict:
    return {
        "schema": b93.SCHEMA,
        "source": b93.SOURCE,
        "controls": [_control(control_id) for control_id in b93.CONTROL_IDS],
        "boundaries": dict(b93.BOUNDARIES),
    }


def test_valid_live_controls_promote_only_ransomware_scenario() -> None:
    result = b93.summarize(_valid())
    assert result["passed"] is True
    assert result["coverage_summary"] == {"PARTIAL": 5, "GAP": 0, "VERIFIED": 1}
    decisions = {item["scenario_id"]: item for item in result["coverage_decisions"]}
    assert decisions["B7-RANSOMWARE-001"]["status"] == "VERIFIED"
    assert all(
        decisions[scenario_id]["status"] == "PARTIAL"
        for scenario_id in b93.SCENARIOS
        if scenario_id != "B7-RANSOMWARE-001"
    )


def test_control_outcomes_cover_positive_admin_and_benign() -> None:
    result = b93.summarize(_valid())
    assert result["control_outcomes"] == {
        "positive-ransomware-like": "DETECTED",
        "administrative-backup-like": "REVIEW_REQUIRED",
        "benign-save": "NO_MATCH",
    }
    assert result["live_thresholds_met"] is True
    assert result["controlled_threat_detector_verification_performed"] is True


def test_positive_evidence_binds_detector_graph_and_incident() -> None:
    result = b93.summarize(_valid())
    assert result["detector_to_security_graph_bound"] is True
    assert result["security_graph_to_incident_bound"] is True
    assert result["positive_evidence_id"].startswith("b93-live-file:")
    assert len(result["graph_digest"]) == 64
    assert len(result["correlation_digest"]) == 64


def test_result_never_claims_broad_ransomware_protection_or_synthetic_fallback() -> None:
    result = b93.summarize(_valid())
    assert result["broad_ransomware_protection_claimed"] is False
    assert result["synthetic_fallback_used"] is False
    decision = next(item for item in result["coverage_decisions"] if item["scenario_id"] == "B7-RANSOMWARE-001")
    assert "Scenario-specific" in decision["limitation"]


def test_detector_module_is_the_accepted_ransomware_detector_path() -> None:
    result = b93.summarize(_valid())
    assert result["detector_module"] == "sentinel.ransomware_detector.detect"


def test_boundary_mutation_fails_closed() -> None:
    data = _valid()
    data["boundaries"]["user_file_access"] = True
    result = b93.summarize(data)
    assert result["passed"] is False
    assert "evidence:boundary_invalid" in result["failures"]


def test_unexpected_sensitive_field_is_rejected_without_echo() -> None:
    data = _valid()
    data["controls"][0]["absolute_path"] = "C:/private/example.txt"
    result = b93.summarize(data)
    assert result["passed"] is False
    serialized = repr(result)
    assert "C:/private/example.txt" not in serialized
    assert "absolute_path" not in serialized


def test_wrong_control_count_fails() -> None:
    data = _valid()
    data["controls"] = data["controls"][:2]
    assert "evidence:control_count_invalid" in b93.validate_evidence(data)


def test_control_order_or_identity_mismatch_fails() -> None:
    data = _valid()
    data["controls"][0]["control_id"] = "benign-save"
    failures = b93.validate_evidence(data)
    assert "control[0]:identity_invalid" in failures


def test_non_live_observation_fails() -> None:
    data = _valid()
    data["controls"][1]["live_observation"] = False
    assert "control[1]:live_observation_required" in b93.validate_evidence(data)


def test_wrong_sandbox_scope_fails() -> None:
    data = _valid()
    data["controls"][0]["sandbox_scope"] = "USER_DOCUMENTS"
    assert "control[0]:sandbox_scope_invalid" in b93.validate_evidence(data)


def test_wrong_observer_backend_fails() -> None:
    data = _valid()
    data["controls"][0]["observer_backend"] = "SYNTHETIC_FIXTURE"
    assert "control[0]:observer_backend_invalid" in b93.validate_evidence(data)


def test_invalid_counts_fail() -> None:
    data = _valid()
    data["controls"][0]["write_event_count"] = -1
    data["controls"][1]["rename_event_count"] = True
    failures = b93.validate_evidence(data)
    assert "control[0]:write_event_count_invalid" in failures
    assert "control[1]:rename_event_count_invalid" in failures


def test_entropy_range_is_bounded() -> None:
    data = _valid()
    data["controls"][0]["entropy_delta"] = 1.1
    assert "control[0]:entropy_delta_invalid" in b93.validate_evidence(data)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_entropy_fails_closed(value: float) -> None:
    data = _valid()
    data["controls"][0]["entropy_delta"] = value
    assert "control[0]:entropy_delta_invalid" in b93.validate_evidence(data)


def test_pathological_event_count_fails_without_serialization_crash() -> None:
    data = _valid()
    data["controls"][0]["write_event_count"] = 10**5000
    report = b93.summarize(data)
    assert report["passed"] is False
    assert "control[0]:write_event_count_invalid" in report["failures"]


def test_reversed_or_unbounded_time_fails() -> None:
    data = _valid()
    data["controls"][0]["completed_at_utc"] = "2026-09-16T11:59:59Z"
    data["controls"][1]["completed_at_utc"] = "2026-09-16T12:00:25Z"
    failures = b93.validate_evidence(data)
    assert "control[0]:time_window_invalid" in failures
    assert "control[1]:time_window_invalid" in failures


def test_cleanup_must_be_confirmed() -> None:
    data = _valid()
    data["controls"][2]["cleanup_state"] = "FAILED"
    assert "control[2]:cleanup_not_confirmed" in b93.validate_evidence(data)


def test_positive_control_cannot_carry_suppressors() -> None:
    data = _valid()
    data["controls"][0]["known_backup_workflow"] = True
    assert "positive:suppressor_not_allowed" in b93.validate_evidence(data)


def test_positive_control_requires_extension_and_canary_signals() -> None:
    data = _valid()
    data["controls"][0]["extension_changed"] = False
    data["controls"][0]["canary_touched"] = False
    assert "positive:required_safe_signals_missing" in b93.validate_evidence(data)


def test_administrative_control_requires_explicit_suppressors() -> None:
    data = _valid()
    data["controls"][1]["known_backup_workflow"] = False
    assert "administrative:explicit_suppressors_required" in b93.validate_evidence(data)


def test_benign_control_rejects_threat_like_flags() -> None:
    data = _valid()
    data["controls"][2]["extension_changed"] = True
    assert "benign:unexpected_signal" in b93.validate_evidence(data)


def test_positive_below_live_threshold_cannot_verify() -> None:
    data = _valid()
    data["controls"][0]["write_event_count"] = 4
    data["controls"][0]["rename_event_count"] = 1
    result = b93.summarize(data)
    assert result["passed"] is False
    assert result["coverage_summary"] == {"PARTIAL": 6, "GAP": 0, "VERIFIED": 0}
    decision = next(item for item in result["coverage_decisions"] if item["scenario_id"] == "B7-RANSOMWARE-001")
    assert decision["status"] == "PARTIAL"


def test_all_non_target_scenarios_have_explicit_blockers() -> None:
    result = b93.summarize(_valid())
    decisions = {item["scenario_id"]: item for item in result["coverage_decisions"]}
    for scenario_id, blocker in b93.PARTIAL_BLOCKERS.items():
        assert decisions[scenario_id]["status"] == "PARTIAL"
        assert decisions[scenario_id]["limitation"] == blocker


def test_input_is_not_mutated() -> None:
    data = _valid()
    before = copy.deepcopy(data)
    b93.summarize(data)
    assert data == before


def test_authority_boundaries_remain_narrow() -> None:
    result = b93.summarize(_valid())
    boundaries = result["boundaries"]
    assert boundaries["acceptance_harness_file_mutation"] is True
    assert boundaries["dedicated_temp_directory_only"] is True
    assert boundaries["user_file_access"] is False
    assert boundaries["file_content_collected"] is False
    assert boundaries["absolute_paths_exported"] is False
    assert boundaries["real_malware_executed"] is False
    assert boundaries["product_file_write_authority"] is False
    assert boundaries["product_file_rename_authority"] is False
    assert boundaries["product_file_delete_authority"] is False
    assert boundaries["remediation_authority"] is False
    assert boundaries["privileged_system_mutation"] is False

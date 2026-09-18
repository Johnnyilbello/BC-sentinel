from __future__ import annotations

from copy import deepcopy
import json

import pytest

from sentinel import beta12_process_file_correlation as b121
from sentinel import beta12_script_abuse_controls as b122


def _control(control_id: str, *, mutations: int, admin: bool = False, bulk: bool = False) -> dict:
    observation = b121.sample_observation(with_parent=True)
    observation["observation_id"] = f"b122-{control_id}"
    observation["process"]["pid"] += mutations
    observation["parent_process"]["pid"] += mutations
    observation["process"]["parent_pid"] = observation["parent_process"]["pid"]
    observation["file"]["target_path_digest"] = ("%064x" % (1000 + mutations))
    observation["file"]["sha256"] = ("%064x" % (2000 + mutations))
    observation["evidence"] = {
        "process_evidence_id": f"ev-{control_id}-process",
        "file_evidence_id": f"ev-{control_id}-file",
        "relation_evidence_id": f"ev-{control_id}-relation",
    }
    return {
        "control_id": control_id,
        "live_observation": True,
        "script_execution_observed": True,
        "script_sha256": "9" * 64,
        "script_path_digest": "8" * 64,
        "file_mutation_count": mutations,
        "duration_seconds": 2.0,
        "known_admin_automation": admin,
        "user_initiated_bulk_operation": bulk,
        "cleanup_state": "EXITED",
        "correlation_observation": observation,
    }


def _evidence() -> dict:
    return {
        "schema": b122.SCHEMA,
        "source": b122.SOURCE,
        "controls": [
            _control("positive-script-mutation-burst", mutations=6),
            _control("administrative-script-mutation-burst", mutations=6, admin=True, bulk=True),
            _control("benign-powershell-script", mutations=1),
        ],
        "boundaries": dict(b122.BOUNDARIES),
    }


def test_self_check_binds_exact_b121_checkpoint():
    report = b122.self_check()
    assert report["passed"] is True
    assert report["source_checkpoint"] == "checkpoint/v012-beta12-b121-pass"
    assert report["source_checkpoint_commit"] == "cd8b3e89211afe29bf32a2646f4210c73179bc1f"
    assert report["target_scenario_id"] == "B12-SCRIPT-ABUSE-001"
    assert report["baseline_verified_scenarios"] == ["B7-POWERSHELL-001", "B7-RANSOMWARE-001"]


def test_positive_admin_benign_controls_have_expected_outcomes():
    report = b122.summarize(_evidence())
    assert report["passed"] is True
    outcomes = {key: value["outcome"] for key, value in report["control_results"].items()}
    assert outcomes == {
        "positive-script-mutation-burst": "DETECTED",
        "administrative-script-mutation-burst": "REVIEW_REQUIRED",
        "benign-powershell-script": "NO_MATCH",
    }


def test_b122_earns_exactly_one_new_verified_scenario():
    report = b122.summarize(_evidence())
    assert report["coverage_summary"] == {"PARTIAL": 4, "GAP": 0, "VERIFIED": 3}
    assert report["verified_scenarios"] == [
        "B7-POWERSHELL-001",
        "B7-RANSOMWARE-001",
        "B12-SCRIPT-ABUSE-001",
    ]
    assert report["new_verified_scenario_earned"] is True


def test_detector_binds_to_graph_and_incident():
    report = b122.summarize(_evidence())
    assert report["detector_to_security_graph_bound"] is True
    assert report["security_graph_to_incident_bound"] is True
    assert len(report["graph_digest"]) == 64
    assert len(report["correlation_digest"]) == 64


def test_no_content_path_or_command_export():
    report = b122.summarize(_evidence())
    assert report["script_content_exported"] is False
    assert report["command_line_exported"] is False
    assert report["raw_path_exported"] is False
    assert report["synthetic_fallback_used"] is False
    assert report["network_required"] is False
    assert report["cloud_required"] is False
    assert report["authority_expanded"] is False


@pytest.mark.parametrize("field", ["command_line", "script_content", "raw_path", "username", "token"])
def test_unexpected_sensitive_control_fields_fail_closed_without_echo(field):
    data = _evidence()
    data["controls"][0][field] = "PRIVATE_B122_VALUE"
    report = b122.summarize(data)
    assert report["passed"] is False
    assert "PRIVATE_B122_VALUE" not in json.dumps(report)


def test_positive_below_mutation_threshold_does_not_verify():
    data = _evidence()
    data["controls"][0]["file_mutation_count"] = 2
    report = b122.summarize(data)
    assert report["passed"] is False
    assert report["coverage_summary"] == {"PARTIAL": 5, "GAP": 0, "VERIFIED": 2}
    assert report["new_verified_scenario_earned"] is False


def test_admin_suppressors_prevent_detected_outcome():
    data = _evidence()
    result = b122.detect_control(data["controls"][1])
    assert result["score"] >= 7
    assert result["outcome"] == "REVIEW_REQUIRED"
    assert result["suppressor"] is True


def test_benign_control_is_no_match():
    data = _evidence()
    result = b122.detect_control(data["controls"][2])
    assert result["score"] < 7
    assert result["outcome"] == "NO_MATCH"


def test_invalid_embedded_correlation_observation_fails_closed():
    data = _evidence()
    data["controls"][0]["correlation_observation"]["file"]["sha256"] = "bad"
    report = b122.summarize(data)
    assert report["passed"] is False
    assert any("correlation_observation_invalid" in item for item in report["failures"])


def test_duplicate_observation_ids_fail_closed():
    data = _evidence()
    data["controls"][1]["correlation_observation"]["observation_id"] = data["controls"][0]["correlation_observation"]["observation_id"]
    report = b122.summarize(data)
    assert report["passed"] is False
    assert "b122:observation_ids_not_distinct" in report["failures"]


def test_boundary_flip_fails_closed():
    data = _evidence()
    data["boundaries"]["automatic_quarantine"] = True
    report = b122.summarize(data)
    assert report["passed"] is False
    assert "b122:boundary_invalid" in report["failures"]


def test_deterministic_summary_for_same_evidence():
    first = b122.summarize(_evidence())
    second = b122.summarize(deepcopy(_evidence()))
    assert first == second


@pytest.mark.parametrize("bad", [None, [], "raw", 7, True, {}])
def test_malformed_top_level_fails_closed(bad):
    assert b122.summarize(bad)["passed"] is False

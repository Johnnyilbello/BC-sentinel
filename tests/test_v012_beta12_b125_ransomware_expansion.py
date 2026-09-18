from __future__ import annotations

from copy import deepcopy
import json

import pytest

from sentinel import beta12_ransomware_expansion as b125
from sentinel import beta9_ransomware_controls as b93


def _b9_control(control_id: str) -> dict:
    row = {
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
        "started_at_utc": "2026-09-18T12:00:00Z",
        "completed_at_utc": "2026-09-18T12:00:02Z",
        "cleanup_state": "CLEAN",
    }
    if control_id == "positive-ransomware-like":
        row["canary_touched"] = True
    elif control_id == "administrative-backup-like":
        row["known_backup_workflow"] = True
        row["user_initiated_bulk_operation"] = True
    elif control_id == "benign-save":
        row["write_event_count"] = 2
        row["rename_event_count"] = 0
        row["entropy_delta"] = 0.0
        row["extension_changed"] = False
    return row


def _evidence() -> dict:
    return {
        "schema": b125.SCHEMA,
        "source": b125.SOURCE,
        "b9_evidence": {
            "schema": b93.SCHEMA,
            "source": b93.SOURCE,
            "controls": [_b9_control(control_id) for control_id in b93.CONTROL_IDS],
            "boundaries": dict(b93.BOUNDARIES),
        },
        "process": {
            "pid": 4321,
            "image_sha256": "a" * 64,
            "image_path_digest": "b" * 64,
        },
        "boundaries": dict(b125.BOUNDARIES),
    }


def test_self_check_binds_exact_b124_checkpoint():
    report = b125.self_check()
    assert report["passed"] is True
    assert report["source_checkpoint"] == "checkpoint/v012-beta12-b124-pass"
    assert report["source_checkpoint_commit"] == "8e1cb119ef225efbf89471bddc645dc5416c8e01"
    assert report["target_scenario_id"] == "B12-RANSOMWARE-PROCESS-001"


def test_reuses_accepted_b9_harness_contract():
    report = b125.summarize(_evidence())
    assert report["passed"] is True
    assert report["reused_b9_live_harness"] is True
    assert report["new_file_mutation_harness_added"] is False
    assert report["b9_control_outcomes"] == {
        "positive-ransomware-like": "DETECTED",
        "administrative-backup-like": "REVIEW_REQUIRED",
        "benign-save": "NO_MATCH",
    }


def test_process_attribution_binds_to_graph_and_incident():
    report = b125.summarize(_evidence())
    assert report["process_attribution_bound"] is True
    assert report["detector_to_security_graph_bound"] is True
    assert report["security_graph_to_incident_bound"] is True
    assert len(report["graph_digest"]) == 64
    assert len(report["correlation_digest"]) == 64


def test_positive_ransomware_detector_signals_are_preserved():
    report = b125.summarize(_evidence())
    assert report["positive_score"] == 10
    assert set(report["positive_matched_signals"]) == {
        "BULK_REWRITE",
        "BULK_RENAME",
        "ENTROPY_SHIFT",
        "EXTENSION_CHURN",
        "CANARY_TOUCH",
    }


def test_b125_earns_sixth_verified_scenario():
    report = b125.summarize(_evidence())
    assert report["coverage_summary"] == {"PARTIAL": 4, "GAP": 0, "VERIFIED": 6}
    assert report["verified_scenarios"] == [
        "B7-POWERSHELL-001",
        "B7-RANSOMWARE-001",
        "B12-SCRIPT-ABUSE-001",
        "B12-AUTOSTART-LINK-001",
        "B12-PROCESS-TREE-001",
        "B12-RANSOMWARE-PROCESS-001",
    ]
    assert report["new_verified_scenario_earned"] is True


def test_boundaries_remain_narrow():
    report = b125.summarize(_evidence())
    assert report["broad_ransomware_protection_claimed"] is False
    assert report["synthetic_fallback_used"] is False
    assert report["authority_expanded"] is False
    assert report["network_required"] is False
    assert report["cloud_required"] is False
    assert report["boundaries"]["user_file_access"] is False
    assert report["boundaries"]["file_content_exported"] is False
    assert report["boundaries"]["absolute_paths_exported"] is False
    assert report["boundaries"]["real_malware_executed"] is False


@pytest.mark.parametrize("field", ["command_line", "raw_path", "username", "token"])
def test_sensitive_extra_top_level_fields_fail_closed_without_echo(field):
    data = _evidence()
    data[field] = "PRIVATE_B125_VALUE"
    report = b125.summarize(data)
    assert report["passed"] is False
    assert "PRIVATE_B125_VALUE" not in json.dumps(report)


def test_invalid_process_hash_fails_closed():
    data = _evidence()
    data["process"]["image_sha256"] = "bad"
    report = b125.summarize(data)
    assert report["passed"] is False
    assert "b125:process_image_sha256_invalid" in report["failures"]


def test_tampered_b9_control_fails_closed():
    data = _evidence()
    data["b9_evidence"]["controls"][0]["sandbox_scope"] = "USER_DOCUMENTS"
    report = b125.summarize(data)
    assert report["passed"] is False
    assert any("sandbox_scope_invalid" in item for item in report["failures"])


def test_boundary_flip_fails_closed():
    data = _evidence()
    data["boundaries"]["user_file_access"] = True
    report = b125.summarize(data)
    assert report["passed"] is False
    assert "b125:boundary_invalid" in report["failures"]


def test_deterministic_summary():
    assert b125.summarize(_evidence()) == b125.summarize(deepcopy(_evidence()))


@pytest.mark.parametrize("bad", [None, [], "raw", 1, True, {}])
def test_malformed_input_fails_closed(bad):
    assert b125.summarize(bad)["passed"] is False

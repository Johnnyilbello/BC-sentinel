from __future__ import annotations

import copy

from sentinel import beta10_proof_mode as proof
from sentinel import beta9_ransomware_controls as b93


def _evidence() -> dict:
    boundaries = dict(b93.BOUNDARIES)
    common = {
        "live_observation": True,
        "sandbox_scope": "DEDICATED_TEMP_DIRECTORY",
        "observer_backend": "WATCHDOG_LOCAL_FILESYSTEM",
        "cleanup_state": "CLEAN",
    }
    return {
        "schema": b93.SCHEMA,
        "source": b93.SOURCE,
        "boundaries": boundaries,
        "controls": [
            {
                **common,
                "control_id": "positive-ransomware-like",
                "write_event_count": 24,
                "rename_event_count": 18,
                "entropy_delta": 0.75,
                "extension_changed": True,
                "canary_touched": True,
                "known_backup_workflow": False,
                "user_initiated_bulk_operation": False,
                "started_at_utc": "2026-09-16T13:30:01+00:00",
                "completed_at_utc": "2026-09-16T13:30:03+00:00",
            },
            {
                **common,
                "control_id": "administrative-backup-like",
                "write_event_count": 24,
                "rename_event_count": 18,
                "entropy_delta": 0.75,
                "extension_changed": True,
                "canary_touched": False,
                "known_backup_workflow": True,
                "user_initiated_bulk_operation": True,
                "started_at_utc": "2026-09-16T13:30:04+00:00",
                "completed_at_utc": "2026-09-16T13:30:06+00:00",
            },
            {
                **common,
                "control_id": "benign-save",
                "write_event_count": 2,
                "rename_event_count": 0,
                "entropy_delta": 0.0,
                "extension_changed": False,
                "canary_touched": False,
                "known_backup_workflow": False,
                "user_initiated_bulk_operation": False,
                "started_at_utc": "2026-09-16T13:30:07+00:00",
                "completed_at_utc": "2026-09-16T13:30:08+00:00",
            },
        ],
    }


def test_baseline_is_deterministic_and_keeps_beta9_coverage() -> None:
    first = proof.baseline_report()
    second = proof.baseline_report()
    assert first == second
    assert first["coverage_summary"] == {"PARTIAL": 5, "GAP": 0, "VERIFIED": 1}
    assert first["verified_scenario_id"] == "B7-RANSOMWARE-001"
    assert first["report_digest"] == second["report_digest"]


def test_baseline_exposes_six_scenarios_with_explicit_limits() -> None:
    report = proof.baseline_report()
    assert len(report["scenarios"]) == 6
    assert all(row["limitation"] for row in report["scenarios"])
    assert [row["scenario_id"] for row in report["scenarios"]] == [row["scenario_id"] for row in proof.SCENARIOS]


def test_only_ransomware_is_verified_and_proof_capable() -> None:
    report = proof.baseline_report()
    verified = [row for row in report["scenarios"] if row["status"] == "VERIFIED"]
    capable = [row for row in report["scenarios"] if row["proof_capability"] == "SAFE_ON_DEMAND_LOCAL_CONTROL"]
    assert [row["scenario_id"] for row in verified] == ["B7-RANSOMWARE-001"]
    assert [row["scenario_id"] for row in capable] == ["B7-RANSOMWARE-001"]


def test_baseline_never_expands_claim_or_authority() -> None:
    report = proof.baseline_report()
    assert report["broad_protection_claimed"] is False
    assert report["synthetic_fallback_used"] is False
    assert not any(report["authority_boundary"].values())
    assert report["privacy"]["local_only"] is True
    assert report["privacy"]["personal_data_collected"] is False
    assert report["privacy"]["remote_access"] is False


def test_fresh_live_control_attaches_current_machine_proof_without_promoting_more_coverage() -> None:
    report = proof.attach_fresh_ransomware_proof(
        proof.baseline_report(),
        _evidence(),
        proof_started_after_utc="2026-09-16T13:30:00+00:00",
    )
    assert report["passed"] is True
    assert report["coverage_summary"] == {"PARTIAL": 5, "GAP": 0, "VERIFIED": 1}
    assert report["current_machine_proof_performed"] is True
    ransomware = next(row for row in report["scenarios"] if row["scenario_id"] == "B7-RANSOMWARE-001")
    assert ransomware["fresh_proof"] is True
    assert ransomware["proof_outcome"] == "DETECTED"
    assert ransomware["proof_details"]["control_outcomes"] == {
        "positive-ransomware-like": "DETECTED",
        "administrative-backup-like": "REVIEW_REQUIRED",
        "benign-save": "NO_MATCH",
    }
    assert ransomware["proof_details"]["detector_to_security_graph_bound"] is True
    assert ransomware["proof_details"]["security_graph_to_incident_bound"] is True
    assert [row["status"] for row in report["scenarios"]].count("VERIFIED") == 1


def test_stale_or_replayed_evidence_is_rejected() -> None:
    result = proof.attach_fresh_ransomware_proof(
        proof.baseline_report(),
        _evidence(),
        proof_started_after_utc="2026-09-16T13:31:00+00:00",
    )
    assert result["passed"] is False
    assert "proof:stale_or_replayed_evidence" in result["failures"]


def test_missing_or_invalid_freshness_threshold_is_rejected() -> None:
    result = proof.attach_fresh_ransomware_proof(
        proof.baseline_report(),
        _evidence(),
        proof_started_after_utc="not-a-date",
    )
    assert result["passed"] is False
    assert "proof:freshness_threshold_invalid" in result["failures"]


def test_sensitive_or_unexpected_control_fields_fail_closed() -> None:
    evidence = _evidence()
    evidence["controls"][0]["absolute_path"] = "C:/Users/example/private.txt"
    result = proof.attach_fresh_ransomware_proof(
        proof.baseline_report(),
        evidence,
        proof_started_after_utc="2026-09-16T13:30:00+00:00",
    )
    assert result["passed"] is False
    assert any("fields_invalid" in failure for failure in result["failures"])
    assert "private.txt" not in repr(result)


def test_attach_does_not_mutate_inputs() -> None:
    baseline = proof.baseline_report()
    evidence = _evidence()
    baseline_before = copy.deepcopy(baseline)
    evidence_before = copy.deepcopy(evidence)
    result = proof.attach_fresh_ransomware_proof(
        baseline,
        evidence,
        proof_started_after_utc="2026-09-16T13:30:00+00:00",
    )
    assert result["passed"] is True
    assert baseline == baseline_before
    assert evidence == evidence_before


def test_summary_is_customer_safe_and_explicit() -> None:
    baseline = proof.baseline_report()
    summary = proof.proof_summary(baseline)
    assert summary == {
        "passed": True,
        "coverage_summary": {"PARTIAL": 5, "GAP": 0, "VERIFIED": 1},
        "verified_scenario_id": "B7-RANSOMWARE-001",
        "verified_count": 1,
        "scenario_count": 6,
        "fresh_proof_count": 0,
        "current_machine_proof_performed": False,
        "broad_protection_claimed": False,
        "authority_expanded": False,
        "proof_capable_scenarios": ["B7-RANSOMWARE-001"],
    }

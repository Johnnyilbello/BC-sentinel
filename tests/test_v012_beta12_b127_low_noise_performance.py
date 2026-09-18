from __future__ import annotations

import pytest

from sentinel import beta12_low_noise_performance as b127


def _measurement(**overrides) -> dict:
    row = {
        "iteration": 1,
        "wall_ms": 12.0,
        "cpu_ms": 8.0,
        "rss_delta_bytes": 1024,
        "false_positive_detections": 0,
        "outcome_drift": 0,
        "user_interruptions": 0,
        "outcomes": dict(b127.EXPECTED_OUTCOMES),
    }
    row.update(overrides)
    return row


def _measurements(count: int = 15, **overrides) -> list[dict]:
    return [_measurement(iteration=index + 1, **overrides) for index in range(count)]


def test_self_check_is_bound_to_exact_b126_checkpoint():
    report = b127.self_check()
    assert report["passed"] is True
    assert report["source_checkpoint"] == "checkpoint/v012-beta12-b126-pass"
    assert report["source_checkpoint_commit"] == "b1f55ea32564d72cae6056308f90f8b41137dc94"
    assert report["coverage_summary"] == {"PARTIAL": 4, "GAP": 0, "VERIFIED": 7}
    assert report["coverage_promoted_by_self_check"] is False
    assert report["new_verified_scenario_earned"] is False


def test_low_noise_case_outcomes_are_exact():
    assert b127.run_low_noise_cases() == b127.EXPECTED_OUTCOMES


def test_benign_cases_never_detect():
    outcomes = b127.run_low_noise_cases()
    assert outcomes["script_benign"] == "NO_MATCH"
    assert outcomes["autostart_benign"] == "NO_MATCH"
    assert outcomes["process_tree_benign"] == "NO_MATCH"
    assert outcomes["ransomware_benign"] == "NO_MATCH"


def test_admin_cases_are_review_not_detected():
    outcomes = b127.run_low_noise_cases()
    assert outcomes["script_admin"] == "REVIEW_REQUIRED"
    assert outcomes["autostart_admin"] == "REVIEW_REQUIRED"
    assert outcomes["process_tree_admin"] == "REVIEW_REQUIRED"
    assert outcomes["ransomware_admin"] == "REVIEW_REQUIRED"


def test_local_reputation_unknowns_are_not_malicious_or_trusted():
    outcomes = b127.run_low_noise_cases()
    assert outcomes["reputation_known_good"] == "TRUSTED_LOCAL"
    assert outcomes["reputation_signed_unknown"] == "UNKNOWN_SIGNED"
    assert outcomes["reputation_unsigned_unknown"] == "UNKNOWN_UNSIGNED"


def test_summary_passes_inside_budgets_and_preserves_coverage():
    report = b127.summarize_measurements(_measurements())
    assert report["passed"] is True
    assert report["failures"] == []
    assert report["coverage_summary"] == {"PARTIAL": 4, "GAP": 0, "VERIFIED": 7}
    assert report["coverage_promoted"] is False
    assert report["verified_count_preserved"] == 7
    assert report["false_positive_gate_passed"] is True
    assert report["outcome_stability_gate_passed"] is True
    assert report["performance_gate_passed"] is True
    assert report["user_interruption_gate_passed"] is True
    assert report["new_verified_scenario_earned"] is False


def test_summary_requires_minimum_repeats():
    report = b127.summarize_measurements(_measurements(9))
    assert report["passed"] is False
    assert "measurement:insufficient_repeats" in report["failures"]


def test_summary_fails_false_positive_budget():
    report = b127.summarize_measurements(_measurements(false_positive_detections=1))
    assert report["passed"] is False
    assert "budget:false_positive_exceeded" in report["failures"]
    assert report["false_positive_gate_passed"] is False


def test_summary_fails_outcome_drift_budget():
    report = b127.summarize_measurements(_measurements(outcome_drift=1))
    assert report["passed"] is False
    assert "budget:outcome_drift_exceeded" in report["failures"]


def test_summary_fails_outcome_payload_drift():
    outcomes = dict(b127.EXPECTED_OUTCOMES)
    outcomes["script_benign"] = "DETECTED"
    report = b127.summarize_measurements(_measurements(outcomes=outcomes))
    assert report["passed"] is False
    assert any(item.endswith(":outcomes_invalid") for item in report["failures"])
    assert report["outcome_stability_gate_passed"] is False


def test_summary_fails_wall_budget():
    report = b127.summarize_measurements(
        _measurements(wall_ms=float(b127.BUDGETS["p95_wall_ms"]) + 1.0)
    )
    assert report["passed"] is False
    assert "budget:p95_wall_exceeded" in report["failures"]


def test_summary_fails_cpu_budget():
    report = b127.summarize_measurements(
        _measurements(cpu_ms=float(b127.BUDGETS["p95_cpu_ms"]) + 1.0)
    )
    assert report["passed"] is False
    assert "budget:p95_cpu_exceeded" in report["failures"]


def test_summary_fails_rss_budget():
    too_large = int((float(b127.BUDGETS["max_rss_delta_mib"]) + 1.0) * 1024 * 1024)
    report = b127.summarize_measurements(_measurements(rss_delta_bytes=too_large))
    assert report["passed"] is False
    assert "budget:rss_delta_exceeded" in report["failures"]


def test_summary_fails_user_interruption_budget():
    report = b127.summarize_measurements(_measurements(user_interruptions=1))
    assert report["passed"] is False
    assert "budget:user_interruptions_exceeded" in report["failures"]


def test_measure_rejects_repeat_count_outside_contract():
    with pytest.raises(ValueError, match="repeat_count_out_of_range"):
        b127.measure(repeats=9)
    with pytest.raises(ValueError, match="repeat_count_out_of_range"):
        b127.measure(repeats=41)


def test_percentile_uses_nearest_rank():
    assert b127._percentile([1.0, 2.0, 3.0, 4.0, 5.0], 0.95) == 5.0
    assert b127._percentile([5.0, 1.0, 3.0, 2.0, 4.0], 0.50) == 3.0


def test_percentile_rejects_invalid_input():
    with pytest.raises(ValueError, match="requires_values"):
        b127._percentile([], 0.95)
    with pytest.raises(ValueError, match="out_of_range"):
        b127._percentile([1.0], 0.0)


def test_boundaries_remain_read_only_local():
    report = b127.summarize_measurements(_measurements())
    assert report["authority_expanded"] is False
    assert report["network_required"] is False
    assert report["cloud_required"] is False
    assert report["boundaries"]["trust_allowlist_mutation"] is False
    assert report["boundaries"]["automatic_quarantine"] is False
    assert report["boundaries"]["terminate_process_authority"] is False

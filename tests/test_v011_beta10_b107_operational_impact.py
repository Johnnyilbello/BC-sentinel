from __future__ import annotations

import pytest

from sentinel import beta10_operational_impact as b107


def _baseline() -> dict:
    return {
        "passed": True,
        "coverage_summary": {"PARTIAL": 4, "GAP": 0, "VERIFIED": 2},
        "synthetic_fallback_used": False,
        "control_results": {
            "positive-powershell-burst": {"outcome": "DETECTED"},
            "administrative-powershell-burst": {"outcome": "REVIEW_REQUIRED"},
            "benign-powershell-session": {"outcome": "NO_MATCH"},
        },
    }


def _measurement(**overrides) -> dict:
    row = {
        "iteration": 1,
        "wall_ms": 12.0,
        "cpu_ms": 8.0,
        "rss_delta_bytes": 1024,
        "user_interruptions": 0,
        "positive_outcome": "DETECTED",
        "administrative_outcome": "REVIEW_REQUIRED",
        "benign_outcome": "NO_MATCH",
    }
    row.update(overrides)
    return row


def _measurements(count: int = 7, **overrides) -> list[dict]:
    rows = []
    for index in range(count):
        row = _measurement(iteration=index + 1, **overrides)
        rows.append(row)
    return rows


def test_b107_contract_preserves_b106_and_coverage() -> None:
    contract = b107.validate_b107_contract()
    assert contract["passed"] is True
    assert contract["source_predecessor_commit"] == "79293c641d1ecf5e1ce8d1fa313b9ea4b03f3868"
    assert contract["predecessor_b106_contract_preserved"] is True
    assert contract["b106_pilot_quarantine_authority_preserved"] is True
    assert contract["b106_pilot_rollback_authority_preserved"] is True
    assert contract["coverage_summary"] == {"PARTIAL": 4, "GAP": 0, "VERIFIED": 2}
    assert contract["coverage_expansion_attempted"] is True
    assert contract["coverage_promoted"] is False
    assert contract["new_authority_expanded"] is False


def test_remaining_candidates_fail_closed() -> None:
    contract = b107.validate_b107_contract()
    assert contract["remaining_candidate_count"] == 4
    decisions = {row["scenario_id"]: row["decision"] for row in contract["candidate_evaluations"]}
    assert decisions == {
        "B7-PERSISTENCE-001": "DEFERRED_BOUNDARY",
        "B7-DEFENSE-EVASION-001": "BLOCKED_AUTHORITY",
        "B7-C2-DNS-001": "BLOCKED_AUTHORITY",
        "B7-CREDENTIAL-001": "BLOCKED_PRIVACY",
    }


def test_privacy_and_authority_boundaries_remain_narrow() -> None:
    contract = b107.validate_b107_contract()
    assert contract["privacy"]["network_io"] is False
    assert contract["privacy"]["credential_access"] is False
    assert contract["privacy"]["powershell_content_read"] is False
    assert contract["authority"]["network_test_authority"] is False
    assert contract["authority"]["protected_security_control_mutation"] is False
    assert contract["authority"]["broad_persistence_mutation"] is False
    assert contract["authority"]["automatic_quarantine"] is False


def test_percentile_uses_nearest_rank() -> None:
    assert b107._percentile([1.0, 2.0, 3.0, 4.0, 5.0], 0.95) == 5.0
    assert b107._percentile([5.0, 1.0, 3.0, 2.0, 4.0], 0.50) == 3.0


def test_percentile_rejects_invalid_input() -> None:
    with pytest.raises(ValueError, match="requires_values"):
        b107._percentile([], 0.95)
    with pytest.raises(ValueError, match="out_of_range"):
        b107._percentile([1.0], 0.0)


def test_measurement_summary_passes_inside_budgets() -> None:
    report = b107.summarize_measurements(_measurements(), _baseline())
    assert report["passed"] is True
    assert report["failures"] == []
    assert report["false_positive_controls_passed"] is True
    assert report["user_interruption_budget_passed"] is True
    assert report["performance_budget_passed"] is True
    assert report["operational_metrics"]["repeat_count"] == 7


def test_measurement_summary_requires_enough_repeats() -> None:
    report = b107.summarize_measurements(_measurements(4), _baseline())
    assert report["passed"] is False
    assert "measurement:insufficient_repeats" in report["failures"]


def test_measurement_summary_fails_wall_budget() -> None:
    report = b107.summarize_measurements(_measurements(wall_ms=900.0), _baseline())
    assert report["passed"] is False
    assert "budget:p95_wall_exceeded" in report["failures"]


def test_measurement_summary_fails_cpu_budget() -> None:
    report = b107.summarize_measurements(_measurements(cpu_ms=900.0), _baseline())
    assert report["passed"] is False
    assert "budget:p95_cpu_exceeded" in report["failures"]


def test_measurement_summary_fails_rss_budget() -> None:
    too_large = int(65 * 1024 * 1024)
    report = b107.summarize_measurements(_measurements(rss_delta_bytes=too_large), _baseline())
    assert report["passed"] is False
    assert "budget:rss_delta_exceeded" in report["failures"]


def test_measurement_summary_fails_user_interruption_budget() -> None:
    report = b107.summarize_measurements(_measurements(user_interruptions=1), _baseline())
    assert report["passed"] is False
    assert "budget:user_interruptions_exceeded" in report["failures"]
    assert report["user_interruption_budget_passed"] is False


def test_measurement_summary_fails_outcome_drift() -> None:
    report = b107.summarize_measurements(
        _measurements(benign_outcome="DETECTED"),
        _baseline(),
    )
    assert report["passed"] is False
    assert any(item.endswith("outcome_drift:benign-powershell-session") for item in report["failures"])
    assert report["false_positive_controls_passed"] is False


def test_measurement_summary_fails_baseline_coverage_change() -> None:
    baseline = _baseline()
    baseline["coverage_summary"] = {"PARTIAL": 3, "GAP": 0, "VERIFIED": 3}
    report = b107.summarize_measurements(_measurements(), baseline)
    assert report["passed"] is False
    assert "baseline:coverage_changed" in report["failures"]


def test_measurement_summary_rejects_synthetic_fallback() -> None:
    baseline = _baseline()
    baseline["synthetic_fallback_used"] = True
    report = b107.summarize_measurements(_measurements(), baseline)
    assert report["passed"] is False
    assert "baseline:synthetic_fallback_not_allowed" in report["failures"]


def test_measure_operational_impact_rejects_repeat_count_outside_contract() -> None:
    with pytest.raises(ValueError, match="repeat_count_out_of_range"):
        b107.measure_operational_impact({}, repeats=4)
    with pytest.raises(ValueError, match="repeat_count_out_of_range"):
        b107.measure_operational_impact({}, repeats=26)

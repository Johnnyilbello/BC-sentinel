from __future__ import annotations

from copy import deepcopy

from sentinel import beta8_final_acceptance as final


def test_final_self_check_freezes_beta8_contract() -> None:
    result = final.self_check()
    assert result["passed"], result["failures"]
    assert result["deterministic_core"] is True
    assert result["coverage_summary"] == {"PARTIAL": 6, "GAP": 0, "VERIFIED": 0}
    assert result["detector_count"] == 3
    assert result["prediction_accuracy"] == 1.0
    assert result["read_only"] is True
    assert result["synthetic_evidence_cannot_verify"] is True
    assert result["predictions_are_evidence"] is False


def test_final_core_is_deterministic() -> None:
    first = final._core_snapshot()
    second = final._core_snapshot()
    assert first == second
    assert final._digest(first) == final._digest(second)


def test_resource_cost_is_measured_and_bounded() -> None:
    report = final.run_final_acceptance()
    assert not final.validate_report(report)
    assert 0 <= report.elapsed_seconds <= final.MAX_PIPELINE_SECONDS
    assert 0 <= report.peak_memory_bytes <= final.MAX_PEAK_BYTES


def test_validation_rejects_verified_claim() -> None:
    payload = final.run_final_acceptance().to_dict()
    broken = deepcopy(payload)
    broken["core"]["coverage"]["summary"] = {"PARTIAL": 5, "GAP": 0, "VERIFIED": 1}
    broken["core_digest"] = final._digest(broken["core"])
    assert "final:coverage_invalid" in final.validate_report(broken)


def test_validation_rejects_prediction_as_evidence() -> None:
    payload = final.run_final_acceptance().to_dict()
    payload["predictions_are_evidence"] = True
    assert "final:read_only_boundary_invalid" in final.validate_report(payload)


def test_validation_rejects_authority_expansion() -> None:
    payload = final.run_final_acceptance().to_dict()
    payload["automatic_quarantine"] = True
    assert "final:automatic_quarantine_must_be_false" in final.validate_report(payload)


def test_source_checkpoint_is_exact_b86_acceptance() -> None:
    assert final.SOURCE_CHECKPOINT == "checkpoint/v011-beta8-b86-pass"
    assert final.SOURCE_CHECKPOINT_COMMIT == "ee98c6fb908c4a8ff133e8fe94f0afd2c2bc08f6"

from __future__ import annotations

from copy import deepcopy

from sentinel import predictive_attack_chain


def test_self_check_validates_complete_controlled_prediction_chain() -> None:
    result = predictive_attack_chain.self_check()
    assert result["passed"], result["failures"]
    assert result["chain_order"] == list(predictive_attack_chain.EXPECTED_CHAIN)
    assert result["predicted_stages"] == ["PERSISTENCE", "DNS", "DETECTION"]
    assert result["confidences"] == [0.65, 0.78, 0.88]
    assert result["accuracy"] == 1.0
    assert result["prediction_count"] == 3


def test_report_is_deterministic_and_calibrated() -> None:
    first = predictive_attack_chain.run_controlled_chain()
    second = predictive_attack_chain.run_controlled_chain()
    assert first.stable_json() == second.stable_json()
    assert first.digest() == second.digest()
    assert first.brier_score == 0.061767
    assert first.to_dict()["confidence_monotonic"] is True


def test_each_prediction_uses_only_observed_support() -> None:
    report = predictive_attack_chain.run_controlled_chain()
    previous: set[str] = set()
    for item in report.predictions:
        current = set(item.supporting_evidence_ids)
        assert current
        assert previous.issubset(current)
        assert item.predicted_stage == item.actual_next_stage
        previous = current


def test_validation_rejects_false_accuracy_and_evidence_claim() -> None:
    payload = predictive_attack_chain.run_controlled_chain().to_dict()
    broken = deepcopy(payload)
    broken["accuracy"] = 0.5
    broken["predictions_are_evidence"] = True
    failures = predictive_attack_chain.validate_report(broken)
    assert "predictive_chain:accuracy_invalid" in failures
    assert "predictive_chain:evidence_boundary_invalid" in failures


def test_validation_rejects_authority_expansion() -> None:
    payload = predictive_attack_chain.run_controlled_chain().to_dict()
    payload["remediation_execution"] = True
    payload["graph_mutation"] = True
    failures = predictive_attack_chain.validate_report(payload)
    assert "predictive_chain:remediation_execution_must_be_false" in failures
    assert "predictive_chain:graph_mutation_must_be_false" in failures


def test_all_authority_fields_remain_false() -> None:
    result = predictive_attack_chain.self_check()
    assert result["advisory_only"] is True
    assert result["predictions_are_evidence"] is False
    for field in predictive_attack_chain.FALSE_AUTHORITY_FIELDS:
        assert result[field] is False

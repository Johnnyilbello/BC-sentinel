from __future__ import annotations

import json

import pytest

from sentinel import defense_evasion_detector, incident_correlation, security_graph


def test_b82_self_check_is_green_and_keeps_partial_coverage() -> None:
    result = defense_evasion_detector.self_check()
    assert result["passed"] is True
    assert result["target_scenario_id"] == "B7-DEFENSE-EVASION-001"
    assert result["coverage_status"] == "PARTIAL"
    assert result["positive_outcome"] == "DETECTED"
    assert result["admin_outcome"] == "REVIEW_REQUIRED"
    assert result["benign_outcome"] == "NO_MATCH"
    assert result["evidence_ids_preserved"] is True


def test_b82_positive_fixture_requires_control_interference_plus_weakening() -> None:
    result = defense_evasion_detector.detect(defense_evasion_detector.positive_fixture())
    assert result.outcome == defense_evasion_detector.OUTCOME_DETECTED
    assert result.score == 12
    assert set(result.matched_signals) == defense_evasion_detector.ALLOWED_SIGNALS
    assert result.detection_latency == 2.0


def test_b82_approved_admin_change_never_becomes_detected() -> None:
    result = defense_evasion_detector.detect(defense_evasion_detector.admin_fixture())
    assert result.outcome == defense_evasion_detector.OUTCOME_REVIEW
    assert "APPROVED_CHANGE" in result.suppressor_reasons
    assert "MAINTENANCE_WINDOW" in result.suppressor_reasons
    assert "SIGNED_ADMIN_WORKFLOW" in result.suppressor_reasons
    assert result.outcome != defense_evasion_detector.OUTCOME_DETECTED


def test_b82_benign_status_observation_is_no_match() -> None:
    result = defense_evasion_detector.detect(defense_evasion_detector.benign_fixture())
    assert result.outcome == defense_evasion_detector.OUTCOME_NO_MATCH
    assert result.score == 0
    assert result.matched_signals == ()


def test_b82_single_strong_signal_is_review_not_detected() -> None:
    base = defense_evasion_detector.ControlTamperObservation(
        event_id="b82-review-only",
        observed_at=50.0,
        control_surface="fixture/security-control/service",
        evidence_id="ev-b82-review-only",
        provenance={
            "source": "b82-test",
            "source_id": "review-only",
            "collector": "tests.b82",
            "trust": "DIRECT",
        },
        security_service_stop_attempted=True,
        correlation_key="b82:review-only",
    )
    result = defense_evasion_detector.detect((base,))
    assert result.outcome == defense_evasion_detector.OUTCOME_REVIEW
    assert result.score == 3


def test_b82_same_evidence_produces_same_serialization_and_digest() -> None:
    first = defense_evasion_detector.detect(defense_evasion_detector.positive_fixture())
    second = defense_evasion_detector.detect(tuple(reversed(defense_evasion_detector.positive_fixture())))
    assert first.stable_json() == second.stable_json()
    assert first.digest() == second.digest()


def test_b82_result_round_trip_is_exact() -> None:
    result = defense_evasion_detector.detect(defense_evasion_detector.positive_fixture())
    restored = defense_evasion_detector.DetectionResult.from_dict(json.loads(result.stable_json()))
    assert restored.to_dict() == result.to_dict()
    assert restored.digest() == result.digest()


def test_b82_duplicate_event_ids_fail_closed() -> None:
    base = defense_evasion_detector.positive_fixture()[0]
    duplicate = defense_evasion_detector.ControlTamperObservation(
        event_id=base.event_id,
        observed_at=base.observed_at + 1,
        control_surface="fixture/security-control/duplicate",
        evidence_id="ev-b82-duplicate",
        provenance=base.provenance,
        protection_disable_attempted=True,
        telemetry_suppressed=True,
        correlation_key="b82:duplicate",
    )
    with pytest.raises(ValueError, match="duplicate_event_id"):
        defense_evasion_detector.detect((base, duplicate))


def test_b82_missing_provenance_fails_closed() -> None:
    invalid = defense_evasion_detector.ControlTamperObservation(
        event_id="b82-invalid-provenance",
        observed_at=1.0,
        control_surface="fixture/security-control/invalid",
        evidence_id="ev-b82-invalid-provenance",
        provenance={},
    )
    with pytest.raises(ValueError, match="provenance"):
        defense_evasion_detector.detect((invalid,))


def test_b82_evidence_graph_preserves_evidence_and_correlates_one_incident() -> None:
    observations = defense_evasion_detector.positive_fixture()
    result = defense_evasion_detector.detect(observations)
    graph = defense_evasion_detector.build_evidence_graph(observations, result)
    graph_validation = security_graph.validate_graph(graph.to_dict())
    assert graph_validation.passed is True
    assert graph_validation.node_count == 3
    assert graph_validation.edge_count == 2
    graph_evidence = {evidence_id for node in graph.nodes for evidence_id in node.evidence_ids}
    assert set(result.evidence_ids).issubset(graph_evidence)

    correlation = defense_evasion_detector.correlate_evidence_graph(graph)
    correlation_validation = incident_correlation.validate_result(correlation, graph)
    assert correlation_validation.passed is True
    assert correlation_validation.incident_count == 1
    assert correlation.source_graph_digest == graph.digest()


def test_b82_graph_and_correlation_are_deterministic() -> None:
    observations = defense_evasion_detector.positive_fixture()
    first_result = defense_evasion_detector.detect(observations)
    first_graph = defense_evasion_detector.build_evidence_graph(observations, first_result)
    first_correlation = defense_evasion_detector.correlate_evidence_graph(first_graph)

    second_result = defense_evasion_detector.detect(observations)
    second_graph = defense_evasion_detector.build_evidence_graph(observations, second_result)
    second_correlation = defense_evasion_detector.correlate_evidence_graph(second_graph)

    assert first_graph.digest() == second_graph.digest()
    assert first_correlation.digest() == second_correlation.digest()


def test_b82_result_validator_rejects_authority_tampering() -> None:
    result = defense_evasion_detector.detect(defense_evasion_detector.positive_fixture()).to_dict()
    result["security_control_mutation"] = True
    result["authority_granted"] = True
    validation = defense_evasion_detector.validate_result(result)
    assert validation.passed is False
    assert "result:security_control_mutation_must_be_false" in validation.failures
    assert "result:authority_granted_must_be_false" in validation.failures


def test_b82_resource_budget_is_measured_and_bounded() -> None:
    result = defense_evasion_detector.self_check()
    resource = result["resource_cost"]
    assert resource["elapsed_seconds"] <= resource["max_seconds"]
    assert resource["peak_memory_bytes"] <= resource["max_peak_memory_bytes"]


def test_b82_never_performs_or_grants_mutating_authority() -> None:
    result = defense_evasion_detector.self_check()
    for field_name in defense_evasion_detector.FALSE_SAFETY_FIELDS:
        assert result[field_name] is False
    assert result["read_only"] is True
    assert result["synthetic_fixture_only"] is True

from __future__ import annotations

import json

import pytest

from sentinel import incident_correlation, ransomware_detector, security_graph


def test_b81_self_check_is_green_and_keeps_partial_coverage() -> None:
    result = ransomware_detector.self_check()
    assert result["passed"] is True
    assert result["target_scenario_id"] == "B7-RANSOMWARE-001"
    assert result["coverage_status"] == "PARTIAL"
    assert result["positive_outcome"] == "DETECTED"
    assert result["backup_outcome"] == "REVIEW_REQUIRED"
    assert result["benign_outcome"] == "NO_MATCH"
    assert result["evidence_ids_preserved"] is True


def test_b81_positive_fixture_requires_multiple_behavioral_signals() -> None:
    result = ransomware_detector.detect(ransomware_detector.positive_fixture())
    assert result.outcome == ransomware_detector.OUTCOME_DETECTED
    assert result.score == 10
    assert set(result.matched_signals) == ransomware_detector.ALLOWED_SIGNALS
    assert result.detection_latency == 2.0


def test_b81_backup_false_positive_control_never_becomes_detected() -> None:
    result = ransomware_detector.detect(ransomware_detector.backup_fixture())
    assert result.outcome == ransomware_detector.OUTCOME_REVIEW
    assert "KNOWN_BACKUP_WORKFLOW" in result.suppressor_reasons
    assert result.outcome != ransomware_detector.OUTCOME_DETECTED


def test_b81_benign_save_is_no_match() -> None:
    result = ransomware_detector.detect(ransomware_detector.benign_fixture())
    assert result.outcome == ransomware_detector.OUTCOME_NO_MATCH
    assert result.score == 0
    assert result.matched_signals == ()


def test_b81_same_evidence_produces_same_serialization_and_digest() -> None:
    first = ransomware_detector.detect(ransomware_detector.positive_fixture())
    second = ransomware_detector.detect(tuple(reversed(ransomware_detector.positive_fixture())))
    assert first.stable_json() == second.stable_json()
    assert first.digest() == second.digest()


def test_b81_result_round_trip_is_exact() -> None:
    result = ransomware_detector.detect(ransomware_detector.positive_fixture())
    restored = ransomware_detector.DetectionResult.from_dict(json.loads(result.stable_json()))
    assert restored.to_dict() == result.to_dict()
    assert restored.digest() == result.digest()


def test_b81_duplicate_event_ids_fail_closed() -> None:
    base = ransomware_detector.positive_fixture()[0]
    duplicate = ransomware_detector.FileActivityObservation(
        event_id=base.event_id,
        observed_at=base.observed_at + 1,
        logical_path="fixture/docs/duplicate.txt",
        evidence_id="ev-b81-duplicate",
        provenance=base.provenance,
        write_count_window=25,
        rename_count_window=18,
        entropy_delta=0.4,
        extension_changed=True,
        correlation_key="b81:duplicate",
    )
    with pytest.raises(ValueError, match="duplicate_event_id"):
        ransomware_detector.detect((base, duplicate))


def test_b81_missing_provenance_fails_closed() -> None:
    invalid = ransomware_detector.FileActivityObservation(
        event_id="b81-invalid-provenance",
        observed_at=1.0,
        logical_path="fixture/invalid.txt",
        evidence_id="ev-b81-invalid-provenance",
        provenance={},
    )
    with pytest.raises(ValueError, match="provenance"):
        ransomware_detector.detect((invalid,))


def test_b81_evidence_graph_preserves_evidence_and_correlates_one_incident() -> None:
    observations = ransomware_detector.positive_fixture()
    result = ransomware_detector.detect(observations)
    graph = ransomware_detector.build_evidence_graph(observations, result)
    graph_validation = security_graph.validate_graph(graph.to_dict())
    assert graph_validation.passed is True
    assert graph_validation.node_count == 3
    assert graph_validation.edge_count == 2
    graph_evidence = {evidence_id for node in graph.nodes for evidence_id in node.evidence_ids}
    assert set(result.evidence_ids).issubset(graph_evidence)

    correlation = ransomware_detector.correlate_evidence_graph(graph)
    correlation_validation = incident_correlation.validate_result(correlation, graph)
    assert correlation_validation.passed is True
    assert correlation_validation.incident_count == 1
    assert correlation.source_graph_digest == graph.digest()


def test_b81_graph_and_correlation_are_deterministic() -> None:
    observations = ransomware_detector.positive_fixture()
    first_result = ransomware_detector.detect(observations)
    first_graph = ransomware_detector.build_evidence_graph(observations, first_result)
    first_correlation = ransomware_detector.correlate_evidence_graph(first_graph)

    second_result = ransomware_detector.detect(observations)
    second_graph = ransomware_detector.build_evidence_graph(observations, second_result)
    second_correlation = ransomware_detector.correlate_evidence_graph(second_graph)

    assert first_graph.digest() == second_graph.digest()
    assert first_correlation.digest() == second_correlation.digest()


def test_b81_result_validator_rejects_authority_tampering() -> None:
    result = ransomware_detector.detect(ransomware_detector.positive_fixture()).to_dict()
    result["authority_granted"] = True
    validation = ransomware_detector.validate_result(result)
    assert validation.passed is False
    assert "result:authority_granted_must_be_false" in validation.failures


def test_b81_never_performs_or_grants_mutating_authority() -> None:
    result = ransomware_detector.self_check()
    for field_name in ransomware_detector.FALSE_SAFETY_FIELDS:
        assert result[field_name] is False
    assert result["read_only"] is True
    assert result["synthetic_fixture_only"] is True

from __future__ import annotations

from copy import deepcopy

import pytest

from sentinel import attack_prediction, incident_correlation


def _fixture():
    return attack_prediction._fixture()


def test_self_check_is_deterministic_advisory_and_side_effect_free() -> None:
    result = attack_prediction.self_check()
    assert result["passed"], result["failures"]
    assert result["observed_stage_order"] == ["PROCESS", "SCRIPT", "PERSISTENCE"]
    assert result["predicted_stage"] == "DNS"
    assert result["confidence"] == 0.78
    assert result["outcome"] == attack_prediction.OUTCOME_PREDICTED
    assert result["insufficient_outcome"] == attack_prediction.OUTCOME_INSUFFICIENT
    assert result["deterministic_serialization"] is True
    assert result["stable_round_trip"] is True
    assert result["source_unchanged"] is True


def test_supported_prefixes_have_explicit_bounded_outcomes() -> None:
    graph, correlation, node_ids, incident_id = _fixture()
    review = attack_prediction.predict_next_stage(graph, correlation, incident_id=incident_id, observed_node_ids=node_ids[:2])
    dns = attack_prediction.predict_next_stage(graph, correlation, incident_id=incident_id, observed_node_ids=node_ids[:3])
    detection = attack_prediction.predict_next_stage(graph, correlation, incident_id=incident_id, observed_node_ids=node_ids[:4])
    assert (review.predicted_stage, review.confidence, review.outcome) == ("PERSISTENCE", 0.65, attack_prediction.OUTCOME_REVIEW)
    assert (dns.predicted_stage, dns.confidence, dns.outcome) == ("DNS", 0.78, attack_prediction.OUTCOME_PREDICTED)
    assert (detection.predicted_stage, detection.confidence, detection.outcome) == ("DETECTION", 0.88, attack_prediction.OUTCOME_PREDICTED)


def test_unknown_or_complete_sequence_fails_closed_without_prediction() -> None:
    graph, correlation, node_ids, incident_id = _fixture()
    one = attack_prediction.predict_next_stage(graph, correlation, incident_id=incident_id, observed_node_ids=node_ids[:1])
    complete = attack_prediction.predict_next_stage(graph, correlation, incident_id=incident_id, observed_node_ids=node_ids)
    for result in (one, complete):
        assert result.outcome == attack_prediction.OUTCOME_INSUFFICIENT
        assert result.predicted_stage is None
        assert result.confidence is None


def test_prediction_preserves_only_observed_evidence_ids() -> None:
    graph, correlation, node_ids, incident_id = _fixture()
    result = attack_prediction.predict_next_stage(graph, correlation, incident_id=incident_id, observed_node_ids=node_ids[:3])
    nodes = {node.node_id: node for node in graph.nodes}
    expected = sorted({evidence for node_id in node_ids[:3] for evidence in nodes[node_id].evidence_ids})
    assert list(result.supporting_evidence_ids) == expected
    assert result.predicted_stage not in result.supporting_evidence_ids
    assert result.to_dict()["prediction_is_evidence"] is False


def test_nodes_must_be_bound_to_one_correlated_incident() -> None:
    graph, correlation, node_ids, incident_id = _fixture()
    with pytest.raises(ValueError, match="not_bound_to_incident"):
        attack_prediction.predict_next_stage(
            graph,
            correlation,
            incident_id=incident_id,
            observed_node_ids=(node_ids[0], "node-from-another-incident"),
        )


def test_missing_incident_and_duplicate_nodes_fail_closed() -> None:
    graph, correlation, node_ids, incident_id = _fixture()
    with pytest.raises(ValueError, match="incident_not_found"):
        attack_prediction.predict_next_stage(graph, correlation, incident_id="missing", observed_node_ids=node_ids[:2])
    with pytest.raises(ValueError, match="observed_nodes_invalid"):
        attack_prediction.predict_next_stage(graph, correlation, incident_id=incident_id, observed_node_ids=(node_ids[0], node_ids[0]))


def test_invalid_correlation_is_rejected() -> None:
    graph, correlation, node_ids, incident_id = _fixture()
    broken = deepcopy(correlation.to_dict())
    broken["source_graph_digest"] = "0" * 64
    invalid = incident_correlation.CorrelationResult.from_dict(broken)
    with pytest.raises(ValueError, match="source_correlation_invalid"):
        attack_prediction.predict_next_stage(graph, invalid, incident_id=incident_id, observed_node_ids=node_ids[:2])


def test_validation_rejects_prediction_as_evidence_or_authority() -> None:
    graph, correlation, node_ids, incident_id = _fixture()
    payload = attack_prediction.predict_next_stage(graph, correlation, incident_id=incident_id, observed_node_ids=node_ids[:3]).to_dict()
    payload["prediction_is_evidence"] = True
    payload["remediation_execution"] = True
    validation = attack_prediction.validate_result(payload)
    assert not validation.passed
    assert "prediction:prediction_is_evidence_must_be_false" in validation.failures
    assert "prediction:remediation_execution_must_be_false" in validation.failures


def test_all_authority_fields_remain_false() -> None:
    result = attack_prediction.self_check()
    assert result["advisory_only"] is True
    for field in attack_prediction.FALSE_AUTHORITY_FIELDS:
        assert result[field] is False

from __future__ import annotations

from copy import deepcopy

import pytest

from sentinel import confidence_gate as gate
from sentinel import incident_correlation


def _context():
    graph = incident_correlation.demo_graph()
    correlation = incident_correlation.IncidentCorrelator(max_time_delta=120.0).correlate(graph)
    incident = next(item for item in correlation.incidents if len(item.node_ids) == 3)
    return graph, correlation, incident


def _candidate(incident_id: str, **overrides) -> gate.RecommendationCandidate:
    values = {
        "candidate_id": "candidate-test",
        "incident_id": incident_id,
        "action": "QUARANTINE",
        "severity": "HIGH",
        "evidence_strength": "STRONG",
        "confidence": 0.92,
        "reversibility": "REVERSIBLE",
        "potential_damage": "MEDIUM",
        "evidence_ids": ("ev-script", "ev-detection"),
        "rationale": "Controlled confidence-gate test fixture.",
    }
    values.update(overrides)
    return gate.RecommendationCandidate(**values)


def test_self_check_is_green_read_only_and_never_grants_authority() -> None:
    result = gate.self_check()
    assert result["passed"] is True
    assert result["recommend_outcome"] == gate.OUTCOME_RECOMMEND
    assert result["review_outcome"] == gate.OUTCOME_REVIEW
    assert result["blocked_outcome"] == gate.OUTCOME_BLOCKED
    assert result["stable_round_trip"] is True
    assert result["source_graph_unchanged"] is True
    assert result["source_correlation_unchanged"] is True
    assert result["missing_confidence_inferred"] is False
    assert result["authority_granted"] is False
    assert result["execution_authority_added"] is False
    assert result["automatic_quarantine"] is False
    assert result["automatic_repair"] is False
    assert result["automatic_restore"] is False
    assert result["terminate_process_authorized"] is False
    assert result["trust_allowlist_mutation_authorized"] is False


def test_strong_supported_evidence_can_be_recommended_but_not_authorized() -> None:
    graph, correlation, incident = _context()
    decision = gate.ConfidenceGate().evaluate(
        candidate=_candidate(incident.incident_id),
        correlation=correlation,
        graph=graph,
    )
    assert decision.outcome == gate.OUTCOME_RECOMMEND
    assert decision.authority_granted is False
    assert decision.matched_evidence_ids == ("ev-detection", "ev-script")
    assert any("advisory" in reason.lower() for reason in decision.reasons)
    assert gate.validate_decision(decision, correlation, graph).passed is True


def test_missing_evidence_and_confidence_fail_closed() -> None:
    graph, correlation, incident = _context()
    candidate = _candidate(
        incident.incident_id,
        evidence_strength="NONE",
        confidence=None,
        evidence_ids=(),
    )
    decision = gate.ConfidenceGate().evaluate(
        candidate=candidate,
        correlation=correlation,
        graph=graph,
    )
    assert decision.outcome == gate.OUTCOME_BLOCKED
    assert decision.authority_granted is False
    assert any("never inferred" in reason for reason in decision.reasons)


def test_unsupported_evidence_reference_fails_closed() -> None:
    graph, correlation, incident = _context()
    candidate = _candidate(
        incident.incident_id,
        evidence_ids=("ev-script", "ev-invented"),
    )
    decision = gate.ConfidenceGate().evaluate(
        candidate=candidate,
        correlation=correlation,
        graph=graph,
    )
    assert decision.outcome == gate.OUTCOME_BLOCKED
    assert "ev-invented" not in decision.matched_evidence_ids
    assert any("not bound" in reason for reason in decision.reasons)


def test_high_damage_or_irreversibility_requires_review() -> None:
    graph, correlation, incident = _context()
    high_damage = gate.ConfidenceGate().evaluate(
        candidate=_candidate(incident.incident_id, potential_damage="HIGH"),
        correlation=correlation,
        graph=graph,
    )
    irreversible = gate.ConfidenceGate().evaluate(
        candidate=_candidate(incident.incident_id, reversibility="IRREVERSIBLE"),
        correlation=correlation,
        graph=graph,
    )
    assert high_damage.outcome == gate.OUTCOME_REVIEW
    assert irreversible.outcome == gate.OUTCOME_REVIEW
    assert high_damage.authority_granted is False
    assert irreversible.authority_granted is False


def test_low_confidence_blocks_even_when_evidence_is_strong() -> None:
    graph, correlation, incident = _context()
    decision = gate.ConfidenceGate().evaluate(
        candidate=_candidate(incident.incident_id, confidence=0.59),
        correlation=correlation,
        graph=graph,
    )
    assert decision.outcome == gate.OUTCOME_BLOCKED
    assert any("fail-closed minimum" in reason for reason in decision.reasons)


def test_moderate_evidence_is_review_not_recommend() -> None:
    graph, correlation, incident = _context()
    decision = gate.ConfidenceGate().evaluate(
        candidate=_candidate(incident.incident_id, evidence_strength="MODERATE"),
        correlation=correlation,
        graph=graph,
    )
    assert decision.outcome == gate.OUTCOME_REVIEW
    assert decision.authority_granted is False


def test_low_severity_disruptive_action_requires_review() -> None:
    graph, correlation, incident = _context()
    decision = gate.ConfidenceGate().evaluate(
        candidate=_candidate(incident.incident_id, severity="LOW"),
        correlation=correlation,
        graph=graph,
    )
    assert decision.outcome == gate.OUTCOME_REVIEW


def test_unknown_incident_and_invalid_candidate_fail_closed() -> None:
    graph, correlation, incident = _context()
    with pytest.raises(ValueError, match="confidence_gate_incident_unknown"):
        gate.ConfidenceGate().evaluate(
            candidate=_candidate("incident:missing"),
            correlation=correlation,
            graph=graph,
        )

    invalid = _candidate(incident.incident_id, confidence=1.5)
    with pytest.raises(ValueError, match="confidence_gate_candidate_invalid"):
        gate.ConfidenceGate().evaluate(
            candidate=invalid,
            correlation=correlation,
            graph=graph,
        )


def test_gate_is_deterministic_round_trip_stable_and_sources_unchanged() -> None:
    graph, correlation, incident = _context()
    graph_before = graph.stable_json()
    correlation_before = correlation.stable_json()
    candidate = _candidate(incident.incident_id)
    first = gate.ConfidenceGate().evaluate(candidate=candidate, correlation=correlation, graph=graph)
    second = gate.ConfidenceGate().evaluate(candidate=candidate, correlation=correlation, graph=graph)
    restored = gate.GateDecision.from_dict(first.to_dict())
    assert first.stable_json() == second.stable_json()
    assert first.digest() == second.digest()
    assert restored.stable_json() == first.stable_json()
    assert graph.stable_json() == graph_before
    assert correlation.stable_json() == correlation_before


def test_validation_rejects_any_authority_grant() -> None:
    graph, correlation, incident = _context()
    decision = gate.ConfidenceGate().evaluate(
        candidate=_candidate(incident.incident_id),
        correlation=correlation,
        graph=graph,
    ).to_dict()
    tampered = deepcopy(decision)
    tampered["authority_granted"] = True
    validation = gate.validate_decision(tampered, correlation, graph)
    assert validation.passed is False
    assert "confidence_gate:authority_granted_must_be_false" in validation.failures


def test_validation_rejects_forged_recommendation_below_threshold() -> None:
    graph, correlation, incident = _context()
    decision = gate.ConfidenceGate().evaluate(
        candidate=_candidate(incident.incident_id),
        correlation=correlation,
        graph=graph,
    ).to_dict()
    forged = deepcopy(decision)
    forged["candidate"]["confidence"] = 0.70
    validation = gate.validate_decision(forged, correlation, graph)
    assert validation.passed is False
    assert "confidence_gate:recommend_requires_confidence_threshold" in validation.failures

from __future__ import annotations

from copy import deepcopy

from sentinel import confidence_gate
from sentinel import explainable_security as explain


def _context():
    return explain._self_check_context()


def test_self_check_is_green_deterministic_evidence_grounded_and_read_only() -> None:
    result = explain.self_check()
    assert result["passed"] is True
    assert result["all_positive_claims_evidence_bound"] is True
    assert result["user_explanation_present"] is True
    assert result["technical_explanation_present"] is True
    assert result["uncertainty_notes_present"] is True
    assert result["stable_round_trip"] is True
    assert result["deterministic_serialization"] is True
    assert result["source_graph_unchanged"] is True
    assert result["source_correlation_unchanged"] is True
    assert result["source_decision_unchanged"] is True
    assert result["authority_granted"] is False
    assert result["confidence_amplified"] is False
    assert result["unsupported_positive_claims_allowed"] is False


def test_generates_user_and_technical_explanations_from_same_sources() -> None:
    graph, correlation, decision = _context()
    output = explain.ExplainableSecurityEngine().generate(
        decision=decision,
        correlation=correlation,
        graph=graph,
    )
    assert output.decision_outcome == confidence_gate.OUTCOME_RECOMMEND
    assert decision.outcome in output.user_explanation
    assert output.incident_id in output.technical_explanation
    assert output.source_graph_digest in output.technical_explanation
    assert output.source_correlation_digest in output.technical_explanation
    assert output.source_decision_digest in output.technical_explanation
    assert "authority_granted=false" in output.technical_explanation


def test_every_positive_claim_is_bound_to_incident_evidence() -> None:
    graph, correlation, decision = _context()
    output = explain.ExplainableSecurityEngine().generate(
        decision=decision,
        correlation=correlation,
        graph=graph,
    )
    positive = [claim for claim in output.claims if claim.claim_type != "LIMITATION"]
    assert positive
    assert all(claim.evidence_ids for claim in positive)
    assert explain.validate_explanation(output, decision, correlation, graph).passed is True


def test_explanation_is_deterministic_and_round_trip_stable() -> None:
    graph, correlation, decision = _context()
    engine = explain.ExplainableSecurityEngine()
    first = engine.generate(decision=decision, correlation=correlation, graph=graph)
    second = engine.generate(decision=decision, correlation=correlation, graph=graph)
    restored = explain.IncidentExplanation.from_dict(first.to_dict())
    assert first.stable_json() == second.stable_json()
    assert first.digest() == second.digest()
    assert restored.stable_json() == first.stable_json()


def test_generation_does_not_mutate_graph_correlation_or_decision() -> None:
    graph, correlation, decision = _context()
    graph_before = graph.digest()
    correlation_before = correlation.digest()
    decision_before = decision.digest()
    explain.ExplainableSecurityEngine().generate(
        decision=decision,
        correlation=correlation,
        graph=graph,
    )
    assert graph.digest() == graph_before
    assert correlation.digest() == correlation_before
    assert decision.digest() == decision_before


def test_validation_rejects_unbound_evidence_claim() -> None:
    graph, correlation, decision = _context()
    payload = explain.ExplainableSecurityEngine().generate(
        decision=decision,
        correlation=correlation,
        graph=graph,
    ).to_dict()
    broken = deepcopy(payload)
    target = next(claim for claim in broken["claims"] if claim["claim_type"] == "OBSERVATION")
    target["evidence_ids"] = ["ev-not-in-incident"]
    validation = explain.validate_explanation(broken, decision, correlation, graph)
    assert validation.passed is False
    assert any("unsupported_evidence_binding" in failure for failure in validation.failures)


def test_validation_rejects_authority_or_confidence_expansion() -> None:
    graph, correlation, decision = _context()
    payload = explain.ExplainableSecurityEngine().generate(
        decision=decision,
        correlation=correlation,
        graph=graph,
    ).to_dict()
    broken = deepcopy(payload)
    broken["authority_granted"] = True
    broken["execution_authority_added"] = True
    broken["confidence_amplified"] = True
    validation = explain.validate_explanation(broken, decision, correlation, graph)
    assert validation.passed is False
    assert "explanation:authority_granted_must_be_false" in validation.failures
    assert "explanation:execution_authority_added" in validation.failures
    assert "explanation:confidence_amplification_forbidden" in validation.failures


def test_validation_rejects_missing_uncertainty_or_limitation() -> None:
    graph, correlation, decision = _context()
    payload = explain.ExplainableSecurityEngine().generate(
        decision=decision,
        correlation=correlation,
        graph=graph,
    ).to_dict()
    broken = deepcopy(payload)
    broken["uncertainty_notes"] = []
    broken["claims"] = [claim for claim in broken["claims"] if claim["claim_type"] != "LIMITATION"]
    validation = explain.validate_explanation(broken, decision, correlation, graph)
    assert validation.passed is False
    assert "explanation:uncertainty_notes_invalid" in validation.failures
    assert "explanation:limitation_claim_required" in validation.failures


def test_validation_rejects_source_digest_tamper() -> None:
    graph, correlation, decision = _context()
    payload = explain.ExplainableSecurityEngine().generate(
        decision=decision,
        correlation=correlation,
        graph=graph,
    ).to_dict()
    broken = deepcopy(payload)
    broken["source_graph_digest"] = "0" * 64
    broken["source_correlation_digest"] = "1" * 64
    broken["source_decision_digest"] = "2" * 64
    validation = explain.validate_explanation(broken, decision, correlation, graph)
    assert validation.passed is False
    assert "explanation:source_graph_digest_mismatch" in validation.failures
    assert "explanation:source_correlation_digest_mismatch" in validation.failures
    assert "explanation:source_decision_digest_mismatch" in validation.failures


def test_explainable_security_contract_never_adds_remediation_authority() -> None:
    result = explain.self_check()
    assert result["automatic_quarantine"] is False
    assert result["automatic_repair"] is False
    assert result["automatic_restore"] is False
    assert result["general_home_execution_authorized"] is False
    assert result["delete_authorized"] is False
    assert result["repair_authorized"] is False
    assert result["terminate_process_authorized"] is False
    assert result["trust_allowlist_mutation_authorized"] is False

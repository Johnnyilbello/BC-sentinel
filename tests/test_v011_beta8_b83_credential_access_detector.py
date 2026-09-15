from __future__ import annotations

import json

import pytest

from sentinel import credential_access_detector, incident_correlation, security_graph


def test_b83_self_check_is_green_and_keeps_partial_coverage() -> None:
    result = credential_access_detector.self_check()
    assert result["passed"] is True
    assert result["target_scenario_id"] == "B7-CREDENTIAL-001"
    assert result["coverage_status"] == "PARTIAL"
    assert result["positive_outcome"] == "DETECTED"
    assert result["admin_outcome"] == "REVIEW_REQUIRED"
    assert result["benign_outcome"] == "NO_MATCH"
    assert result["sensitive_input_rejected"] is True
    assert result["evidence_ids_preserved"] is True
    assert result["stable_round_trip"] is True
    assert result["deterministic_serialization"] is True


def test_positive_fixture_is_metadata_only_and_detected() -> None:
    observations = credential_access_detector.positive_fixture()
    result = credential_access_detector.detect(observations)
    assert result.outcome == credential_access_detector.OUTCOME_DETECTED
    assert result.score >= credential_access_detector.DETECT_SCORE
    assert credential_access_detector.SIGNAL_PROTECTED_AUTH_TARGET in result.matched_signals
    assert credential_access_detector.SIGNAL_CREDENTIAL_STORE_TARGET in result.matched_signals
    payload = result.to_dict()
    assert payload["metadata_only"] is True
    assert payload["credential_access"] is False
    assert payload["credential_material_collected"] is False
    assert payload["credential_values_serialized"] is False
    assert payload["credential_values_emitted"] is False


def test_approved_security_fixture_never_becomes_detected() -> None:
    result = credential_access_detector.detect(credential_access_detector.admin_fixture())
    assert result.outcome == credential_access_detector.OUTCOME_REVIEW
    assert "APPROVED_SECURITY_TOOL" in result.suppressor_reasons
    assert "MAINTENANCE_WINDOW" in result.suppressor_reasons
    assert "SIGNED_ADMIN_WORKFLOW" in result.suppressor_reasons


def test_benign_fixture_is_no_match() -> None:
    result = credential_access_detector.detect(credential_access_detector.benign_fixture())
    assert result.outcome == credential_access_detector.OUTCOME_NO_MATCH
    assert result.score == 0
    assert result.matched_signals == ()


def test_secret_bearing_provenance_is_rejected_before_detection() -> None:
    fixture = credential_access_detector.rejected_secret_bearing_fixture()
    validation = credential_access_detector.validate_observations(fixture)
    assert validation.passed is False
    assert any("secret_bearing_provenance_rejected" in item for item in validation.failures)
    with pytest.raises(ValueError, match="credential_access_detector_invalid_input"):
        credential_access_detector.detect(fixture)


def test_result_serialization_is_stable_and_order_independent() -> None:
    fixture = credential_access_detector.positive_fixture()
    first = credential_access_detector.detect(fixture)
    second = credential_access_detector.detect(tuple(reversed(fixture)))
    assert first.stable_json() == second.stable_json()
    assert first.digest() == second.digest()
    restored = credential_access_detector.DetectionResult.from_dict(json.loads(first.stable_json()))
    assert restored.to_dict() == first.to_dict()


def test_graph_preserves_evidence_without_secret_material() -> None:
    fixture = credential_access_detector.positive_fixture()
    result = credential_access_detector.detect(fixture)
    graph = credential_access_detector.build_evidence_graph(fixture, result)
    validation = security_graph.validate_graph(graph.to_dict())
    assert validation.passed is True
    observed_evidence = {evidence_id for node in graph.nodes for evidence_id in node.evidence_ids}
    assert set(result.evidence_ids).issubset(observed_evidence)
    serialized = json.dumps(graph.to_dict(), sort_keys=True).lower()
    assert "[redacted]" not in serialized
    assert "password" not in serialized


def test_graph_correlates_with_accepted_incident_engine() -> None:
    fixture = credential_access_detector.positive_fixture()
    result = credential_access_detector.detect(fixture)
    graph = credential_access_detector.build_evidence_graph(fixture, result)
    correlation = credential_access_detector.correlate_evidence_graph(graph)
    validation = incident_correlation.validate_result(correlation, graph)
    assert validation.passed is True
    assert correlation.source_graph_digest == graph.digest()
    assert len(correlation.incidents) >= 1


def test_all_authority_and_credential_access_flags_remain_false() -> None:
    payload = credential_access_detector.detect(
        credential_access_detector.positive_fixture()
    ).to_dict()
    for field_name in credential_access_detector.FALSE_SAFETY_FIELDS:
        assert payload[field_name] is False, field_name
    assert payload["read_only"] is True
    assert payload["synthetic_fixture_only"] is True
    assert payload["metadata_only"] is True


def test_invalid_duplicate_evidence_fails_closed() -> None:
    first = credential_access_detector.CredentialIndicatorObservation(
        event_id="dup-1",
        observed_at=1.0,
        source_surface="fixture/a",
        evidence_id="ev-dup",
        provenance={
            "source": "fixture",
            "source_id": "dup-1",
            "collector": "test",
            "trust": "DIRECT",
        },
    )
    second = credential_access_detector.CredentialIndicatorObservation(
        event_id="dup-2",
        observed_at=2.0,
        source_surface="fixture/b",
        evidence_id="ev-dup",
        provenance={
            "source": "fixture",
            "source_id": "dup-2",
            "collector": "test",
            "trust": "DIRECT",
        },
    )
    validation = credential_access_detector.validate_observations((first, second))
    assert validation.passed is False
    assert "observation[1]:duplicate_evidence_id" in validation.failures

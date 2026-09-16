from __future__ import annotations

import copy

import pytest

from sentinel import beta10_attack_story as story
from sentinel import beta9_ransomware_controls, incident_correlation, security_graph


def _prov(trust: str = "DIRECT") -> dict[str, str]:
    return {"source": "b102-test", "source_id": "fixture", "collector": "pytest", "trust": trust}


def _full_graph() -> tuple[security_graph.SecurityGraph, incident_correlation.CorrelationResult]:
    builder = security_graph.SecurityGraphBuilder()
    specs = (
        ("PROCESS", "Entry observation", 10.0, "ENTRY_POINT", "e-entry", "DIRECT"),
        ("SCRIPT", "Execution observation", 11.0, None, "e-exec", "DIRECT"),
        ("PERSISTENCE", "Persistence observation", 12.0, None, "e-persist", "DIRECT"),
        ("FILE", "File activity observation", 13.0, None, "e-file", "DIRECT"),
        ("DNS", "Network observation", 14.0, None, "e-net", "DIRECT"),
        ("DETECTION", "Detector observation", 15.0, None, "e-detect", "DERIVED"),
        ("ACTION", "Response proposal observation", 16.0, None, "e-response", "DIRECT"),
    )
    nodes = []
    for index, (kind, label, at, explicit, evidence_id, trust) in enumerate(specs):
        attributes = {"correlation_keys": ["incident:test"]}
        if explicit:
            attributes["attack_story_stage"] = explicit
        node = builder.ingest_observation(
            {
                "node_type": kind,
                "identity": {"i": index},
                "label": label,
                "observed_at": at,
                "provenance": _prov(trust),
                "evidence_ids": [evidence_id],
                "confidence": 0.9 if kind != "DETECTION" else 0.8,
                "attributes": attributes,
            }
        )
        nodes.append(node)
    for left, right in zip(nodes, nodes[1:]):
        builder.link(
            edge_type="OBSERVED_WITH",
            source=left.node_id,
            target=right.node_id,
            observed_at=max(left.observed_at, right.observed_at),
            provenance=_prov("DERIVED"),
            evidence_ids=[left.evidence_ids[0], right.evidence_ids[0]],
            confidence=0.8,
            reason="Controlled B10-2 relationship fixture.",
        )
    graph = builder.build(graph_id="b102-full", incident_id="b102-full", created_at=16.0, metadata={"fixture": True})
    correlation = incident_correlation.IncidentCorrelator(max_time_delta=30.0).correlate(graph)
    assert len(correlation.incidents) == 1
    return graph, correlation


def _partial_graph() -> tuple[security_graph.SecurityGraph, incident_correlation.CorrelationResult]:
    builder = security_graph.SecurityGraphBuilder()
    evidence = builder.ingest_observation(
        {
            "node_type": "EVIDENCE",
            "identity": {"id": "live-file"},
            "label": "Controlled file activity",
            "observed_at": 100.0,
            "provenance": _prov("DIRECT"),
            "evidence_ids": ["e-live-file"],
            "confidence": 1.0,
            "attributes": {"write_event_count": 24, "rename_event_count": 18, "correlation_keys": ["b102:partial"]},
        }
    )
    detection = builder.ingest_observation(
        {
            "node_type": "DETECTION",
            "identity": {"id": "detector"},
            "label": "Ransomware-like detector",
            "observed_at": 100.1,
            "provenance": _prov("DERIVED"),
            "evidence_ids": ["e-live-file"],
            "confidence": 1.0,
            "attributes": {"correlation_keys": ["b102:partial"]},
        }
    )
    builder.link(
        edge_type="SUPPORTED_BY",
        source=detection.node_id,
        target=evidence.node_id,
        observed_at=100.1,
        provenance=_prov("DERIVED"),
        evidence_ids=["e-live-file"],
        confidence=1.0,
        reason="Detector supported by controlled file activity.",
    )
    graph = builder.build(graph_id="b102-partial", incident_id="b102-partial", created_at=100.1, metadata={"fixture": True})
    correlation = incident_correlation.IncidentCorrelator(max_time_delta=30.0).correlate(graph)
    return graph, correlation


def _b93_evidence() -> dict:
    def row(
        control_id: str,
        writes: int,
        renames: int,
        entropy: float,
        extension: bool,
        canary: bool,
        admin: bool,
        started: str,
        completed: str,
    ) -> dict:
        return {
            "control_id": control_id,
            "live_observation": True,
            "sandbox_scope": "DEDICATED_TEMP_DIRECTORY",
            "observer_backend": "WATCHDOG_LOCAL_FILESYSTEM",
            "write_event_count": writes,
            "rename_event_count": renames,
            "entropy_delta": entropy,
            "extension_changed": extension,
            "canary_touched": canary,
            "known_backup_workflow": admin,
            "user_initiated_bulk_operation": admin,
            "started_at_utc": started,
            "completed_at_utc": completed,
            "cleanup_state": "CLEAN",
        }

    return {
        "schema": beta9_ransomware_controls.SCHEMA,
        "source": beta9_ransomware_controls.SOURCE,
        "controls": [
            row("positive-ransomware-like", 24, 18, 0.75, True, True, False, "2026-09-16T12:00:00Z", "2026-09-16T12:00:02Z"),
            row("administrative-backup-like", 24, 18, 0.75, True, False, True, "2026-09-16T12:00:03Z", "2026-09-16T12:00:05Z"),
            row("benign-save", 2, 0, 0.0, False, False, False, "2026-09-16T12:00:06Z", "2026-09-16T12:00:07Z"),
        ],
        "boundaries": dict(beta9_ransomware_controls.BOUNDARIES),
    }


def test_full_story_maps_all_explicit_supported_stages() -> None:
    graph, correlation = _full_graph()
    result = story.generate_story(graph=graph, correlation=correlation).to_dict()
    validation = story.validate_story(result, graph=graph, correlation=correlation)
    assert validation["passed"]
    assert validation["observed_stage_count"] == 7
    assert validation["unknown_stage_count"] == 0
    assert [row["status"] for row in result["stages"]] == ["OBSERVED"] * 7


def test_partial_story_keeps_unproven_stages_unknown() -> None:
    graph, correlation = _partial_graph()
    result = story.generate_story(graph=graph, correlation=correlation).to_dict()
    observed = {row["stage_id"] for row in result["stages"] if row["status"] == "OBSERVED"}
    unknown = {row["stage_id"] for row in result["stages"] if row["status"] == "UNKNOWN"}
    assert observed == {"FILE_ACTIVITY", "DETECTION"}
    assert unknown == {"ENTRY_POINT", "EXECUTION", "PERSISTENCE", "NETWORK_ACTIVITY", "RESPONSE"}
    assert "UNKNOWN" in result["plain_language_summary"]


def test_unknown_stage_cannot_carry_invented_evidence() -> None:
    graph, correlation = _partial_graph()
    payload = story.generate_story(graph=graph, correlation=correlation).to_dict()
    target = next(row for row in payload["stages"] if row["stage_id"] == "ENTRY_POINT")
    target["evidence_ids"] = ["invented"]
    target["node_ids"] = [correlation.incidents[0].node_ids[0]]
    validation = story.validate_story(payload, graph=graph, correlation=correlation)
    assert not validation["passed"]
    assert any("unknown_contains_evidence" in item for item in validation["failures"])


def test_claims_must_be_bound_to_incident_evidence() -> None:
    graph, correlation = _full_graph()
    payload = story.generate_story(graph=graph, correlation=correlation).to_dict()
    payload["claims"][0]["evidence_ids"] = ["outside-incident"]
    validation = story.validate_story(payload, graph=graph, correlation=correlation)
    assert not validation["passed"]
    assert "story:claim_evidence_invalid" in validation["failures"]


def test_story_is_deterministic_and_does_not_mutate_sources() -> None:
    graph, correlation = _full_graph()
    graph_digest = graph.digest()
    correlation_digest = correlation.digest()
    first = story.generate_story(graph=graph, correlation=correlation).to_dict()
    second = story.generate_story(graph=graph, correlation=correlation).to_dict()
    assert first == second
    assert graph.digest() == graph_digest
    assert correlation.digest() == correlation_digest


def test_story_preserves_authority_privacy_and_coverage_boundaries() -> None:
    graph, correlation = _partial_graph()
    payload = story.generate_story(graph=graph, correlation=correlation).to_dict()
    assert payload["coverage_summary"] == {"PARTIAL": 5, "GAP": 0, "VERIFIED": 1}
    assert payload["coverage_changed"] is False
    assert payload["broad_protection_claimed"] is False
    assert payload["read_only"] is True
    assert not any(payload["authority_boundary"].values())
    assert payload["privacy"] == story.PRIVACY_BOUNDARY


def test_entry_point_requires_explicit_evidence_not_process_inference() -> None:
    graph, correlation = _partial_graph()
    payload = story.generate_story(graph=graph, correlation=correlation).to_dict()
    entry = next(row for row in payload["stages"] if row["stage_id"] == "ENTRY_POINT")
    assert entry["status"] == "UNKNOWN"
    assert entry["evidence_ids"] == []


def test_b93_accepted_evidence_builds_live_bound_attack_story() -> None:
    evidence = _b93_evidence()
    payload = story.story_from_b93_evidence(evidence)
    assert payload["passed"]
    assert payload["source_live_control"] is True
    assert payload["source_detector_outcome"] == "DETECTED"
    assert payload["source_detector_score"] == 10
    assert payload["detector_to_security_graph_bound"] is True
    assert payload["security_graph_to_incident_bound"] is True
    observed = {row["stage_id"] for row in payload["stages"] if row["status"] == "OBSERVED"}
    assert observed == {"FILE_ACTIVITY", "DETECTION"}
    assert payload["synthetic_fallback_used"] is False


def test_b93_story_rejects_invalid_or_unclean_evidence() -> None:
    evidence = _b93_evidence()
    evidence["controls"][0]["cleanup_state"] = "DIRTY"
    payload = story.story_from_b93_evidence(evidence)
    assert not payload["passed"]
    assert payload["failures"] == ["story:b93_live_evidence_not_accepted"]


def test_relationships_are_exact_graph_edges_not_generated_causality() -> None:
    graph, correlation = _full_graph()
    payload = story.generate_story(graph=graph, correlation=correlation).to_dict()
    assert {row["edge_id"] for row in payload["relationships"]} == set(correlation.incidents[0].graph_edge_ids)
    assert all(row["reason"] == "Controlled B10-2 relationship fixture." for row in payload["relationships"])


def test_tampered_source_digest_fails_validation() -> None:
    graph, correlation = _full_graph()
    payload = story.generate_story(graph=graph, correlation=correlation).to_dict()
    payload["source_graph_digest"] = "0" * 64
    validation = story.validate_story(payload, graph=graph, correlation=correlation)
    assert not validation["passed"]
    assert "story:graph_digest_mismatch" in validation["failures"]


def test_multiple_incidents_require_explicit_selection() -> None:
    graph, correlation = _full_graph()
    extra = incident_correlation.CorrelationResult(
        source_graph_id=correlation.source_graph_id,
        source_graph_digest=correlation.source_graph_digest,
        max_time_delta=correlation.max_time_delta,
        incidents=(correlation.incidents[0], copy.deepcopy(correlation.incidents[0])),
    )
    with pytest.raises(ValueError, match="incident_id_required"):
        story.generate_story(graph=graph, correlation=extra)

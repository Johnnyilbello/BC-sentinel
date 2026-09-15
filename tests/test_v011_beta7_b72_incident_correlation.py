from __future__ import annotations

from copy import deepcopy

import pytest

from sentinel import incident_correlation as correlation
from sentinel import security_graph


def _provenance(source_id: str) -> dict:
    return {
        "source": "b72-test-fixture",
        "source_id": source_id,
        "collector": "tests.test_v011_beta7_b72_incident_correlation",
        "trust": "DIRECT",
    }


def _node(
    node_id: str,
    node_type: str,
    observed_at: float,
    *,
    evidence_ids: tuple[str, ...] = (),
    correlation_keys: list[str] | None = None,
) -> security_graph.GraphNode:
    attributes = {"fixture": True}
    if correlation_keys is not None:
        attributes["correlation_keys"] = correlation_keys
    return security_graph.GraphNode(
        node_id=node_id,
        node_type=node_type,
        label=node_id,
        observed_at=observed_at,
        provenance=_provenance(node_id),
        evidence_ids=evidence_ids,
        confidence=0.8,
        attributes=attributes,
    )


def _build_graph(nodes: list[security_graph.GraphNode], edges: list[dict] | None = None) -> security_graph.SecurityGraph:
    builder = security_graph.SecurityGraphBuilder()
    for node in nodes:
        builder.add_node(node)
    for edge in edges or []:
        builder.link(**edge)
    return builder.build(
        graph_id="graph-b72-test",
        incident_id="uncorrelated-batch",
        created_at=1000.0,
        metadata={"fixture": True},
    )


def _edge(source: str, target: str, edge_type: str = "TRIGGERED") -> dict:
    return {
        "edge_type": edge_type,
        "source": source,
        "target": target,
        "observed_at": 3.0,
        "provenance": _provenance(f"edge-{source}-{target}"),
        "evidence_ids": [f"ev-edge-{source}-{target}"],
        "confidence": 0.9,
        "reason": "Controlled explicit Security Graph relation.",
    }


def test_self_check_is_green_deterministic_and_read_only() -> None:
    result = correlation.self_check()
    assert result["passed"] is True
    assert result["incident_sizes"] == [1, 3]
    assert result["source_graph_unchanged"] is True
    assert result["stable_round_trip"] is True
    assert result["deterministic_serialization"] is True
    assert result["every_correlation_link_explained"] is True
    assert result["temporal_proximity_alone_correlates"] is False
    assert result["execution_authority_added"] is False
    assert result["automatic_quarantine"] is False
    assert result["automatic_repair"] is False
    assert result["automatic_restore"] is False
    assert result["terminate_process_authorized"] is False
    assert result["trust_allowlist_mutation_authorized"] is False


def test_existing_graph_chain_becomes_one_incident_and_unrelated_node_stays_separate() -> None:
    graph = _build_graph(
        [
            _node("process", "PROCESS", 1.0),
            _node("script", "SCRIPT", 2.0),
            _node("detection", "DETECTION", 3.0),
            _node("dns-unrelated", "DNS", 3.1),
        ],
        [_edge("process", "script", "EXECUTED"), _edge("script", "detection")],
    )
    result = correlation.IncidentCorrelator(max_time_delta=30.0).correlate(graph)
    groups = sorted(sorted(item.node_ids) for item in result.incidents)
    assert groups == [["detection", "process", "script"], ["dns-unrelated"]]
    assert correlation.validate_result(result, graph).passed is True


def test_shared_evidence_correlates_only_inside_time_window() -> None:
    near = _build_graph(
        [
            _node("file", "FILE", 10.0, evidence_ids=("ev-shared",)),
            _node("detection", "DETECTION", 20.0, evidence_ids=("ev-shared",)),
        ]
    )
    correlated = correlation.IncidentCorrelator(max_time_delta=15.0).correlate(near)
    assert len(correlated.incidents) == 1
    assert any(
        link.rule == correlation.RULE_SHARED_EVIDENCE
        for link in correlated.incidents[0].links
    )

    far = _build_graph(
        [
            _node("file", "FILE", 10.0, evidence_ids=("ev-shared",)),
            _node("detection", "DETECTION", 40.0, evidence_ids=("ev-shared",)),
        ]
    )
    separated = correlation.IncidentCorrelator(max_time_delta=15.0).correlate(far)
    assert len(separated.incidents) == 2


def test_explicit_correlation_key_correlates_with_explanation() -> None:
    graph = _build_graph(
        [
            _node("process", "PROCESS", 1.0, correlation_keys=["session:abc"]),
            _node("dns", "DNS", 2.0, correlation_keys=["session:abc"]),
        ]
    )
    result = correlation.IncidentCorrelator(max_time_delta=5.0).correlate(graph)
    assert len(result.incidents) == 1
    links = result.incidents[0].links
    assert any(link.rule == correlation.RULE_EXPLICIT_KEY for link in links)
    assert all(link.reason.strip() for link in links)


def test_temporal_proximity_alone_never_correlates() -> None:
    graph = _build_graph(
        [
            _node("process", "PROCESS", 1.0),
            _node("dns", "DNS", 1.01),
            _node("file", "FILE", 1.02),
        ]
    )
    result = correlation.IncidentCorrelator(max_time_delta=999.0).correlate(graph)
    assert len(result.incidents) == 3
    assert all(not incident.links for incident in result.incidents)


def test_graph_edge_correlation_is_not_discarded_by_time_window() -> None:
    graph = _build_graph(
        [_node("process", "PROCESS", 1.0), _node("file", "FILE", 900.0)],
        [_edge("process", "file", "CREATED")],
    )
    result = correlation.IncidentCorrelator(max_time_delta=1.0).correlate(graph)
    assert len(result.incidents) == 1
    link = next(link for link in result.incidents[0].links if link.rule == correlation.RULE_GRAPH_EDGE)
    assert link.source_edge_id is not None
    assert "Security Graph relation CREATED" in link.reason


def test_malformed_explicit_correlation_keys_fail_closed() -> None:
    bad = _node("process", "PROCESS", 1.0, correlation_keys=["valid"])
    payload = bad.to_dict()
    payload["attributes"]["correlation_keys"] = ["", 7]
    malformed = security_graph.GraphNode.from_dict(payload)
    graph = _build_graph([malformed, _node("dns", "DNS", 2.0)])
    with pytest.raises(ValueError, match="incident_correlation_keys_invalid:process"):
        correlation.IncidentCorrelator().correlate(graph)


def test_source_graph_digest_is_preserved_and_source_is_not_mutated() -> None:
    graph = _build_graph(
        [_node("process", "PROCESS", 1.0), _node("script", "SCRIPT", 2.0)],
        [_edge("process", "script", "EXECUTED")],
    )
    before_json = graph.stable_json()
    before_digest = graph.digest()
    result = correlation.IncidentCorrelator().correlate(graph)
    assert graph.stable_json() == before_json
    assert graph.digest() == before_digest
    assert result.source_graph_digest == before_digest


def test_correlation_is_deterministic_and_round_trip_stable() -> None:
    graph = _build_graph(
        [
            _node("z-process", "PROCESS", 1.0, evidence_ids=("ev-shared",)),
            _node("a-script", "SCRIPT", 2.0, evidence_ids=("ev-shared",)),
            _node("m-dns", "DNS", 5.0),
        ]
    )
    engine = correlation.IncidentCorrelator(max_time_delta=10.0)
    first = engine.correlate(graph)
    second = engine.correlate(graph)
    restored = correlation.CorrelationResult.from_dict(first.to_dict())
    assert first.stable_json() == second.stable_json()
    assert first.digest() == second.digest()
    assert restored.stable_json() == first.stable_json()


def test_validation_rejects_duplicate_assignment_and_missing_graph_edge_representation() -> None:
    graph = _build_graph(
        [_node("process", "PROCESS", 1.0), _node("script", "SCRIPT", 2.0)],
        [_edge("process", "script", "EXECUTED")],
    )
    result = correlation.IncidentCorrelator().correlate(graph).to_dict()
    broken = deepcopy(result)
    broken["incidents"].append(deepcopy(broken["incidents"][0]))
    validation = correlation.validate_result(broken, graph)
    assert validation.passed is False
    assert "correlation:node_assigned_multiple_times" in validation.failures

    missing_edge = deepcopy(result)
    missing_edge["incidents"][0]["graph_edge_ids"] = []
    validation = correlation.validate_result(missing_edge, graph)
    assert validation.passed is False
    assert "correlation:graph_edge_assignment_not_exact" in validation.failures


def test_validation_rejects_unexplained_or_out_of_window_temporal_link() -> None:
    graph = _build_graph(
        [
            _node("file", "FILE", 1.0, evidence_ids=("ev-shared",)),
            _node("detection", "DETECTION", 2.0, evidence_ids=("ev-shared",)),
        ]
    )
    payload = correlation.IncidentCorrelator(max_time_delta=5.0).correlate(graph).to_dict()
    link = payload["incidents"][0]["links"][0]
    link["reason"] = ""
    link["time_delta"] = 50.0
    validation = correlation.validate_result(payload, graph)
    assert validation.passed is False
    assert any("reason_invalid" in failure for failure in validation.failures)
    assert any("temporal_rule_outside_window" in failure for failure in validation.failures)

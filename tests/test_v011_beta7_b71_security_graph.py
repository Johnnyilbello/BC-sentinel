from __future__ import annotations

from copy import deepcopy

import pytest

from sentinel import security_graph as graph


def _provenance(source_id: str = "evt-1") -> dict:
    return {
        "source": "b71-test-fixture",
        "source_id": source_id,
        "collector": "tests.test_v011_beta7_b71_security_graph",
        "trust": "DIRECT",
    }


def _node(node_id: str, node_type: str = "PROCESS") -> graph.GraphNode:
    return graph.GraphNode(
        node_id=node_id,
        node_type=node_type,
        label=node_id,
        observed_at=1.0,
        provenance=_provenance(node_id),
        evidence_ids=(f"ev-{node_id}",),
        confidence=0.8,
        attributes={"fixture": True},
    )


def _valid_graph() -> graph.SecurityGraph:
    builder = graph.SecurityGraphBuilder()
    process = builder.add_node(_node("process-1", "PROCESS"))
    file_node = builder.add_node(_node("file-1", "FILE"))
    detection = builder.add_node(_node("detection-1", "DETECTION"))
    builder.link(
        edge_type="CREATED",
        source=process.node_id,
        target=file_node.node_id,
        observed_at=2.0,
        provenance=_provenance("edge-create"),
        evidence_ids=["ev-create"],
        confidence=0.9,
        reason="Controlled fixture observed process creating file.",
    )
    builder.link(
        edge_type="TRIGGERED",
        source=file_node.node_id,
        target=detection.node_id,
        observed_at=3.0,
        provenance=_provenance("edge-detect"),
        evidence_ids=["ev-detect"],
        confidence=0.7,
        reason="Controlled fixture file evidence triggered detection.",
    )
    return builder.build(
        graph_id="graph-test",
        incident_id="incident-test",
        created_at=4.0,
        metadata={"fixture": True},
    )


def test_demo_graph_self_check_is_green_and_read_only() -> None:
    result = graph.self_check()
    assert result["passed"] is True
    assert result["node_count"] == 3
    assert result["edge_count"] == 2
    assert result["stable_round_trip"] is True
    assert result["provenance_required"] is True
    assert result["execution_authority_added"] is False
    assert result["automatic_quarantine"] is False
    assert result["automatic_repair"] is False
    assert result["automatic_restore"] is False
    assert result["general_home_execution_authorized"] is False
    assert result["terminate_process_authorized"] is False
    assert result["trust_allowlist_mutation_authorized"] is False


def test_serialization_and_digest_are_stable_across_insertion_order() -> None:
    left = graph.SecurityGraphBuilder()
    right = graph.SecurityGraphBuilder()
    nodes = [_node("z-process", "PROCESS"), _node("a-file", "FILE")]
    for item in nodes:
        left.add_node(item)
    for item in reversed(nodes):
        right.add_node(item)

    edge_args = dict(
        edge_type="ACCESSED",
        source="z-process",
        target="a-file",
        observed_at=2.0,
        provenance=_provenance("edge-stable"),
        evidence_ids=["ev-2", "ev-1"],
        confidence=0.75,
        reason="Stable fixture relation.",
    )
    left.link(**edge_args)
    right.link(**edge_args)
    graph_left = left.build(graph_id="stable", incident_id="inc", created_at=3.0)
    graph_right = right.build(graph_id="stable", incident_id="inc", created_at=3.0)
    assert graph_left.stable_json() == graph_right.stable_json()
    assert graph_left.digest() == graph_right.digest()


def test_observation_ids_are_deterministic() -> None:
    observation = {
        "node_type": "DNS",
        "identity": {"query": "example.invalid", "process": 44},
        "label": "example.invalid",
        "observed_at": 10.0,
        "provenance": _provenance("dns-1"),
        "evidence_ids": ["ev-dns"],
        "confidence": 0.5,
        "attributes": {"answer": "203.0.113.10"},
    }
    one = graph.SecurityGraphBuilder().ingest_observation(observation)
    two = graph.SecurityGraphBuilder().ingest_observation(deepcopy(observation))
    assert one.node_id == two.node_id
    assert one == two


def test_conflicting_duplicate_node_is_rejected_but_identical_ingest_is_idempotent() -> None:
    builder = graph.SecurityGraphBuilder()
    original = _node("same", "FILE")
    assert builder.add_node(original) == original
    assert builder.add_node(original) == original
    conflicting = graph.GraphNode(
        node_id="same",
        node_type="FILE",
        label="different",
        observed_at=1.0,
        provenance=_provenance("same"),
        evidence_ids=("ev-same",),
        confidence=0.8,
        attributes={"fixture": True},
    )
    with pytest.raises(ValueError, match="security_graph_conflicting_node:same"):
        builder.add_node(conflicting)


def test_missing_edge_endpoint_and_self_loop_fail_closed() -> None:
    payload = _valid_graph().to_dict()
    broken = deepcopy(payload)
    broken["edges"][0]["target"] = "missing-node"
    result = graph.validate_graph(broken)
    assert result.passed is False
    assert any("target_missing:missing-node" in failure for failure in result.failures)

    loop = deepcopy(payload)
    loop["edges"][0]["target"] = loop["edges"][0]["source"]
    result = graph.validate_graph(loop)
    assert result.passed is False
    assert any("self_loop_not_allowed" in failure for failure in result.failures)


def test_invalid_provenance_and_confidence_are_rejected() -> None:
    payload = _valid_graph().to_dict()
    payload["nodes"][0]["provenance"] = {
        "source": "",
        "source_id": "evt",
        "collector": "test",
        "trust": "MAGIC",
    }
    payload["nodes"][0]["confidence"] = 1.5
    result = graph.validate_graph(payload)
    assert result.passed is False
    assert any("provenance_source_invalid" in failure for failure in result.failures)
    assert any("provenance_trust_invalid" in failure for failure in result.failures)
    assert any("confidence_invalid" in failure for failure in result.failures)


def test_duplicate_edge_id_is_rejected() -> None:
    payload = _valid_graph().to_dict()
    duplicate = deepcopy(payload["edges"][0])
    payload["edges"].append(duplicate)
    result = graph.validate_graph(payload)
    assert result.passed is False
    assert any("duplicate_edge_id" in failure for failure in result.failures)


def test_subgraph_query_is_deterministic_and_does_not_invent_edges() -> None:
    full = _valid_graph()
    sub = full.subgraph(["file-1"], max_depth=1)
    ids = {node.node_id for node in sub.nodes}
    assert ids == {"process-1", "file-1", "detection-1"}
    assert len(sub.edges) == 2
    assert sub.metadata["subgraph_of"] == full.graph_id
    assert sub.stable_json() == full.subgraph(["file-1"], max_depth=1).stable_json()

    seed_only = full.subgraph(["file-1"], max_depth=0)
    assert [node.node_id for node in seed_only.nodes] == ["file-1"]
    assert seed_only.edges == ()


def test_round_trip_preserves_graph_exactly() -> None:
    original = _valid_graph()
    restored = graph.SecurityGraph.from_dict(original.to_dict())
    assert graph.validate_graph(restored.to_dict()).passed is True
    assert restored.stable_json() == original.stable_json()
    assert restored.digest() == original.digest()


def test_edge_reason_is_mandatory_for_explainability() -> None:
    payload = _valid_graph().to_dict()
    payload["edges"][0]["reason"] = ""
    result = graph.validate_graph(payload)
    assert result.passed is False
    assert any("reason_invalid" in failure for failure in result.failures)

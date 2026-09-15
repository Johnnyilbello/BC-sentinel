from __future__ import annotations

"""B7-1 provenance-preserving Sentinel Security Graph foundation.

The graph is an in-memory/read-only incident intelligence structure. It does
not execute detectors, remediation, process control, network activity, trust
mutation or privileged operations. Its job is to preserve relationships and
provenance so later Beta7 milestones can correlate and explain incidents
without rewriting the underlying evidence.
"""

from dataclasses import dataclass, field
import argparse
import hashlib
import json
from collections import deque
from typing import Any, Final, Iterable

SCHEMA: Final[str] = "bc-sentinel-security-graph-v1"
PROFILE: Final[str] = "v0.11.0-beta.7-b71-security-graph"
SOURCE_CHECKPOINT: Final[str] = "checkpoint/v011-beta7-b70-pass"
SOURCE_CHECKPOINT_COMMIT: Final[str] = "cd06f284525b3e0f70c121b6b97833cbf388c9ce"

ALLOWED_NODE_TYPES: Final[set[str]] = {
    "PROCESS",
    "FILE",
    "SCRIPT",
    "PERSISTENCE",
    "NETWORK",
    "DNS",
    "DETECTION",
    "EVIDENCE",
    "ACTION",
}
ALLOWED_EDGE_TYPES: Final[set[str]] = {
    "SPAWNED",
    "EXECUTED",
    "ACCESSED",
    "CREATED",
    "MODIFIED",
    "PERSISTED_VIA",
    "RESOLVED_TO",
    "CONNECTED_TO",
    "TRIGGERED",
    "SUPPORTED_BY",
    "ACTION_ON",
    "OBSERVED_WITH",
}
ALLOWED_PROVENANCE_TRUST: Final[set[str]] = {
    "DIRECT",
    "DERIVED",
    "IMPORTED",
    "UNKNOWN",
}


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _stable_hash(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _valid_timestamp(value: Any) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and value >= 0
    )


def _valid_confidence(value: Any) -> bool:
    return value is None or (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and 0.0 <= float(value) <= 1.0
    )


def _validate_string_list(value: Any) -> bool:
    return isinstance(value, list) and all(_nonempty_string(item) for item in value)


def _validate_provenance(value: Any, prefix: str) -> list[str]:
    failures: list[str] = []
    if not isinstance(value, dict):
        return [f"{prefix}:provenance_not_object"]
    for field_name in ("source", "source_id", "collector"):
        if not _nonempty_string(value.get(field_name)):
            failures.append(f"{prefix}:provenance_{field_name}_invalid")
    trust = str(value.get("trust") or "").strip().upper()
    if trust not in ALLOWED_PROVENANCE_TRUST:
        failures.append(f"{prefix}:provenance_trust_invalid")
    return failures


@dataclass(frozen=True)
class GraphValidation:
    passed: bool
    failures: tuple[str, ...]
    node_count: int
    edge_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "profile": PROFILE,
            "passed": self.passed,
            "failures": list(self.failures),
            "node_count": self.node_count,
            "edge_count": self.edge_count,
            "read_only": True,
            "execution_authority_added": False,
        }


@dataclass(frozen=True)
class GraphNode:
    node_id: str
    node_type: str
    label: str
    observed_at: float
    provenance: dict[str, Any]
    evidence_ids: tuple[str, ...] = field(default_factory=tuple)
    confidence: float | None = None
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type,
            "label": self.label,
            "observed_at": self.observed_at,
            "provenance": dict(self.provenance),
            "evidence_ids": list(self.evidence_ids),
            "confidence": self.confidence,
            "attributes": dict(self.attributes),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "GraphNode":
        return cls(
            node_id=str(payload.get("node_id") or ""),
            node_type=str(payload.get("node_type") or "").upper(),
            label=str(payload.get("label") or ""),
            observed_at=float(payload.get("observed_at") or 0.0),
            provenance=dict(payload.get("provenance") or {}),
            evidence_ids=tuple(str(item) for item in (payload.get("evidence_ids") or [])),
            confidence=(
                None
                if payload.get("confidence") is None
                else float(payload.get("confidence"))
            ),
            attributes=dict(payload.get("attributes") or {}),
        )


@dataclass(frozen=True)
class GraphEdge:
    edge_id: str
    edge_type: str
    source: str
    target: str
    observed_at: float
    provenance: dict[str, Any]
    evidence_ids: tuple[str, ...] = field(default_factory=tuple)
    confidence: float | None = None
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "edge_type": self.edge_type,
            "source": self.source,
            "target": self.target,
            "observed_at": self.observed_at,
            "provenance": dict(self.provenance),
            "evidence_ids": list(self.evidence_ids),
            "confidence": self.confidence,
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "GraphEdge":
        return cls(
            edge_id=str(payload.get("edge_id") or ""),
            edge_type=str(payload.get("edge_type") or "").upper(),
            source=str(payload.get("source") or ""),
            target=str(payload.get("target") or ""),
            observed_at=float(payload.get("observed_at") or 0.0),
            provenance=dict(payload.get("provenance") or {}),
            evidence_ids=tuple(str(item) for item in (payload.get("evidence_ids") or [])),
            confidence=(
                None
                if payload.get("confidence") is None
                else float(payload.get("confidence"))
            ),
            reason=str(payload.get("reason") or ""),
        )


@dataclass(frozen=True)
class SecurityGraph:
    graph_id: str
    incident_id: str
    created_at: float
    nodes: tuple[GraphNode, ...]
    edges: tuple[GraphEdge, ...]
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "profile": PROFILE,
            "source_checkpoint": SOURCE_CHECKPOINT,
            "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
            "graph_id": self.graph_id,
            "incident_id": self.incident_id,
            "created_at": self.created_at,
            "nodes": [node.to_dict() for node in sorted(self.nodes, key=lambda item: item.node_id)],
            "edges": [edge.to_dict() for edge in sorted(self.edges, key=lambda item: item.edge_id)],
            "metadata": dict(self.metadata),
        }

    def stable_json(self) -> str:
        return _canonical_json(self.to_dict())

    def digest(self) -> str:
        return hashlib.sha256(self.stable_json().encode("utf-8")).hexdigest()

    def node(self, node_id: str) -> GraphNode | None:
        return next((node for node in self.nodes if node.node_id == node_id), None)

    def nodes_by_type(self, node_type: str) -> tuple[GraphNode, ...]:
        wanted = str(node_type or "").upper()
        return tuple(sorted((n for n in self.nodes if n.node_type == wanted), key=lambda n: n.node_id))

    def neighbors(self, node_id: str, *, direction: str = "both") -> tuple[GraphNode, ...]:
        direction = direction.lower()
        if direction not in {"both", "in", "out"}:
            raise ValueError("security_graph_direction_invalid")
        ids: set[str] = set()
        for edge in self.edges:
            if direction in {"both", "out"} and edge.source == node_id:
                ids.add(edge.target)
            if direction in {"both", "in"} and edge.target == node_id:
                ids.add(edge.source)
        return tuple(sorted((node for node in self.nodes if node.node_id in ids), key=lambda n: n.node_id))

    def subgraph(self, seed_ids: Iterable[str], *, max_depth: int = 1) -> "SecurityGraph":
        if isinstance(max_depth, bool) or not isinstance(max_depth, int) or max_depth < 0:
            raise ValueError("security_graph_depth_invalid")
        seeds = {str(item) for item in seed_ids if str(item)}
        known = {node.node_id for node in self.nodes}
        if not seeds or not seeds.issubset(known):
            raise ValueError("security_graph_seed_invalid")

        selected = set(seeds)
        frontier = deque((seed, 0) for seed in sorted(seeds))
        while frontier:
            current, depth = frontier.popleft()
            if depth >= max_depth:
                continue
            for neighbor in self.neighbors(current):
                if neighbor.node_id not in selected:
                    selected.add(neighbor.node_id)
                    frontier.append((neighbor.node_id, depth + 1))

        nodes = tuple(node for node in self.nodes if node.node_id in selected)
        edges = tuple(
            edge
            for edge in self.edges
            if edge.source in selected and edge.target in selected
        )
        return SecurityGraph(
            graph_id=f"{self.graph_id}:subgraph:{_stable_hash(sorted(selected))[:12]}",
            incident_id=self.incident_id,
            created_at=self.created_at,
            nodes=tuple(sorted(nodes, key=lambda n: n.node_id)),
            edges=tuple(sorted(edges, key=lambda e: e.edge_id)),
            metadata={**self.metadata, "subgraph_of": self.graph_id, "seed_ids": sorted(seeds)},
        )

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "SecurityGraph":
        return cls(
            graph_id=str(payload.get("graph_id") or ""),
            incident_id=str(payload.get("incident_id") or ""),
            created_at=float(payload.get("created_at") or 0.0),
            nodes=tuple(GraphNode.from_dict(item) for item in (payload.get("nodes") or [])),
            edges=tuple(GraphEdge.from_dict(item) for item in (payload.get("edges") or [])),
            metadata=dict(payload.get("metadata") or {}),
        )


class SecurityGraphBuilder:
    """Deterministic, in-memory builder. No I/O and no execution authority."""

    def __init__(self) -> None:
        self._nodes: dict[str, GraphNode] = {}
        self._edges: dict[str, GraphEdge] = {}

    @staticmethod
    def deterministic_node_id(node_type: str, identity: Any) -> str:
        normalized_type = str(node_type or "").upper()
        return f"{normalized_type.lower()}:{_stable_hash({'type': normalized_type, 'identity': identity})[:20]}"

    @staticmethod
    def deterministic_edge_id(
        edge_type: str,
        source: str,
        target: str,
        evidence_ids: Iterable[str],
    ) -> str:
        material = {
            "edge_type": str(edge_type or "").upper(),
            "source": source,
            "target": target,
            "evidence_ids": sorted(str(item) for item in evidence_ids),
        }
        return f"edge:{_stable_hash(material)[:24]}"

    def add_node(self, node: GraphNode) -> GraphNode:
        existing = self._nodes.get(node.node_id)
        if existing is not None:
            if existing != node:
                raise ValueError(f"security_graph_conflicting_node:{node.node_id}")
            return existing
        self._nodes[node.node_id] = node
        return node

    def ingest_observation(self, observation: dict[str, Any]) -> GraphNode:
        if not isinstance(observation, dict):
            raise ValueError("security_graph_observation_not_object")
        node_type = str(observation.get("node_type") or "").upper()
        identity = observation.get("identity")
        node_id = str(observation.get("node_id") or "") or self.deterministic_node_id(node_type, identity)
        node = GraphNode(
            node_id=node_id,
            node_type=node_type,
            label=str(observation.get("label") or ""),
            observed_at=float(observation.get("observed_at") or 0.0),
            provenance=dict(observation.get("provenance") or {}),
            evidence_ids=tuple(sorted(str(item) for item in (observation.get("evidence_ids") or []))),
            confidence=(
                None
                if observation.get("confidence") is None
                else float(observation.get("confidence"))
            ),
            attributes=dict(observation.get("attributes") or {}),
        )
        return self.add_node(node)

    def add_edge(self, edge: GraphEdge) -> GraphEdge:
        existing = self._edges.get(edge.edge_id)
        if existing is not None:
            if existing != edge:
                raise ValueError(f"security_graph_conflicting_edge:{edge.edge_id}")
            return existing
        self._edges[edge.edge_id] = edge
        return edge

    def link(
        self,
        *,
        edge_type: str,
        source: str,
        target: str,
        observed_at: float,
        provenance: dict[str, Any],
        evidence_ids: Iterable[str] = (),
        confidence: float | None = None,
        reason: str,
        edge_id: str | None = None,
    ) -> GraphEdge:
        evidence = tuple(sorted(str(item) for item in evidence_ids))
        resolved_id = edge_id or self.deterministic_edge_id(edge_type, source, target, evidence)
        return self.add_edge(
            GraphEdge(
                edge_id=resolved_id,
                edge_type=str(edge_type or "").upper(),
                source=source,
                target=target,
                observed_at=float(observed_at),
                provenance=dict(provenance),
                evidence_ids=evidence,
                confidence=confidence,
                reason=reason,
            )
        )

    def build(
        self,
        *,
        graph_id: str,
        incident_id: str,
        created_at: float,
        metadata: dict[str, Any] | None = None,
    ) -> SecurityGraph:
        graph = SecurityGraph(
            graph_id=graph_id,
            incident_id=incident_id,
            created_at=float(created_at),
            nodes=tuple(sorted(self._nodes.values(), key=lambda item: item.node_id)),
            edges=tuple(sorted(self._edges.values(), key=lambda item: item.edge_id)),
            metadata=dict(metadata or {}),
        )
        validation = validate_graph(graph.to_dict())
        if not validation.passed:
            raise ValueError("security_graph_invalid:" + ",".join(validation.failures))
        return graph


def _validate_node(item: Any, index: int) -> list[str]:
    prefix = f"node[{index}]"
    failures: list[str] = []
    if not isinstance(item, dict):
        return [f"{prefix}:not_object"]
    if not _nonempty_string(item.get("node_id")):
        failures.append(f"{prefix}:node_id_invalid")
    node_type = str(item.get("node_type") or "").upper()
    if node_type not in ALLOWED_NODE_TYPES:
        failures.append(f"{prefix}:node_type_invalid")
    if not _nonempty_string(item.get("label")):
        failures.append(f"{prefix}:label_invalid")
    if not _valid_timestamp(item.get("observed_at")):
        failures.append(f"{prefix}:observed_at_invalid")
    failures.extend(_validate_provenance(item.get("provenance"), prefix))
    if not _validate_string_list(item.get("evidence_ids")):
        failures.append(f"{prefix}:evidence_ids_invalid")
    if not _valid_confidence(item.get("confidence")):
        failures.append(f"{prefix}:confidence_invalid")
    if not isinstance(item.get("attributes"), dict):
        failures.append(f"{prefix}:attributes_not_object")
    return failures


def _validate_edge(item: Any, index: int, node_ids: set[str]) -> list[str]:
    prefix = f"edge[{index}]"
    failures: list[str] = []
    if not isinstance(item, dict):
        return [f"{prefix}:not_object"]
    if not _nonempty_string(item.get("edge_id")):
        failures.append(f"{prefix}:edge_id_invalid")
    edge_type = str(item.get("edge_type") or "").upper()
    if edge_type not in ALLOWED_EDGE_TYPES:
        failures.append(f"{prefix}:edge_type_invalid")
    source = str(item.get("source") or "")
    target = str(item.get("target") or "")
    if source not in node_ids:
        failures.append(f"{prefix}:source_missing:{source}")
    if target not in node_ids:
        failures.append(f"{prefix}:target_missing:{target}")
    if source and source == target:
        failures.append(f"{prefix}:self_loop_not_allowed")
    if not _valid_timestamp(item.get("observed_at")):
        failures.append(f"{prefix}:observed_at_invalid")
    failures.extend(_validate_provenance(item.get("provenance"), prefix))
    if not _validate_string_list(item.get("evidence_ids")):
        failures.append(f"{prefix}:evidence_ids_invalid")
    if not _valid_confidence(item.get("confidence")):
        failures.append(f"{prefix}:confidence_invalid")
    if not _nonempty_string(item.get("reason")):
        failures.append(f"{prefix}:reason_invalid")
    return failures


def validate_graph(payload: Any) -> GraphValidation:
    failures: list[str] = []
    if not isinstance(payload, dict):
        return GraphValidation(False, ("graph:not_object",), 0, 0)
    if payload.get("schema") != SCHEMA:
        failures.append("graph:schema_mismatch")
    if payload.get("profile") != PROFILE:
        failures.append("graph:profile_mismatch")
    if payload.get("source_checkpoint") != SOURCE_CHECKPOINT:
        failures.append("graph:source_checkpoint_mismatch")
    if payload.get("source_checkpoint_commit") != SOURCE_CHECKPOINT_COMMIT:
        failures.append("graph:source_checkpoint_commit_mismatch")
    if not _nonempty_string(payload.get("graph_id")):
        failures.append("graph:graph_id_invalid")
    if not _nonempty_string(payload.get("incident_id")):
        failures.append("graph:incident_id_invalid")
    if not _valid_timestamp(payload.get("created_at")):
        failures.append("graph:created_at_invalid")
    if not isinstance(payload.get("metadata"), dict):
        failures.append("graph:metadata_not_object")

    nodes = payload.get("nodes")
    edges = payload.get("edges")
    if not isinstance(nodes, list):
        return GraphValidation(False, tuple(failures + ["graph:nodes_not_array"]), 0, 0)
    if not isinstance(edges, list):
        return GraphValidation(False, tuple(failures + ["graph:edges_not_array"]), len(nodes), 0)

    seen_nodes: set[str] = set()
    for index, item in enumerate(nodes):
        failures.extend(_validate_node(item, index))
        if isinstance(item, dict):
            node_id = str(item.get("node_id") or "")
            if node_id:
                if node_id in seen_nodes:
                    failures.append(f"node[{index}]:duplicate_node_id:{node_id}")
                seen_nodes.add(node_id)

    seen_edges: set[str] = set()
    for index, item in enumerate(edges):
        failures.extend(_validate_edge(item, index, seen_nodes))
        if isinstance(item, dict):
            edge_id = str(item.get("edge_id") or "")
            if edge_id:
                if edge_id in seen_edges:
                    failures.append(f"edge[{index}]:duplicate_edge_id:{edge_id}")
                seen_edges.add(edge_id)

    return GraphValidation(not failures, tuple(failures), len(nodes), len(edges))


def demo_graph() -> SecurityGraph:
    provenance = {
        "source": "b71-controlled-fixture",
        "source_id": "fixture-001",
        "collector": "sentinel.security_graph.self_check",
        "trust": "DIRECT",
    }
    builder = SecurityGraphBuilder()
    process = builder.ingest_observation(
        {
            "node_type": "PROCESS",
            "identity": {"pid": 4242, "image": "fixture.exe"},
            "label": "fixture.exe",
            "observed_at": 1.0,
            "provenance": provenance,
            "evidence_ids": ["ev-process-1"],
            "confidence": 1.0,
            "attributes": {"pid": 4242},
        }
    )
    script = builder.ingest_observation(
        {
            "node_type": "SCRIPT",
            "identity": {"sha256": "a" * 64},
            "label": "controlled.ps1",
            "observed_at": 2.0,
            "provenance": provenance,
            "evidence_ids": ["ev-script-1"],
            "confidence": 1.0,
            "attributes": {"sha256": "a" * 64},
        }
    )
    detection = builder.ingest_observation(
        {
            "node_type": "DETECTION",
            "identity": {"finding_id": "finding-001"},
            "label": "Controlled script behavior",
            "observed_at": 3.0,
            "provenance": provenance,
            "evidence_ids": ["ev-detection-1"],
            "confidence": 0.9,
            "attributes": {"severity": "HIGH"},
        }
    )
    builder.link(
        edge_type="EXECUTED",
        source=process.node_id,
        target=script.node_id,
        observed_at=2.0,
        provenance=provenance,
        evidence_ids=["ev-script-1"],
        confidence=1.0,
        reason="Controlled process/script execution evidence.",
    )
    builder.link(
        edge_type="TRIGGERED",
        source=script.node_id,
        target=detection.node_id,
        observed_at=3.0,
        provenance=provenance,
        evidence_ids=["ev-detection-1"],
        confidence=0.9,
        reason="Controlled script evidence triggered the fixture detection.",
    )
    return builder.build(
        graph_id="graph-b71-self-check",
        incident_id="incident-b71-self-check",
        created_at=4.0,
        metadata={"fixture": True},
    )


def self_check() -> dict[str, Any]:
    graph = demo_graph()
    validation = validate_graph(graph.to_dict())
    round_trip = SecurityGraph.from_dict(graph.to_dict())
    return {
        **validation.to_dict(),
        "graph_digest": graph.digest(),
        "stable_round_trip": round_trip.stable_json() == graph.stable_json(),
        "deterministic_serialization": graph.stable_json() == graph.stable_json(),
        "provenance_required": True,
        "edge_reason_required": True,
        "missing_node_edges_allowed": False,
        "conflicting_duplicate_ids_allowed": False,
        "automatic_quarantine": False,
        "automatic_repair": False,
        "automatic_restore": False,
        "general_home_execution_authorized": False,
        "delete_authorized": False,
        "repair_authorized": False,
        "terminate_process_authorized": False,
        "trust_allowlist_mutation_authorized": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel B7-1 Security Graph foundation")
    parser.add_argument("--self-check", action="store_true")
    args = parser.parse_args(argv)
    result = self_check()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("passed") is True and result.get("stable_round_trip") is True else 4


if __name__ == "__main__":
    raise SystemExit(main())

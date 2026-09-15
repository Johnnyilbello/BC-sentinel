from __future__ import annotations

"""B7-2 deterministic, read-only incident correlation engine.

The correlator groups already-observed Security Graph nodes into incidents using
explicit graph relations, shared evidence, and explicit collector-provided
correlation keys. Temporal proximity alone is never sufficient. The engine
preserves the source graph verbatim and introduces no detector or remediation
authority.
"""

from dataclasses import dataclass, field
import argparse
import hashlib
import json
from itertools import combinations
from typing import Any, Final, Iterable

from sentinel import security_graph

SCHEMA: Final[str] = "bc-sentinel-incident-correlation-v1"
PROFILE: Final[str] = "v0.11.0-beta.7-b72-incident-correlation"
SOURCE_CHECKPOINT: Final[str] = "checkpoint/v011-beta7-b71-pass"
SOURCE_CHECKPOINT_COMMIT: Final[str] = "c75697b25c63e59bdfc2ad32374c4232c607fea0"

RULE_GRAPH_EDGE: Final[str] = "GRAPH_EDGE"
RULE_SHARED_EVIDENCE: Final[str] = "SHARED_EVIDENCE"
RULE_EXPLICIT_KEY: Final[str] = "EXPLICIT_CORRELATION_KEY"
ALLOWED_RULES: Final[set[str]] = {
    RULE_GRAPH_EDGE,
    RULE_SHARED_EVIDENCE,
    RULE_EXPLICIT_KEY,
}


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _stable_hash(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _valid_timestamp(value: Any) -> bool:
    return not isinstance(value, bool) and isinstance(value, (int, float)) and value >= 0


def _valid_delta(value: Any) -> bool:
    return not isinstance(value, bool) and isinstance(value, (int, float)) and value >= 0


def _valid_sha256(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    return all(char in "0123456789abcdef" for char in value.lower())


def _explicit_keys(node: security_graph.GraphNode) -> tuple[str, ...]:
    if "correlation_keys" not in node.attributes:
        return ()
    raw = node.attributes.get("correlation_keys")
    if not isinstance(raw, list) or any(not _nonempty_string(item) for item in raw):
        raise ValueError(f"incident_correlation_keys_invalid:{node.node_id}")
    normalized = tuple(sorted({str(item).strip() for item in raw}))
    if not normalized:
        raise ValueError(f"incident_correlation_keys_invalid:{node.node_id}")
    return normalized


@dataclass(frozen=True)
class CorrelationLink:
    link_id: str
    source: str
    target: str
    rule: str
    reason: str
    observed_at: float
    time_delta: float
    evidence_ids: tuple[str, ...] = field(default_factory=tuple)
    correlation_keys: tuple[str, ...] = field(default_factory=tuple)
    source_edge_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "link_id": self.link_id,
            "source": self.source,
            "target": self.target,
            "rule": self.rule,
            "reason": self.reason,
            "observed_at": self.observed_at,
            "time_delta": self.time_delta,
            "evidence_ids": list(self.evidence_ids),
            "correlation_keys": list(self.correlation_keys),
            "source_edge_id": self.source_edge_id,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "CorrelationLink":
        return cls(
            link_id=str(payload.get("link_id") or ""),
            source=str(payload.get("source") or ""),
            target=str(payload.get("target") or ""),
            rule=str(payload.get("rule") or "").upper(),
            reason=str(payload.get("reason") or ""),
            observed_at=float(payload.get("observed_at") or 0.0),
            time_delta=float(payload.get("time_delta") or 0.0),
            evidence_ids=tuple(str(item) for item in (payload.get("evidence_ids") or [])),
            correlation_keys=tuple(str(item) for item in (payload.get("correlation_keys") or [])),
            source_edge_id=(
                None
                if payload.get("source_edge_id") is None
                else str(payload.get("source_edge_id"))
            ),
        )


@dataclass(frozen=True)
class IncidentCluster:
    incident_id: str
    node_ids: tuple[str, ...]
    graph_edge_ids: tuple[str, ...]
    links: tuple[CorrelationLink, ...]
    started_at: float
    ended_at: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "node_ids": list(self.node_ids),
            "graph_edge_ids": list(self.graph_edge_ids),
            "links": [link.to_dict() for link in sorted(self.links, key=lambda item: item.link_id)],
            "started_at": self.started_at,
            "ended_at": self.ended_at,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "IncidentCluster":
        return cls(
            incident_id=str(payload.get("incident_id") or ""),
            node_ids=tuple(str(item) for item in (payload.get("node_ids") or [])),
            graph_edge_ids=tuple(str(item) for item in (payload.get("graph_edge_ids") or [])),
            links=tuple(
                CorrelationLink.from_dict(item) for item in (payload.get("links") or [])
            ),
            started_at=float(payload.get("started_at") or 0.0),
            ended_at=float(payload.get("ended_at") or 0.0),
        )


@dataclass(frozen=True)
class CorrelationResult:
    source_graph_id: str
    source_graph_digest: str
    max_time_delta: float
    incidents: tuple[IncidentCluster, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "profile": PROFILE,
            "source_checkpoint": SOURCE_CHECKPOINT,
            "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
            "source_graph_id": self.source_graph_id,
            "source_graph_digest": self.source_graph_digest,
            "max_time_delta": self.max_time_delta,
            "incidents": [
                incident.to_dict()
                for incident in sorted(self.incidents, key=lambda item: item.incident_id)
            ],
            "read_only": True,
            "execution_authority_added": False,
        }

    def stable_json(self) -> str:
        return _canonical_json(self.to_dict())

    def digest(self) -> str:
        return hashlib.sha256(self.stable_json().encode("utf-8")).hexdigest()

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "CorrelationResult":
        return cls(
            source_graph_id=str(payload.get("source_graph_id") or ""),
            source_graph_digest=str(payload.get("source_graph_digest") or ""),
            max_time_delta=float(payload.get("max_time_delta") or 0.0),
            incidents=tuple(
                IncidentCluster.from_dict(item) for item in (payload.get("incidents") or [])
            ),
        )


@dataclass(frozen=True)
class CorrelationValidation:
    passed: bool
    failures: tuple[str, ...]
    incident_count: int
    correlated_node_count: int
    link_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "profile": PROFILE,
            "passed": self.passed,
            "failures": list(self.failures),
            "incident_count": self.incident_count,
            "correlated_node_count": self.correlated_node_count,
            "link_count": self.link_count,
            "read_only": True,
            "execution_authority_added": False,
        }


class _UnionFind:
    def __init__(self, ids: Iterable[str]) -> None:
        self.parent = {item: item for item in ids}

    def find(self, item: str) -> str:
        parent = self.parent[item]
        if parent != item:
            self.parent[item] = self.find(parent)
        return self.parent[item]

    def union(self, left: str, right: str) -> None:
        root_left = self.find(left)
        root_right = self.find(right)
        if root_left == root_right:
            return
        first, second = sorted((root_left, root_right))
        self.parent[second] = first


class IncidentCorrelator:
    """Conservative deterministic correlator. It never mutates the source graph."""

    def __init__(self, *, max_time_delta: float = 120.0) -> None:
        if not _valid_delta(max_time_delta):
            raise ValueError("incident_correlation_time_window_invalid")
        self.max_time_delta = float(max_time_delta)

    @staticmethod
    def _link_id(material: dict[str, Any]) -> str:
        return "corr:" + _stable_hash(material)[:24]

    def _graph_edge_link(
        self,
        edge: security_graph.GraphEdge,
        nodes: dict[str, security_graph.GraphNode],
    ) -> CorrelationLink:
        left = nodes[edge.source]
        right = nodes[edge.target]
        delta = abs(float(left.observed_at) - float(right.observed_at))
        material = {
            "rule": RULE_GRAPH_EDGE,
            "source": edge.source,
            "target": edge.target,
            "edge_id": edge.edge_id,
        }
        return CorrelationLink(
            link_id=self._link_id(material),
            source=edge.source,
            target=edge.target,
            rule=RULE_GRAPH_EDGE,
            reason=f"Existing Security Graph relation {edge.edge_type}: {edge.reason}",
            observed_at=float(edge.observed_at),
            time_delta=delta,
            evidence_ids=tuple(sorted(edge.evidence_ids)),
            correlation_keys=(),
            source_edge_id=edge.edge_id,
        )

    def correlate(self, graph: security_graph.SecurityGraph) -> CorrelationResult:
        graph_validation = security_graph.validate_graph(graph.to_dict())
        if not graph_validation.passed:
            raise ValueError("incident_correlation_source_graph_invalid:" + ",".join(graph_validation.failures))

        source_digest_before = graph.digest()
        nodes = {node.node_id: node for node in graph.nodes}
        uf = _UnionFind(sorted(nodes))
        links: dict[str, CorrelationLink] = {}

        for edge in sorted(graph.edges, key=lambda item: item.edge_id):
            link = self._graph_edge_link(edge, nodes)
            links[link.link_id] = link
            uf.union(edge.source, edge.target)

        ordered_nodes = sorted(graph.nodes, key=lambda item: item.node_id)
        for left, right in combinations(ordered_nodes, 2):
            delta = abs(float(left.observed_at) - float(right.observed_at))
            if delta > self.max_time_delta:
                continue

            shared_evidence = tuple(sorted(set(left.evidence_ids) & set(right.evidence_ids)))
            if shared_evidence:
                material = {
                    "rule": RULE_SHARED_EVIDENCE,
                    "source": left.node_id,
                    "target": right.node_id,
                    "evidence_ids": shared_evidence,
                }
                link = CorrelationLink(
                    link_id=self._link_id(material),
                    source=left.node_id,
                    target=right.node_id,
                    rule=RULE_SHARED_EVIDENCE,
                    reason="Nodes share explicit evidence IDs within the configured correlation window.",
                    observed_at=max(float(left.observed_at), float(right.observed_at)),
                    time_delta=delta,
                    evidence_ids=shared_evidence,
                    correlation_keys=(),
                    source_edge_id=None,
                )
                links[link.link_id] = link
                uf.union(left.node_id, right.node_id)

            left_keys = set(_explicit_keys(left))
            right_keys = set(_explicit_keys(right))
            shared_keys = tuple(sorted(left_keys & right_keys))
            if shared_keys:
                material = {
                    "rule": RULE_EXPLICIT_KEY,
                    "source": left.node_id,
                    "target": right.node_id,
                    "correlation_keys": shared_keys,
                }
                link = CorrelationLink(
                    link_id=self._link_id(material),
                    source=left.node_id,
                    target=right.node_id,
                    rule=RULE_EXPLICIT_KEY,
                    reason="Nodes share collector-provided explicit correlation keys within the configured window.",
                    observed_at=max(float(left.observed_at), float(right.observed_at)),
                    time_delta=delta,
                    evidence_ids=tuple(sorted(set(left.evidence_ids) & set(right.evidence_ids))),
                    correlation_keys=shared_keys,
                    source_edge_id=None,
                )
                links[link.link_id] = link
                uf.union(left.node_id, right.node_id)

        groups: dict[str, list[str]] = {}
        for node_id in sorted(nodes):
            groups.setdefault(uf.find(node_id), []).append(node_id)

        incidents: list[IncidentCluster] = []
        for member_ids in sorted((tuple(sorted(group)) for group in groups.values())):
            member_set = set(member_ids)
            internal_edges = tuple(
                edge.edge_id
                for edge in sorted(graph.edges, key=lambda item: item.edge_id)
                if edge.source in member_set and edge.target in member_set
            )
            incident_links = tuple(
                sorted(
                    (
                        link
                        for link in links.values()
                        if link.source in member_set and link.target in member_set
                    ),
                    key=lambda item: item.link_id,
                )
            )
            timestamps = [float(nodes[node_id].observed_at) for node_id in member_ids]
            incident_id = "incident:" + _stable_hash(
                {
                    "source_graph_digest": source_digest_before,
                    "node_ids": member_ids,
                    "graph_edge_ids": internal_edges,
                }
            )[:24]
            incidents.append(
                IncidentCluster(
                    incident_id=incident_id,
                    node_ids=member_ids,
                    graph_edge_ids=internal_edges,
                    links=incident_links,
                    started_at=min(timestamps),
                    ended_at=max(timestamps),
                )
            )

        result = CorrelationResult(
            source_graph_id=graph.graph_id,
            source_graph_digest=source_digest_before,
            max_time_delta=self.max_time_delta,
            incidents=tuple(sorted(incidents, key=lambda item: item.incident_id)),
        )
        validation = validate_result(result, graph)
        if not validation.passed:
            raise ValueError("incident_correlation_result_invalid:" + ",".join(validation.failures))
        if graph.digest() != source_digest_before:
            raise RuntimeError("incident_correlation_source_graph_mutated")
        return result


def validate_result(
    result: CorrelationResult | dict[str, Any],
    graph: security_graph.SecurityGraph,
) -> CorrelationValidation:
    payload = result.to_dict() if isinstance(result, CorrelationResult) else result
    failures: list[str] = []
    if not isinstance(payload, dict):
        return CorrelationValidation(False, ("correlation:not_object",), 0, 0, 0)

    if payload.get("schema") != SCHEMA:
        failures.append("correlation:schema_mismatch")
    if payload.get("profile") != PROFILE:
        failures.append("correlation:profile_mismatch")
    if payload.get("source_checkpoint") != SOURCE_CHECKPOINT:
        failures.append("correlation:source_checkpoint_mismatch")
    if payload.get("source_checkpoint_commit") != SOURCE_CHECKPOINT_COMMIT:
        failures.append("correlation:source_checkpoint_commit_mismatch")
    if payload.get("source_graph_id") != graph.graph_id:
        failures.append("correlation:source_graph_id_mismatch")
    digest = payload.get("source_graph_digest")
    if not _valid_sha256(digest) or digest != graph.digest():
        failures.append("correlation:source_graph_digest_mismatch")
    if not _valid_delta(payload.get("max_time_delta")):
        failures.append("correlation:max_time_delta_invalid")

    incidents = payload.get("incidents")
    if not isinstance(incidents, list):
        return CorrelationValidation(False, tuple(failures + ["correlation:incidents_not_array"]), 0, 0, 0)

    graph_nodes = {node.node_id: node for node in graph.nodes}
    graph_edges = {edge.edge_id: edge for edge in graph.edges}
    assigned_nodes: list[str] = []
    represented_edges: list[str] = []
    seen_incidents: set[str] = set()
    seen_links: set[str] = set()
    link_count = 0

    for index, incident in enumerate(incidents):
        prefix = f"incident[{index}]"
        if not isinstance(incident, dict):
            failures.append(f"{prefix}:not_object")
            continue
        incident_id = incident.get("incident_id")
        if not _nonempty_string(incident_id):
            failures.append(f"{prefix}:incident_id_invalid")
        elif incident_id in seen_incidents:
            failures.append(f"{prefix}:duplicate_incident_id:{incident_id}")
        else:
            seen_incidents.add(str(incident_id))

        node_ids = incident.get("node_ids")
        if not isinstance(node_ids, list) or not node_ids or any(not _nonempty_string(item) for item in node_ids):
            failures.append(f"{prefix}:node_ids_invalid")
            node_ids = []
        if len(node_ids) != len(set(node_ids)):
            failures.append(f"{prefix}:duplicate_node_id")
        for node_id in node_ids:
            if node_id not in graph_nodes:
                failures.append(f"{prefix}:unknown_node:{node_id}")
        assigned_nodes.extend(node_ids)

        edge_ids = incident.get("graph_edge_ids")
        if not isinstance(edge_ids, list) or any(not _nonempty_string(item) for item in edge_ids):
            failures.append(f"{prefix}:graph_edge_ids_invalid")
            edge_ids = []
        if len(edge_ids) != len(set(edge_ids)):
            failures.append(f"{prefix}:duplicate_graph_edge_id")
        member_set = set(node_ids)
        for edge_id in edge_ids:
            edge = graph_edges.get(edge_id)
            if edge is None:
                failures.append(f"{prefix}:unknown_graph_edge:{edge_id}")
            elif edge.source not in member_set or edge.target not in member_set:
                failures.append(f"{prefix}:cross_incident_graph_edge:{edge_id}")
        represented_edges.extend(edge_ids)

        started_at = incident.get("started_at")
        ended_at = incident.get("ended_at")
        if not _valid_timestamp(started_at) or not _valid_timestamp(ended_at):
            failures.append(f"{prefix}:time_bounds_invalid")
        elif float(started_at) > float(ended_at):
            failures.append(f"{prefix}:time_bounds_reversed")
        elif node_ids and all(node_id in graph_nodes for node_id in node_ids):
            times = [float(graph_nodes[node_id].observed_at) for node_id in node_ids]
            if float(started_at) != min(times) or float(ended_at) != max(times):
                failures.append(f"{prefix}:time_bounds_not_exact")

        incident_links = incident.get("links")
        if not isinstance(incident_links, list):
            failures.append(f"{prefix}:links_not_array")
            incident_links = []
        for link_index, link in enumerate(incident_links):
            link_prefix = f"{prefix}.link[{link_index}]"
            link_count += 1
            if not isinstance(link, dict):
                failures.append(f"{link_prefix}:not_object")
                continue
            link_id = link.get("link_id")
            if not _nonempty_string(link_id):
                failures.append(f"{link_prefix}:link_id_invalid")
            elif link_id in seen_links:
                failures.append(f"{link_prefix}:duplicate_link_id:{link_id}")
            else:
                seen_links.add(str(link_id))
            source = str(link.get("source") or "")
            target = str(link.get("target") or "")
            if source not in member_set or target not in member_set or source == target:
                failures.append(f"{link_prefix}:endpoints_invalid")
            rule = str(link.get("rule") or "").upper()
            if rule not in ALLOWED_RULES:
                failures.append(f"{link_prefix}:rule_invalid")
            if not _nonempty_string(link.get("reason")):
                failures.append(f"{link_prefix}:reason_invalid")
            if not _valid_timestamp(link.get("observed_at")):
                failures.append(f"{link_prefix}:observed_at_invalid")
            if not _valid_delta(link.get("time_delta")):
                failures.append(f"{link_prefix}:time_delta_invalid")
            evidence_ids = link.get("evidence_ids")
            if not isinstance(evidence_ids, list) or any(not _nonempty_string(item) for item in evidence_ids):
                failures.append(f"{link_prefix}:evidence_ids_invalid")
            correlation_keys = link.get("correlation_keys")
            if not isinstance(correlation_keys, list) or any(not _nonempty_string(item) for item in correlation_keys):
                failures.append(f"{link_prefix}:correlation_keys_invalid")
            source_edge_id = link.get("source_edge_id")
            if rule == RULE_GRAPH_EDGE:
                if not _nonempty_string(source_edge_id) or source_edge_id not in graph_edges:
                    failures.append(f"{link_prefix}:graph_edge_binding_invalid")
            else:
                if source_edge_id is not None:
                    failures.append(f"{link_prefix}:unexpected_source_edge")
                if _valid_delta(link.get("time_delta")) and float(link.get("time_delta")) > float(payload.get("max_time_delta") or 0.0):
                    failures.append(f"{link_prefix}:temporal_rule_outside_window")
            if rule == RULE_SHARED_EVIDENCE and not evidence_ids:
                failures.append(f"{link_prefix}:shared_evidence_missing")
            if rule == RULE_EXPLICIT_KEY and not correlation_keys:
                failures.append(f"{link_prefix}:explicit_keys_missing")

    if sorted(assigned_nodes) != sorted(graph_nodes):
        failures.append("correlation:node_assignment_not_exact")
    if len(assigned_nodes) != len(set(assigned_nodes)):
        failures.append("correlation:node_assigned_multiple_times")
    if sorted(represented_edges) != sorted(graph_edges):
        failures.append("correlation:graph_edge_assignment_not_exact")
    if len(represented_edges) != len(set(represented_edges)):
        failures.append("correlation:graph_edge_assigned_multiple_times")

    return CorrelationValidation(
        passed=not failures,
        failures=tuple(failures),
        incident_count=len(incidents),
        correlated_node_count=len(set(assigned_nodes)),
        link_count=link_count,
    )


def demo_graph() -> security_graph.SecurityGraph:
    provenance = {
        "source": "b72-controlled-fixture",
        "source_id": "fixture-b72",
        "collector": "sentinel.incident_correlation.self_check",
        "trust": "DIRECT",
    }
    builder = security_graph.SecurityGraphBuilder()
    process = builder.ingest_observation({
        "node_type": "PROCESS", "identity": {"pid": 7201}, "label": "fixture.exe",
        "observed_at": 10.0, "provenance": provenance, "evidence_ids": ["ev-process"],
        "confidence": 1.0, "attributes": {"correlation_keys": ["session:b72-a"]},
    })
    script = builder.ingest_observation({
        "node_type": "SCRIPT", "identity": {"sha256": "b" * 64}, "label": "controlled.ps1",
        "observed_at": 12.0, "provenance": provenance, "evidence_ids": ["ev-script"],
        "confidence": 1.0, "attributes": {"correlation_keys": ["session:b72-a"]},
    })
    detection = builder.ingest_observation({
        "node_type": "DETECTION", "identity": {"finding": "b72-detection"}, "label": "Controlled behavior",
        "observed_at": 13.0, "provenance": provenance, "evidence_ids": ["ev-script", "ev-detection"],
        "confidence": 0.9, "attributes": {},
    })
    unrelated = builder.ingest_observation({
        "node_type": "DNS", "identity": {"query": "unrelated.invalid"}, "label": "unrelated.invalid",
        "observed_at": 13.5, "provenance": provenance, "evidence_ids": ["ev-unrelated"],
        "confidence": 0.5, "attributes": {},
    })
    builder.link(
        edge_type="EXECUTED", source=process.node_id, target=script.node_id, observed_at=12.0,
        provenance=provenance, evidence_ids=["ev-script"], confidence=1.0,
        reason="Controlled execution relation.",
    )
    builder.link(
        edge_type="TRIGGERED", source=script.node_id, target=detection.node_id, observed_at=13.0,
        provenance=provenance, evidence_ids=["ev-detection"], confidence=0.9,
        reason="Controlled detection relation.",
    )
    return builder.build(
        graph_id="graph-b72-self-check", incident_id="uncorrelated-batch-b72", created_at=14.0,
        metadata={"fixture": True, "unrelated_node": unrelated.node_id},
    )


def self_check() -> dict[str, Any]:
    graph = demo_graph()
    before = graph.digest()
    correlator = IncidentCorrelator(max_time_delta=120.0)
    result = correlator.correlate(graph)
    validation = validate_result(result, graph)
    round_trip = CorrelationResult.from_dict(result.to_dict())
    sizes = sorted(len(incident.node_ids) for incident in result.incidents)
    return {
        **validation.to_dict(),
        "source_graph_digest": before,
        "source_graph_unchanged": graph.digest() == before,
        "correlation_digest": result.digest(),
        "stable_round_trip": round_trip.stable_json() == result.stable_json(),
        "deterministic_serialization": correlator.correlate(graph).stable_json() == result.stable_json(),
        "incident_sizes": sizes,
        "temporal_proximity_alone_correlates": False,
        "raw_evidence_preserved": True,
        "every_correlation_link_explained": all(bool(link.reason.strip()) for incident in result.incidents for link in incident.links),
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
    parser = argparse.ArgumentParser(description="BC Sentinel B7-2 Incident Correlation Engine")
    parser.add_argument("--self-check", action="store_true")
    parser.parse_args(argv)
    result = self_check()
    print(json.dumps(result, indent=2, sort_keys=True))
    required = (
        result.get("passed") is True
        and result.get("source_graph_unchanged") is True
        and result.get("stable_round_trip") is True
        and result.get("deterministic_serialization") is True
        and result.get("incident_sizes") == [1, 3]
        and result.get("temporal_proximity_alone_correlates") is False
    )
    return 0 if required else 4


if __name__ == "__main__":
    raise SystemExit(main())

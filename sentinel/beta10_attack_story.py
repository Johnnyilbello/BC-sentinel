from __future__ import annotations

"""B10-2 Attack Story 2.0.

Build deterministic, evidence-bound incident stories from the accepted Security
Graph and Incident Correlation primitives. Missing stages remain UNKNOWN. The
module is read-only: it adds no detector, remediation, network, process-control
or privileged authority and never promotes coverage.
"""

import argparse
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Final

from sentinel import beta9_ransomware_controls, incident_correlation, ransomware_detector, security_graph

SCHEMA: Final[str] = "bc-sentinel-beta10-attack-story-v1"
PROFILE: Final[str] = "v0.11.0-beta.10-b102-attack-story"
SOURCE_CHECKPOINT: Final[str] = "checkpoint/v011-beta10-b101-pass"
SOURCE_CHECKPOINT_COMMIT: Final[str] = "d1ea57abcc69407cf0e17d5ff1e008bcf48ca9af"
BASELINE_COVERAGE: Final[dict[str, int]] = {"PARTIAL": 5, "GAP": 0, "VERIFIED": 1}

STAGE_DEFINITIONS: Final[tuple[tuple[str, str], ...]] = (
    ("ENTRY_POINT", "Punto d'ingresso"),
    ("EXECUTION", "Esecuzione"),
    ("PERSISTENCE", "Persistenza"),
    ("FILE_ACTIVITY", "Attività file"),
    ("NETWORK_ACTIVITY", "Attività di rete"),
    ("DETECTION", "Rilevamento"),
    ("RESPONSE", "Risposta"),
)
STAGE_IDS: Final[tuple[str, ...]] = tuple(item[0] for item in STAGE_DEFINITIONS)
STAGE_LABELS: Final[dict[str, str]] = dict(STAGE_DEFINITIONS)

AUTHORITY_BOUNDARY: Final[dict[str, bool]] = {
    "automatic_quarantine": False,
    "automatic_repair": False,
    "automatic_restore": False,
    "delete_authority": False,
    "repair_authority": False,
    "terminate_process_authority": False,
    "trust_allowlist_mutation": False,
    "privileged_system_mutation": False,
    "remote_access": False,
}
PRIVACY_BOUNDARY: Final[dict[str, bool]] = {
    "local_only": True,
    "personal_data_collected": False,
    "file_content_collected": False,
    "absolute_paths_exported": False,
    "remote_access": False,
}


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _utc_iso(timestamp: float) -> str:
    return datetime.fromtimestamp(float(timestamp), timezone.utc).isoformat().replace("+00:00", "Z")


def _stage_for_node(node: security_graph.GraphNode) -> str | None:
    explicit = str(node.attributes.get("attack_story_stage") or "").upper()
    if explicit in STAGE_IDS:
        return explicit
    if node.node_type == "DETECTION":
        return "DETECTION"
    if node.node_type == "ACTION":
        return "RESPONSE"
    if node.node_type == "PERSISTENCE":
        return "PERSISTENCE"
    if node.node_type in {"NETWORK", "DNS"}:
        return "NETWORK_ACTIVITY"
    if node.node_type in {"PROCESS", "SCRIPT"}:
        return "EXECUTION"
    if node.node_type == "FILE":
        return "FILE_ACTIVITY"
    if node.node_type == "EVIDENCE" and any(
        key in node.attributes
        for key in ("write_event_count", "rename_event_count", "entropy_delta", "extension_changed", "canary_touched")
    ):
        return "FILE_ACTIVITY"
    return None


def _claim_certainty(nodes: list[security_graph.GraphNode]) -> str:
    trusts = {str(node.provenance.get("trust") or "UNKNOWN").upper() for node in nodes}
    return "DIRECT_EVIDENCE" if trusts and trusts == {"DIRECT"} else "CORRELATED_EVIDENCE"


@dataclass(frozen=True)
class StoryClaim:
    claim_id: str
    stage_id: str
    certainty: str
    text: str
    evidence_ids: tuple[str, ...]
    node_ids: tuple[str, ...]
    edge_ids: tuple[str, ...] = field(default_factory=tuple)
    confidence: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "stage_id": self.stage_id,
            "certainty": self.certainty,
            "text": self.text,
            "evidence_ids": list(self.evidence_ids),
            "node_ids": list(self.node_ids),
            "edge_ids": list(self.edge_ids),
            "confidence": self.confidence,
        }


@dataclass(frozen=True)
class StoryStage:
    stage_id: str
    label: str
    order: int
    status: str
    started_at_utc: str | None
    ended_at_utc: str | None
    evidence_ids: tuple[str, ...]
    node_ids: tuple[str, ...]
    edge_ids: tuple[str, ...]
    confidence: float | None
    explanation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "stage_id": self.stage_id,
            "label": self.label,
            "order": self.order,
            "status": self.status,
            "started_at_utc": self.started_at_utc,
            "ended_at_utc": self.ended_at_utc,
            "evidence_ids": list(self.evidence_ids),
            "node_ids": list(self.node_ids),
            "edge_ids": list(self.edge_ids),
            "confidence": self.confidence,
            "explanation": self.explanation,
        }


@dataclass(frozen=True)
class AttackStory:
    story_id: str
    incident_id: str
    source_graph_digest: str
    source_correlation_digest: str
    stages: tuple[StoryStage, ...]
    claims: tuple[StoryClaim, ...]
    relationships: tuple[dict[str, Any], ...]
    plain_language_summary: str
    technical_summary: str
    source_live_control: bool = False

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "schema": SCHEMA,
            "profile": PROFILE,
            "source_checkpoint": SOURCE_CHECKPOINT,
            "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
            "story_id": self.story_id,
            "incident_id": self.incident_id,
            "source_graph_digest": self.source_graph_digest,
            "source_correlation_digest": self.source_correlation_digest,
            "stages": [stage.to_dict() for stage in self.stages],
            "claims": [claim.to_dict() for claim in self.claims],
            "relationships": list(self.relationships),
            "plain_language_summary": self.plain_language_summary,
            "technical_summary": self.technical_summary,
            "source_live_control": self.source_live_control,
            "coverage_summary": dict(BASELINE_COVERAGE),
            "coverage_changed": False,
            "broad_protection_claimed": False,
            "read_only": True,
            "authority_boundary": dict(AUTHORITY_BOUNDARY),
            "privacy": dict(PRIVACY_BOUNDARY),
        }
        payload["story_digest"] = _digest(payload)
        return payload


def _incident(
    correlation: incident_correlation.CorrelationResult,
    incident_id: str | None,
) -> incident_correlation.IncidentCluster:
    if not correlation.incidents:
        raise ValueError("attack_story:no_incident")
    if incident_id is None:
        if len(correlation.incidents) != 1:
            raise ValueError("attack_story:incident_id_required")
        return correlation.incidents[0]
    match = next((item for item in correlation.incidents if item.incident_id == incident_id), None)
    if match is None:
        raise ValueError("attack_story:incident_unknown")
    return match


def generate_story(
    *,
    graph: security_graph.SecurityGraph,
    correlation: incident_correlation.CorrelationResult,
    incident_id: str | None = None,
    source_live_control: bool = False,
) -> AttackStory:
    graph_before = graph.digest()
    correlation_before = correlation.digest()
    graph_validation = security_graph.validate_graph(graph.to_dict())
    if not graph_validation.passed:
        raise ValueError("attack_story:graph_invalid:" + ",".join(graph_validation.failures))
    correlation_validation = incident_correlation.validate_result(correlation, graph)
    if not correlation_validation.passed:
        raise ValueError("attack_story:correlation_invalid:" + ",".join(correlation_validation.failures))

    incident = _incident(correlation, incident_id)
    node_map = {node.node_id: node for node in graph.nodes}
    edge_map = {edge.edge_id: edge for edge in graph.edges}
    incident_nodes = [node_map[node_id] for node_id in incident.node_ids]
    incident_edges = [edge_map[edge_id] for edge_id in incident.graph_edge_ids]

    stage_nodes: dict[str, list[security_graph.GraphNode]] = {stage_id: [] for stage_id in STAGE_IDS}
    for node in incident_nodes:
        stage_id = _stage_for_node(node)
        if stage_id is not None:
            stage_nodes[stage_id].append(node)

    stages: list[StoryStage] = []
    claims: list[StoryClaim] = []
    for order, stage_id in enumerate(STAGE_IDS, start=1):
        nodes = sorted(stage_nodes[stage_id], key=lambda item: (item.observed_at, item.node_id))
        if not nodes:
            stages.append(
                StoryStage(
                    stage_id=stage_id,
                    label=STAGE_LABELS[stage_id],
                    order=order,
                    status="UNKNOWN",
                    started_at_utc=None,
                    ended_at_utc=None,
                    evidence_ids=(),
                    node_ids=(),
                    edge_ids=(),
                    confidence=None,
                    explanation="Nessuna prova accettata nell'incidente fornito dimostra questa fase.",
                )
            )
            continue

        node_ids = {node.node_id for node in nodes}
        related_edges = sorted(
            (edge for edge in incident_edges if edge.source in node_ids or edge.target in node_ids),
            key=lambda item: (item.observed_at, item.edge_id),
        )
        evidence_ids = tuple(sorted({eid for node in nodes for eid in node.evidence_ids}))
        edge_ids = tuple(edge.edge_id for edge in related_edges)
        confidences = [float(node.confidence) for node in nodes if node.confidence is not None]
        confidence = min(confidences) if confidences else None
        started = min(node.observed_at for node in nodes)
        ended = max(node.observed_at for node in nodes)
        explanation = (
            f"{len(nodes)} elemento/i del Security Graph supportano questa fase; "
            f"le prove restano limitate agli ID dichiarati."
        )
        stage = StoryStage(
            stage_id=stage_id,
            label=STAGE_LABELS[stage_id],
            order=order,
            status="OBSERVED",
            started_at_utc=_utc_iso(started),
            ended_at_utc=_utc_iso(ended),
            evidence_ids=evidence_ids,
            node_ids=tuple(sorted(node_ids)),
            edge_ids=edge_ids,
            confidence=confidence,
            explanation=explanation,
        )
        stages.append(stage)
        claim_material = {
            "stage_id": stage_id,
            "node_ids": stage.node_ids,
            "evidence_ids": stage.evidence_ids,
            "edge_ids": stage.edge_ids,
        }
        claims.append(
            StoryClaim(
                claim_id="story-claim:" + _digest(claim_material)[:24],
                stage_id=stage_id,
                certainty=_claim_certainty(nodes),
                text=f"Fase osservata: {STAGE_LABELS[stage_id]}.",
                evidence_ids=stage.evidence_ids,
                node_ids=stage.node_ids,
                edge_ids=stage.edge_ids,
                confidence=confidence,
            )
        )

    relationships: list[dict[str, Any]] = []
    for edge in sorted(incident_edges, key=lambda item: (item.observed_at, item.edge_id)):
        relationships.append(
            {
                "edge_id": edge.edge_id,
                "edge_type": edge.edge_type,
                "source_node_id": edge.source,
                "target_node_id": edge.target,
                "evidence_ids": list(edge.evidence_ids),
                "confidence": edge.confidence,
                "reason": edge.reason,
            }
        )

    observed = [stage for stage in stages if stage.status == "OBSERVED"]
    unknown = [stage for stage in stages if stage.status == "UNKNOWN"]
    observed_labels = " → ".join(stage.label for stage in observed) if observed else "nessuna fase"
    unknown_labels = ", ".join(stage.label for stage in unknown) if unknown else "nessuna"
    plain = (
        f"BC Sentinel dispone di prove per {len(observed)} fase/i: {observed_labels}. "
        f"Restano non dimostrate dalle prove disponibili: {unknown_labels}. "
        "Le fasi UNKNOWN non vengono dedotte o completate automaticamente."
    )
    technical = (
        f"incident={incident.incident_id}; graph={graph_before}; correlation={correlation_before}; "
        f"observed_stages={','.join(stage.stage_id for stage in observed)}; "
        f"unknown_stages={','.join(stage.stage_id for stage in unknown)}; "
        f"nodes={len(incident.node_ids)}; edges={len(incident.graph_edge_ids)}; read_only=true."
    )
    material = {
        "incident_id": incident.incident_id,
        "graph": graph_before,
        "correlation": correlation_before,
        "stages": [stage.to_dict() for stage in stages],
        "relationships": relationships,
    }
    story = AttackStory(
        story_id="attack-story:" + _digest(material)[:24],
        incident_id=incident.incident_id,
        source_graph_digest=graph_before,
        source_correlation_digest=correlation_before,
        stages=tuple(stages),
        claims=tuple(claims),
        relationships=tuple(relationships),
        plain_language_summary=plain,
        technical_summary=technical,
        source_live_control=bool(source_live_control),
    )
    validation = validate_story(story, graph=graph, correlation=correlation)
    if not validation["passed"]:
        raise ValueError("attack_story:output_invalid:" + ",".join(validation["failures"]))
    if graph.digest() != graph_before or correlation.digest() != correlation_before:
        raise RuntimeError("attack_story:source_mutated")
    return story


def validate_story(
    story: AttackStory | dict[str, Any],
    *,
    graph: security_graph.SecurityGraph,
    correlation: incident_correlation.CorrelationResult,
) -> dict[str, Any]:
    payload = story.to_dict() if isinstance(story, AttackStory) else story
    failures: list[str] = []
    if not isinstance(payload, dict):
        return {"passed": False, "failures": ["story:not_object"]}
    if payload.get("schema") != SCHEMA or payload.get("profile") != PROFILE:
        failures.append("story:schema_or_profile_invalid")
    if payload.get("source_checkpoint") != SOURCE_CHECKPOINT or payload.get("source_checkpoint_commit") != SOURCE_CHECKPOINT_COMMIT:
        failures.append("story:source_checkpoint_invalid")
    if payload.get("source_graph_digest") != graph.digest():
        failures.append("story:graph_digest_mismatch")
    if payload.get("source_correlation_digest") != correlation.digest():
        failures.append("story:correlation_digest_mismatch")
    if payload.get("coverage_summary") != BASELINE_COVERAGE or payload.get("coverage_changed") is not False:
        failures.append("story:coverage_boundary_invalid")
    if payload.get("broad_protection_claimed") is not False or payload.get("read_only") is not True:
        failures.append("story:claim_or_read_only_boundary_invalid")
    if payload.get("authority_boundary") != AUTHORITY_BOUNDARY or any(AUTHORITY_BOUNDARY.values()):
        failures.append("story:authority_boundary_invalid")
    if payload.get("privacy") != PRIVACY_BOUNDARY:
        failures.append("story:privacy_boundary_invalid")

    incident_id = str(payload.get("incident_id") or "")
    incident = next((item for item in correlation.incidents if item.incident_id == incident_id), None)
    if incident is None:
        failures.append("story:incident_unknown")
        return {"passed": False, "failures": failures}
    node_map = {node.node_id: node for node in graph.nodes}
    edge_map = {edge.edge_id: edge for edge in graph.edges}
    supported_evidence = {
        eid
        for node_id in incident.node_ids
        for eid in node_map[node_id].evidence_ids
    }
    supported_evidence.update(
        eid
        for edge_id in incident.graph_edge_ids
        for eid in edge_map[edge_id].evidence_ids
    )

    stages = payload.get("stages")
    if not isinstance(stages, list) or [item.get("stage_id") for item in stages if isinstance(item, dict)] != list(STAGE_IDS):
        failures.append("story:stage_order_invalid")
    else:
        for expected_order, stage in enumerate(stages, start=1):
            if not isinstance(stage, dict):
                failures.append("story:stage_not_object")
                continue
            if stage.get("order") != expected_order or stage.get("label") != STAGE_LABELS[stage["stage_id"]]:
                failures.append(f"story:{stage.get('stage_id')}:stage_identity_invalid")
            status = stage.get("status")
            evidence_ids = stage.get("evidence_ids")
            node_ids = stage.get("node_ids")
            edge_ids = stage.get("edge_ids")
            if status == "UNKNOWN":
                if evidence_ids or node_ids or edge_ids or stage.get("confidence") is not None or stage.get("started_at_utc") is not None or stage.get("ended_at_utc") is not None:
                    failures.append(f"story:{stage['stage_id']}:unknown_contains_evidence")
            elif status == "OBSERVED":
                if not isinstance(evidence_ids, list) or not evidence_ids or not set(evidence_ids).issubset(supported_evidence):
                    failures.append(f"story:{stage['stage_id']}:evidence_invalid")
                if not isinstance(node_ids, list) or not node_ids or not set(node_ids).issubset(set(incident.node_ids)):
                    failures.append(f"story:{stage['stage_id']}:nodes_invalid")
                if not isinstance(edge_ids, list) or not set(edge_ids).issubset(set(incident.graph_edge_ids)):
                    failures.append(f"story:{stage['stage_id']}:edges_invalid")
            else:
                failures.append(f"story:{stage['stage_id']}:status_invalid")

    claims = payload.get("claims")
    if not isinstance(claims, list):
        failures.append("story:claims_not_array")
    else:
        observed_ids = {stage["stage_id"] for stage in stages if isinstance(stage, dict) and stage.get("status") == "OBSERVED"} if isinstance(stages, list) else set()
        for claim in claims:
            if not isinstance(claim, dict) or claim.get("stage_id") not in observed_ids:
                failures.append("story:claim_stage_invalid")
                continue
            if not claim.get("evidence_ids") or not set(claim["evidence_ids"]).issubset(supported_evidence):
                failures.append("story:claim_evidence_invalid")
            if claim.get("certainty") not in {"DIRECT_EVIDENCE", "CORRELATED_EVIDENCE"}:
                failures.append("story:claim_certainty_invalid")

    if not isinstance(payload.get("plain_language_summary"), str) or not payload["plain_language_summary"]:
        failures.append("story:plain_summary_missing")
    if not isinstance(payload.get("technical_summary"), str) or not payload["technical_summary"]:
        failures.append("story:technical_summary_missing")
    return {
        "passed": not failures,
        "failures": failures,
        "observed_stage_count": sum(1 for stage in stages if isinstance(stage, dict) and stage.get("status") == "OBSERVED") if isinstance(stages, list) else 0,
        "unknown_stage_count": sum(1 for stage in stages if isinstance(stage, dict) and stage.get("status") == "UNKNOWN") if isinstance(stages, list) else 0,
        "claim_count": len(claims) if isinstance(claims, list) else 0,
    }


def story_from_b93_evidence(evidence: object) -> dict[str, Any]:
    summary = beta9_ransomware_controls.summarize(evidence)
    if not summary.get("passed"):
        return {"passed": False, "failures": ["story:b93_live_evidence_not_accepted"]}
    if summary.get("coverage_summary") != BASELINE_COVERAGE:
        return {"passed": False, "failures": ["story:coverage_baseline_changed"]}
    if not isinstance(evidence, dict):
        return {"passed": False, "failures": ["story:evidence_not_object"]}
    controls = evidence.get("controls")
    if not isinstance(controls, list):
        return {"passed": False, "failures": ["story:controls_missing"]}
    positive = next((row for row in controls if isinstance(row, dict) and row.get("control_id") == "positive-ransomware-like"), None)
    if positive is None:
        return {"passed": False, "failures": ["story:positive_control_missing"]}

    observation, evidence_id = beta9_ransomware_controls._observation(positive)
    result = ransomware_detector.detect((observation,))
    graph, correlation = beta9_ransomware_controls._positive_graph(observation, result, evidence_id)
    if graph.digest() != summary.get("graph_digest") or correlation.digest() != summary.get("correlation_digest"):
        return {"passed": False, "failures": ["story:b93_graph_binding_mismatch"]}
    story = generate_story(graph=graph, correlation=correlation, source_live_control=True)
    payload = story.to_dict()
    validation = validate_story(payload, graph=graph, correlation=correlation)
    payload.update(
        {
            "passed": bool(validation["passed"]),
            "failures": list(validation["failures"]),
            "source_proof_evidence_id": evidence_id,
            "source_detector_outcome": result.outcome,
            "source_detector_score": result.score,
            "source_matched_signals": list(result.matched_signals),
            "detector_to_security_graph_bound": bool(summary.get("detector_to_security_graph_bound")),
            "security_graph_to_incident_bound": bool(summary.get("security_graph_to_incident_bound")),
            "synthetic_fallback_used": False,
        }
    )
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--b93-evidence", type=Path, required=True)
    args = parser.parse_args()
    try:
        evidence = json.loads(args.b93_evidence.read_text(encoding="utf-8-sig"))
        result = story_from_b93_evidence(evidence)
    except (OSError, UnicodeError, ValueError) as exc:
        result = {"passed": False, "failures": [f"story:input_error:{type(exc).__name__}"]}
    print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))
    return 0 if result.get("passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())

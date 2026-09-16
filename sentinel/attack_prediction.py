from __future__ import annotations

"""B8-5 deterministic, advisory-only next-stage prediction foundation."""

import argparse
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Final

from sentinel import attack_chain_harness, incident_correlation, security_graph

SCHEMA: Final[str] = "bc-sentinel-attack-prediction-v1"
PROFILE: Final[str] = "v0.11.0-beta.8-b85-attack-prediction"
OUTCOME_PREDICTED: Final[str] = "PREDICTED"
OUTCOME_REVIEW: Final[str] = "REVIEW_REQUIRED"
OUTCOME_INSUFFICIENT: Final[str] = "INSUFFICIENT_EVIDENCE"

TRANSITIONS: Final[dict[tuple[str, ...], tuple[str, float, str]]] = {
    ("PROCESS", "SCRIPT"): ("PERSISTENCE", 0.65, OUTCOME_REVIEW),
    ("PROCESS", "SCRIPT", "PERSISTENCE"): ("DNS", 0.78, OUTCOME_PREDICTED),
    ("PROCESS", "SCRIPT", "PERSISTENCE", "DNS"): ("DETECTION", 0.88, OUTCOME_PREDICTED),
}

FALSE_AUTHORITY_FIELDS: Final[tuple[str, ...]] = (
    "prediction_is_evidence",
    "graph_mutation",
    "correlation_mutation",
    "process_execution",
    "file_write",
    "network_io",
    "registry_mutation",
    "credential_access",
    "remediation_execution",
    "automatic_quarantine",
    "automatic_repair",
    "automatic_restore",
    "general_home_execution_authorized",
    "delete_authorized",
    "repair_authorized",
    "terminate_process_authorized",
    "trust_allowlist_mutation_authorized",
    "privileged_system_mutation_authorized",
    "authority_granted",
    "execution_authority_added",
)


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _stable_hash(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class PredictionResult:
    incident_id: str
    observed_node_ids: tuple[str, ...]
    observed_stage_order: tuple[str, ...]
    supporting_evidence_ids: tuple[str, ...]
    predicted_stage: str | None
    confidence: float | None
    outcome: str
    rationale: str
    source_graph_digest: str
    source_correlation_digest: str

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema": SCHEMA,
            "profile": PROFILE,
            "incident_id": self.incident_id,
            "observed_node_ids": list(self.observed_node_ids),
            "observed_stage_order": list(self.observed_stage_order),
            "supporting_evidence_ids": list(self.supporting_evidence_ids),
            "predicted_stage": self.predicted_stage,
            "confidence": self.confidence,
            "outcome": self.outcome,
            "rationale": self.rationale,
            "source_graph_digest": self.source_graph_digest,
            "source_correlation_digest": self.source_correlation_digest,
            "advisory_only": True,
            "observed_evidence_preserved": True,
        }
        payload.update({field: False for field in FALSE_AUTHORITY_FIELDS})
        return payload

    def stable_json(self) -> str:
        return _canonical_json(self.to_dict())

    def digest(self) -> str:
        return _stable_hash(self.to_dict())

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "PredictionResult":
        return cls(
            incident_id=str(payload.get("incident_id") or ""),
            observed_node_ids=tuple(str(item) for item in payload.get("observed_node_ids") or []),
            observed_stage_order=tuple(str(item) for item in payload.get("observed_stage_order") or []),
            supporting_evidence_ids=tuple(str(item) for item in payload.get("supporting_evidence_ids") or []),
            predicted_stage=(str(payload["predicted_stage"]) if payload.get("predicted_stage") is not None else None),
            confidence=(float(payload["confidence"]) if payload.get("confidence") is not None else None),
            outcome=str(payload.get("outcome") or ""),
            rationale=str(payload.get("rationale") or ""),
            source_graph_digest=str(payload.get("source_graph_digest") or ""),
            source_correlation_digest=str(payload.get("source_correlation_digest") or ""),
        )


@dataclass(frozen=True)
class PredictionValidation:
    passed: bool
    failures: tuple[str, ...]


def validate_result(payload: PredictionResult | dict[str, Any]) -> PredictionValidation:
    data = payload.to_dict() if isinstance(payload, PredictionResult) else payload
    failures: list[str] = []
    if data.get("schema") != SCHEMA or data.get("profile") != PROFILE:
        failures.append("prediction:schema_or_profile_invalid")
    stages = data.get("observed_stage_order")
    nodes = data.get("observed_node_ids")
    evidence = data.get("supporting_evidence_ids")
    if not isinstance(stages, list) or not stages:
        failures.append("prediction:observed_stages_missing")
    if not isinstance(nodes, list) or len(nodes) != len(stages or []):
        failures.append("prediction:observed_nodes_invalid")
    if not isinstance(evidence, list) or not evidence or evidence != sorted(set(evidence)):
        failures.append("prediction:supporting_evidence_invalid")
    outcome = data.get("outcome")
    predicted = data.get("predicted_stage")
    confidence = data.get("confidence")
    if outcome == OUTCOME_INSUFFICIENT:
        if predicted is not None or confidence is not None:
            failures.append("prediction:insufficient_must_not_predict")
    elif outcome in {OUTCOME_PREDICTED, OUTCOME_REVIEW}:
        if not isinstance(predicted, str) or not predicted:
            failures.append("prediction:predicted_stage_missing")
        if not isinstance(confidence, (int, float)) or not 0.0 <= float(confidence) <= 1.0:
            failures.append("prediction:confidence_invalid")
    else:
        failures.append("prediction:outcome_invalid")
    if data.get("advisory_only") is not True:
        failures.append("prediction:advisory_only_required")
    if data.get("observed_evidence_preserved") is not True:
        failures.append("prediction:evidence_preservation_required")
    if not str(data.get("source_graph_digest") or "") or not str(data.get("source_correlation_digest") or ""):
        failures.append("prediction:source_digest_missing")
    for field in FALSE_AUTHORITY_FIELDS:
        if data.get(field) is not False:
            failures.append(f"prediction:{field}_must_be_false")
    return PredictionValidation(not failures, tuple(failures))


def predict_next_stage(
    graph: security_graph.SecurityGraph,
    correlation: incident_correlation.CorrelationResult,
    *,
    incident_id: str,
    observed_node_ids: tuple[str, ...],
) -> PredictionResult:
    graph_validation = security_graph.validate_graph(graph.to_dict())
    correlation_validation = incident_correlation.validate_result(correlation, graph)
    if not graph_validation.passed:
        raise ValueError("prediction_source_graph_invalid:" + ",".join(graph_validation.failures))
    if not correlation_validation.passed:
        raise ValueError("prediction_source_correlation_invalid:" + ",".join(correlation_validation.failures))

    incidents = {item.incident_id: item for item in correlation.incidents}
    incident = incidents.get(incident_id)
    if incident is None:
        raise ValueError("prediction_incident_not_found")
    if not observed_node_ids or len(set(observed_node_ids)) != len(observed_node_ids):
        raise ValueError("prediction_observed_nodes_invalid")
    if not set(observed_node_ids).issubset(set(incident.node_ids)):
        raise ValueError("prediction_nodes_not_bound_to_incident")

    node_map = {node.node_id: node for node in graph.nodes}
    try:
        ordered = tuple(sorted((node_map[node_id] for node_id in observed_node_ids), key=lambda node: (node.observed_at, node.node_id)))
    except KeyError as exc:
        raise ValueError("prediction_observed_node_missing") from exc
    stages = tuple(node.node_type for node in ordered)
    evidence_ids = tuple(sorted({evidence_id for node in ordered for evidence_id in node.evidence_ids}))
    transition = TRANSITIONS.get(stages)
    if transition is None:
        predicted_stage = None
        confidence = None
        outcome = OUTCOME_INSUFFICIENT
        rationale = "Observed incident stages do not match an accepted deterministic transition; no next stage is predicted."
    else:
        predicted_stage, confidence, outcome = transition
        rationale = (
            f"Accepted synthetic transition {stages[-1]} -> {predicted_stage}; advisory hypothesis only, "
            "never evidence and never execution authority."
        )

    result = PredictionResult(
        incident_id=incident_id,
        observed_node_ids=tuple(node.node_id for node in ordered),
        observed_stage_order=stages,
        supporting_evidence_ids=evidence_ids,
        predicted_stage=predicted_stage,
        confidence=confidence,
        outcome=outcome,
        rationale=rationale,
        source_graph_digest=graph.digest(),
        source_correlation_digest=correlation.digest(),
    )
    validation = validate_result(result)
    if not validation.passed:
        raise ValueError("prediction_result_invalid:" + ",".join(validation.failures))
    return result


def _fixture() -> tuple[security_graph.SecurityGraph, incident_correlation.CorrelationResult, tuple[str, ...], str]:
    graph, stage_node_ids = attack_chain_harness.build_controlled_graph()
    correlation = incident_correlation.IncidentCorrelator(max_time_delta=120.0).correlate(graph)
    incident = next(item for item in correlation.incidents if set(stage_node_ids).issubset(set(item.node_ids)))
    return graph, correlation, stage_node_ids, incident.incident_id


def self_check() -> dict[str, Any]:
    graph, correlation, node_ids, incident_id = _fixture()
    graph_before = graph.digest()
    correlation_before = correlation.digest()
    predicted = predict_next_stage(graph, correlation, incident_id=incident_id, observed_node_ids=node_ids[:3])
    repeated = predict_next_stage(graph, correlation, incident_id=incident_id, observed_node_ids=node_ids[:3])
    insufficient = predict_next_stage(graph, correlation, incident_id=incident_id, observed_node_ids=node_ids[:1])
    round_trip = PredictionResult.from_dict(predicted.to_dict()).stable_json() == predicted.stable_json()
    failures: list[str] = []
    if predicted.predicted_stage != "DNS" or predicted.outcome != OUTCOME_PREDICTED or predicted.confidence != 0.78:
        failures.append("prediction:expected_transition_missing")
    if insufficient.outcome != OUTCOME_INSUFFICIENT or insufficient.predicted_stage is not None:
        failures.append("prediction:insufficient_case_invalid")
    if predicted.stable_json() != repeated.stable_json():
        failures.append("prediction:not_deterministic")
    if graph.digest() != graph_before or correlation.digest() != correlation_before:
        failures.append("prediction:source_mutated")
    if not round_trip:
        failures.append("prediction:round_trip_unstable")
    payload = predicted.to_dict()
    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "passed": not failures,
        "failures": failures,
        "observed_stage_order": list(predicted.observed_stage_order),
        "predicted_stage": predicted.predicted_stage,
        "confidence": predicted.confidence,
        "outcome": predicted.outcome,
        "insufficient_outcome": insufficient.outcome,
        "prediction_digest": predicted.digest(),
        "source_graph_digest": graph_before,
        "source_correlation_digest": correlation_before,
        "deterministic_serialization": predicted.stable_json() == repeated.stable_json(),
        "stable_round_trip": round_trip,
        "source_unchanged": graph.digest() == graph_before and correlation.digest() == correlation_before,
        "synthetic_fixture_only": True,
        "advisory_only": payload["advisory_only"],
        **{field: payload[field] for field in FALSE_AUTHORITY_FIELDS},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel B8-5 attack prediction foundation")
    parser.add_argument("--self-check", action="store_true")
    args = parser.parse_args()
    if not args.self_check:
        parser.error("only --self-check is supported")
    result = self_check()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

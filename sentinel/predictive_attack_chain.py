from __future__ import annotations

"""B8-6 controlled multi-stage prediction validation, advisory only."""

import argparse
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Final

from sentinel import attack_prediction

SCHEMA: Final[str] = "bc-sentinel-predictive-attack-chain-v1"
PROFILE: Final[str] = "v0.11.0-beta.8-b86-predictive-chain"
EXPECTED_CHAIN: Final[tuple[str, ...]] = ("PROCESS", "SCRIPT", "PERSISTENCE", "DNS", "DETECTION")

FALSE_AUTHORITY_FIELDS: Final[tuple[str, ...]] = attack_prediction.FALSE_AUTHORITY_FIELDS


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@dataclass(frozen=True)
class ChainPrediction:
    observed_stages: tuple[str, ...]
    actual_next_stage: str
    predicted_stage: str
    confidence: float
    outcome: str
    prediction_digest: str
    supporting_evidence_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "observed_stages": list(self.observed_stages),
            "actual_next_stage": self.actual_next_stage,
            "predicted_stage": self.predicted_stage,
            "confidence": self.confidence,
            "outcome": self.outcome,
            "prediction_digest": self.prediction_digest,
            "supporting_evidence_ids": list(self.supporting_evidence_ids),
            "matched": self.predicted_stage == self.actual_next_stage,
        }


@dataclass(frozen=True)
class PredictiveChainReport:
    incident_id: str
    source_graph_digest: str
    source_correlation_digest: str
    chain_order: tuple[str, ...]
    predictions: tuple[ChainPrediction, ...]
    accuracy: float
    brier_score: float

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema": SCHEMA,
            "profile": PROFILE,
            "incident_id": self.incident_id,
            "source_graph_digest": self.source_graph_digest,
            "source_correlation_digest": self.source_correlation_digest,
            "chain_order": list(self.chain_order),
            "predictions": [item.to_dict() for item in self.predictions],
            "prediction_count": len(self.predictions),
            "accuracy": self.accuracy,
            "brier_score": self.brier_score,
            "confidence_monotonic": all(
                self.predictions[index].confidence < self.predictions[index + 1].confidence
                for index in range(len(self.predictions) - 1)
            ),
            "advisory_only": True,
            "predictions_are_evidence": False,
            "synthetic_fixture_only": True,
        }
        payload.update({field: False for field in FALSE_AUTHORITY_FIELDS})
        return payload

    def stable_json(self) -> str:
        return _canonical_json(self.to_dict())

    def digest(self) -> str:
        return hashlib.sha256(self.stable_json().encode("utf-8")).hexdigest()


def run_controlled_chain() -> PredictiveChainReport:
    graph, correlation, node_ids, incident_id = attack_prediction._fixture()
    graph_digest = graph.digest()
    correlation_digest = correlation.digest()
    node_map = {node.node_id: node for node in graph.nodes}
    chain_order = tuple(node_map[node_id].node_type for node_id in node_ids)
    if chain_order != EXPECTED_CHAIN:
        raise ValueError("predictive_chain_order_invalid")
    predictions: list[ChainPrediction] = []
    for prefix_length in (2, 3, 4):
        prediction = attack_prediction.predict_next_stage(
            graph,
            correlation,
            incident_id=incident_id,
            observed_node_ids=node_ids[:prefix_length],
        )
        if prediction.predicted_stage is None or prediction.confidence is None:
            raise ValueError("predictive_chain_expected_prediction_missing")
        predictions.append(
            ChainPrediction(
                observed_stages=prediction.observed_stage_order,
                actual_next_stage=chain_order[prefix_length],
                predicted_stage=prediction.predicted_stage,
                confidence=prediction.confidence,
                outcome=prediction.outcome,
                prediction_digest=prediction.digest(),
                supporting_evidence_ids=prediction.supporting_evidence_ids,
            )
        )
    accuracy = sum(item.predicted_stage == item.actual_next_stage for item in predictions) / len(predictions)
    brier = sum((item.confidence - 1.0) ** 2 for item in predictions) / len(predictions)
    if graph.digest() != graph_digest or correlation.digest() != correlation_digest:
        raise RuntimeError("predictive_chain_source_mutated")
    return PredictiveChainReport(
        incident_id=incident_id,
        source_graph_digest=graph_digest,
        source_correlation_digest=correlation_digest,
        chain_order=chain_order,
        predictions=tuple(predictions),
        accuracy=round(accuracy, 6),
        brier_score=round(brier, 6),
    )


def validate_report(payload: PredictiveChainReport | dict[str, Any]) -> tuple[str, ...]:
    data = payload.to_dict() if isinstance(payload, PredictiveChainReport) else payload
    failures: list[str] = []
    if data.get("schema") != SCHEMA or data.get("profile") != PROFILE:
        failures.append("predictive_chain:schema_or_profile_invalid")
    if data.get("chain_order") != list(EXPECTED_CHAIN):
        failures.append("predictive_chain:order_invalid")
    if data.get("prediction_count") != 3 or len(data.get("predictions") or []) != 3:
        failures.append("predictive_chain:prediction_count_invalid")
    if data.get("accuracy") != 1.0:
        failures.append("predictive_chain:accuracy_invalid")
    if data.get("confidence_monotonic") is not True:
        failures.append("predictive_chain:confidence_not_monotonic")
    if data.get("advisory_only") is not True or data.get("predictions_are_evidence") is not False:
        failures.append("predictive_chain:evidence_boundary_invalid")
    for item in data.get("predictions") or []:
        if not isinstance(item, dict) or item.get("matched") is not True:
            failures.append("predictive_chain:prediction_mismatch")
        if not item.get("supporting_evidence_ids"):
            failures.append("predictive_chain:evidence_missing")
    for field in FALSE_AUTHORITY_FIELDS:
        if data.get(field) is not False:
            failures.append(f"predictive_chain:{field}_must_be_false")
    return tuple(failures)


def self_check() -> dict[str, Any]:
    first = run_controlled_chain()
    second = run_controlled_chain()
    failures = list(validate_report(first))
    deterministic = first.stable_json() == second.stable_json()
    if not deterministic:
        failures.append("predictive_chain:not_deterministic")
    payload = first.to_dict()
    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "passed": not failures,
        "failures": failures,
        "chain_order": list(first.chain_order),
        "predicted_stages": [item.predicted_stage for item in first.predictions],
        "confidences": [item.confidence for item in first.predictions],
        "accuracy": first.accuracy,
        "brier_score": first.brier_score,
        "prediction_count": len(first.predictions),
        "report_digest": first.digest(),
        "deterministic_serialization": deterministic,
        "confidence_monotonic": payload["confidence_monotonic"],
        "advisory_only": payload["advisory_only"],
        "predictions_are_evidence": payload["predictions_are_evidence"],
        "synthetic_fixture_only": payload["synthetic_fixture_only"],
        **{field: payload[field] for field in FALSE_AUTHORITY_FIELDS},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel B8-6 predictive multi-stage chain")
    parser.add_argument("--self-check", action="store_true")
    args = parser.parse_args()
    if not args.self_check:
        parser.error("only --self-check is supported")
    result = self_check()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

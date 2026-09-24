from __future__ import annotations

"""B8-1 deterministic ransomware-like detector acceptance path.

The detector consumes normalized, already-observed file activity fixtures. It
never opens, writes, renames, encrypts, or deletes files. It emits advisory
evidence only and preserves provenance for the accepted Security Graph and
Incident Correlation foundations.
"""

from dataclasses import dataclass, field
import argparse
import hashlib
import json
import math
from typing import Any, Final, Iterable

from sentinel import beta8_coverage_baseline, incident_correlation, security_graph

SCHEMA: Final[str] = "bc-sentinel-ransomware-detector-v1"
PROFILE: Final[str] = "v0.11.0-beta.8-b81-ransomware-detector"
SOURCE_CHECKPOINT: Final[str] = "checkpoint/v011-beta8-repository-hygiene-pass"
SOURCE_CHECKPOINT_COMMIT: Final[str] = "c33a06d6487115f5ae080edede75f5e63c6bf188"
TARGET_SCENARIO_ID: Final[str] = "B7-RANSOMWARE-001"

OUTCOME_DETECTED: Final[str] = "DETECTED"
OUTCOME_REVIEW: Final[str] = "REVIEW_REQUIRED"
OUTCOME_NO_MATCH: Final[str] = "NO_MATCH"
ALLOWED_OUTCOMES: Final[set[str]] = {OUTCOME_DETECTED, OUTCOME_REVIEW, OUTCOME_NO_MATCH}

SIGNAL_BULK_REWRITE: Final[str] = "BULK_REWRITE"
SIGNAL_BULK_RENAME: Final[str] = "BULK_RENAME"
SIGNAL_ENTROPY_SHIFT: Final[str] = "ENTROPY_SHIFT"
SIGNAL_EXTENSION_CHURN: Final[str] = "EXTENSION_CHURN"
SIGNAL_CANARY_TOUCH: Final[str] = "CANARY_TOUCH"
ALLOWED_SIGNALS: Final[set[str]] = {
    SIGNAL_BULK_REWRITE,
    SIGNAL_BULK_RENAME,
    SIGNAL_ENTROPY_SHIFT,
    SIGNAL_EXTENSION_CHURN,
    SIGNAL_CANARY_TOUCH,
}

MIN_BULK_WRITES: Final[int] = 20
MIN_BULK_RENAMES: Final[int] = 15
MIN_ENTROPY_DELTA: Final[float] = 0.30
DETECT_SCORE: Final[int] = 6
REVIEW_SCORE: Final[int] = 3

FALSE_SAFETY_FIELDS: Final[tuple[str, ...]] = (
    "process_execution",
    "file_read",
    "file_write",
    "file_rename",
    "file_delete",
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


def _nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _valid_number(value: Any) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        numeric = float(value)
    except (OverflowError, TypeError, ValueError):
        return False
    return math.isfinite(numeric)


def _validate_provenance(value: Any, prefix: str) -> list[str]:
    failures: list[str] = []
    if not isinstance(value, dict):
        return [f"{prefix}:provenance_not_object"]
    for field_name in ("source", "source_id", "collector"):
        if not _nonempty(value.get(field_name)):
            failures.append(f"{prefix}:provenance_{field_name}_invalid")
    trust = str(value.get("trust") or "").upper()
    if trust not in security_graph.ALLOWED_PROVENANCE_TRUST:
        failures.append(f"{prefix}:provenance_trust_invalid")
    return failures


@dataclass(frozen=True)
class FileActivityObservation:
    event_id: str
    observed_at: float
    logical_path: str
    evidence_id: str
    provenance: dict[str, Any]
    write_count_window: int = 0
    rename_count_window: int = 0
    entropy_delta: float = 0.0
    extension_changed: bool = False
    canary_touched: bool = False
    known_backup_workflow: bool = False
    user_initiated_bulk_operation: bool = False
    correlation_key: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "observed_at": self.observed_at,
            "logical_path": self.logical_path,
            "evidence_id": self.evidence_id,
            "provenance": dict(self.provenance),
            "write_count_window": self.write_count_window,
            "rename_count_window": self.rename_count_window,
            "entropy_delta": self.entropy_delta,
            "extension_changed": self.extension_changed,
            "canary_touched": self.canary_touched,
            "known_backup_workflow": self.known_backup_workflow,
            "user_initiated_bulk_operation": self.user_initiated_bulk_operation,
            "correlation_key": self.correlation_key,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "FileActivityObservation":
        return cls(
            event_id=str(payload.get("event_id") or ""),
            observed_at=float(payload.get("observed_at") or 0.0),
            logical_path=str(payload.get("logical_path") or ""),
            evidence_id=str(payload.get("evidence_id") or ""),
            provenance=dict(payload.get("provenance") or {}),
            write_count_window=int(payload.get("write_count_window") or 0),
            rename_count_window=int(payload.get("rename_count_window") or 0),
            entropy_delta=float(payload.get("entropy_delta") or 0.0),
            extension_changed=bool(payload.get("extension_changed", False)),
            canary_touched=bool(payload.get("canary_touched", False)),
            known_backup_workflow=bool(payload.get("known_backup_workflow", False)),
            user_initiated_bulk_operation=bool(payload.get("user_initiated_bulk_operation", False)),
            correlation_key=str(payload.get("correlation_key") or ""),
        )


@dataclass(frozen=True)
class DetectionResult:
    outcome: str
    score: int
    matched_signals: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    event_ids: tuple[str, ...]
    first_observed_at: float
    detection_observed_at: float
    detection_latency: float
    suppressor_reasons: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "profile": PROFILE,
            "source_checkpoint": SOURCE_CHECKPOINT,
            "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
            "target_scenario_id": TARGET_SCENARIO_ID,
            "outcome": self.outcome,
            "score": self.score,
            "matched_signals": list(self.matched_signals),
            "evidence_ids": list(self.evidence_ids),
            "event_ids": list(self.event_ids),
            "first_observed_at": self.first_observed_at,
            "detection_observed_at": self.detection_observed_at,
            "detection_latency": self.detection_latency,
            "suppressor_reasons": list(self.suppressor_reasons),
            "coverage_status": "PARTIAL",
            "read_only": True,
            "synthetic_fixture_only": True,
            "process_execution": False,
            "file_read": False,
            "file_write": False,
            "file_rename": False,
            "file_delete": False,
            "network_io": False,
            "registry_mutation": False,
            "credential_access": False,
            "remediation_execution": False,
            "automatic_quarantine": False,
            "automatic_repair": False,
            "automatic_restore": False,
            "general_home_execution_authorized": False,
            "delete_authorized": False,
            "repair_authorized": False,
            "terminate_process_authorized": False,
            "trust_allowlist_mutation_authorized": False,
            "privileged_system_mutation_authorized": False,
            "authority_granted": False,
            "execution_authority_added": False,
        }

    def stable_json(self) -> str:
        return _canonical_json(self.to_dict())

    def digest(self) -> str:
        return hashlib.sha256(self.stable_json().encode("utf-8")).hexdigest()

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "DetectionResult":
        return cls(
            outcome=str(payload.get("outcome") or ""),
            score=int(payload.get("score") or 0),
            matched_signals=tuple(sorted(str(item) for item in (payload.get("matched_signals") or []))),
            evidence_ids=tuple(sorted(str(item) for item in (payload.get("evidence_ids") or []))),
            event_ids=tuple(sorted(str(item) for item in (payload.get("event_ids") or []))),
            first_observed_at=float(payload.get("first_observed_at") or 0.0),
            detection_observed_at=float(payload.get("detection_observed_at") or 0.0),
            detection_latency=float(payload.get("detection_latency") or 0.0),
            suppressor_reasons=tuple(sorted(str(item) for item in (payload.get("suppressor_reasons") or []))),
        )


@dataclass(frozen=True)
class DetectorValidation:
    passed: bool
    failures: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "profile": PROFILE,
            "passed": self.passed,
            "failures": list(self.failures),
            "read_only": True,
            "execution_authority_added": False,
        }


def validate_observations(observations: Iterable[FileActivityObservation]) -> DetectorValidation:
    failures: list[str] = []
    items = tuple(observations)
    if not items:
        return DetectorValidation(False, ("observations:empty",))
    seen_events: set[str] = set()
    seen_evidence: set[str] = set()
    for index, item in enumerate(items):
        prefix = f"observation[{index}]"
        if not isinstance(item, FileActivityObservation):
            failures.append(f"{prefix}:type_invalid")
            continue
        if not _nonempty(item.event_id):
            failures.append(f"{prefix}:event_id_invalid")
        elif item.event_id in seen_events:
            failures.append(f"{prefix}:duplicate_event_id")
        seen_events.add(item.event_id)
        if not _nonempty(item.evidence_id):
            failures.append(f"{prefix}:evidence_id_invalid")
        elif item.evidence_id in seen_evidence:
            failures.append(f"{prefix}:duplicate_evidence_id")
        seen_evidence.add(item.evidence_id)
        if not _nonempty(item.logical_path):
            failures.append(f"{prefix}:logical_path_invalid")
        if not _valid_number(item.observed_at) or item.observed_at < 0:
            failures.append(f"{prefix}:observed_at_invalid")
        if isinstance(item.write_count_window, bool) or not isinstance(item.write_count_window, int) or item.write_count_window < 0:
            failures.append(f"{prefix}:write_count_invalid")
        if isinstance(item.rename_count_window, bool) or not isinstance(item.rename_count_window, int) or item.rename_count_window < 0:
            failures.append(f"{prefix}:rename_count_invalid")
        if not _valid_number(item.entropy_delta) or item.entropy_delta < 0:
            failures.append(f"{prefix}:entropy_delta_invalid")
        for field_name in (
            "extension_changed",
            "canary_touched",
            "known_backup_workflow",
            "user_initiated_bulk_operation",
        ):
            if not isinstance(getattr(item, field_name), bool):
                failures.append(f"{prefix}:{field_name}_invalid")
        failures.extend(_validate_provenance(item.provenance, prefix))
        if not isinstance(item.correlation_key, str):
            failures.append(f"{prefix}:correlation_key_invalid")
        elif item.correlation_key and not item.correlation_key.strip():
            failures.append(f"{prefix}:correlation_key_invalid")

    valid_items = tuple(item for item in items if isinstance(item, FileActivityObservation))
    if len(valid_items) > 1:
        keys = tuple(item.correlation_key for item in valid_items)
        if any(not isinstance(key, str) or not key.strip() for key in keys):
            failures.append("observations:correlation_key_required_for_batch")
        elif len(set(keys)) != 1:
            failures.append("observations:mixed_correlation_keys")
    return DetectorValidation(not failures, tuple(dict.fromkeys(failures)))


def _signals(observation: FileActivityObservation) -> set[str]:
    signals: set[str] = set()
    if observation.write_count_window >= MIN_BULK_WRITES:
        signals.add(SIGNAL_BULK_REWRITE)
    if observation.rename_count_window >= MIN_BULK_RENAMES:
        signals.add(SIGNAL_BULK_RENAME)
    if observation.entropy_delta >= MIN_ENTROPY_DELTA:
        signals.add(SIGNAL_ENTROPY_SHIFT)
    if observation.extension_changed:
        signals.add(SIGNAL_EXTENSION_CHURN)
    if observation.canary_touched:
        signals.add(SIGNAL_CANARY_TOUCH)
    return signals


def _score(signals: set[str]) -> int:
    weights = {
        SIGNAL_BULK_REWRITE: 2,
        SIGNAL_BULK_RENAME: 2,
        SIGNAL_ENTROPY_SHIFT: 2,
        SIGNAL_EXTENSION_CHURN: 1,
        SIGNAL_CANARY_TOUCH: 3,
    }
    return sum(weights[item] for item in signals)


def detect(observations: Iterable[FileActivityObservation]) -> DetectionResult:
    items = tuple(observations)
    validation = validate_observations(items)
    if not validation.passed:
        raise ValueError("ransomware_detector_invalid_input:" + ",".join(validation.failures))
    items = tuple(sorted(items, key=lambda item: (item.observed_at, item.event_id)))

    all_signals: set[str] = set()
    evidence_ids: set[str] = set()
    event_ids: set[str] = set()
    suppressors: set[str] = set()
    for item in items:
        all_signals.update(_signals(item))
        evidence_ids.add(item.evidence_id)
        event_ids.add(item.event_id)
        if item.known_backup_workflow:
            suppressors.add("KNOWN_BACKUP_WORKFLOW")
        if item.user_initiated_bulk_operation:
            suppressors.add("USER_INITIATED_BULK_OPERATION")

    score = _score(all_signals)
    destructive_pattern = bool({SIGNAL_BULK_REWRITE, SIGNAL_BULK_RENAME} & all_signals)
    content_change_pattern = SIGNAL_ENTROPY_SHIFT in all_signals or SIGNAL_EXTENSION_CHURN in all_signals
    high_confidence_shape = destructive_pattern and content_change_pattern and score >= DETECT_SCORE

    if suppressors:
        outcome = OUTCOME_REVIEW if score >= REVIEW_SCORE else OUTCOME_NO_MATCH
    elif high_confidence_shape:
        outcome = OUTCOME_DETECTED
    elif score >= REVIEW_SCORE:
        outcome = OUTCOME_REVIEW
    else:
        outcome = OUTCOME_NO_MATCH

    first = min(float(item.observed_at) for item in items)
    detected_at = max(float(item.observed_at) for item in items)
    return DetectionResult(
        outcome=outcome,
        score=score,
        matched_signals=tuple(sorted(all_signals)),
        evidence_ids=tuple(sorted(evidence_ids)),
        event_ids=tuple(sorted(event_ids)),
        first_observed_at=first,
        detection_observed_at=detected_at,
        detection_latency=detected_at - first,
        suppressor_reasons=tuple(sorted(suppressors)),
    )


def validate_result(payload: dict[str, Any] | Any) -> DetectorValidation:
    failures: list[str] = []
    if not isinstance(payload, dict):
        return DetectorValidation(False, ("result:not_object",))
    exact = {
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "target_scenario_id": TARGET_SCENARIO_ID,
        "coverage_status": "PARTIAL",
    }
    for field_name, expected in exact.items():
        if payload.get(field_name) != expected:
            failures.append(f"result:{field_name}_mismatch")
    outcome = payload.get("outcome")
    if not isinstance(outcome, str) or outcome not in ALLOWED_OUTCOMES:
        failures.append("result:outcome_invalid")
    score = payload.get("score")
    if isinstance(score, bool) or not isinstance(score, int) or score < 0:
        failures.append("result:score_invalid")
    signals = payload.get("matched_signals")
    if not isinstance(signals, list) or any(
        not isinstance(item, str) or item not in ALLOWED_SIGNALS for item in signals
    ):
        failures.append("result:signals_invalid")
    for field_name in ("evidence_ids", "event_ids", "suppressor_reasons"):
        value = payload.get(field_name)
        if not isinstance(value, list) or any(not _nonempty(item) for item in value):
            failures.append(f"result:{field_name}_invalid")
    for field_name in ("first_observed_at", "detection_observed_at", "detection_latency"):
        value = payload.get(field_name)
        if not _valid_number(value) or value < 0:
            failures.append(f"result:{field_name}_invalid")
    if (
        _valid_number(payload.get("first_observed_at"))
        and _valid_number(payload.get("detection_observed_at"))
        and payload["detection_observed_at"] < payload["first_observed_at"]
    ):
        failures.append("result:time_order_invalid")
    if payload.get("read_only") is not True:
        failures.append("result:read_only_required")
    if payload.get("synthetic_fixture_only") is not True:
        failures.append("result:synthetic_fixture_only_required")
    for field_name in FALSE_SAFETY_FIELDS:
        if payload.get(field_name) is not False:
            failures.append(f"result:{field_name}_must_be_false")
    return DetectorValidation(not failures, tuple(failures))


def build_evidence_graph(
    observations: Iterable[FileActivityObservation],
    result: DetectionResult,
) -> security_graph.SecurityGraph:
    items = tuple(observations)
    validation = validate_observations(items)
    if not validation.passed:
        raise ValueError("ransomware_detector_invalid_graph_input:" + ",".join(validation.failures))
    items = tuple(sorted(items, key=lambda item: (item.observed_at, item.event_id)))
    result_validation = validate_result(result.to_dict())
    if not result_validation.passed:
        raise ValueError("ransomware_detector_invalid_result:" + ",".join(result_validation.failures))

    builder = security_graph.SecurityGraphBuilder()
    file_nodes: list[security_graph.GraphNode] = []
    for item in items:
        attributes: dict[str, Any] = {
            "fixture": True,
            "write_count_window": item.write_count_window,
            "rename_count_window": item.rename_count_window,
            "entropy_delta": item.entropy_delta,
            "extension_changed": item.extension_changed,
            "canary_touched": item.canary_touched,
            "known_backup_workflow": item.known_backup_workflow,
            "user_initiated_bulk_operation": item.user_initiated_bulk_operation,
        }
        if item.correlation_key:
            attributes["correlation_keys"] = [item.correlation_key]
        node = builder.ingest_observation({
            "node_type": "FILE",
            "identity": {"event_id": item.event_id, "logical_path": item.logical_path},
            "label": item.logical_path,
            "observed_at": item.observed_at,
            "provenance": item.provenance,
            "evidence_ids": [item.evidence_id],
            "confidence": 1.0,
            "attributes": attributes,
        })
        file_nodes.append(node)

    detector_provenance = {
        "source": "b81-ransomware-detector",
        "source_id": TARGET_SCENARIO_ID,
        "collector": "sentinel.ransomware_detector",
        "trust": "DERIVED",
    }
    corr_keys = sorted({item.correlation_key for item in items if item.correlation_key})
    detection_node = builder.ingest_observation({
        "node_type": "DETECTION",
        "identity": {"scenario": TARGET_SCENARIO_ID, "digest": result.digest()},
        "label": f"Ransomware-like detector: {result.outcome}",
        "observed_at": result.detection_observed_at,
        "provenance": detector_provenance,
        "evidence_ids": list(result.evidence_ids),
        "confidence": min(1.0, result.score / 10.0),
        "attributes": {
            "fixture": True,
            "outcome": result.outcome,
            "score": result.score,
            "matched_signals": list(result.matched_signals),
            "correlation_keys": corr_keys,
        },
    })

    for node in file_nodes:
        builder.link(
            edge_type="TRIGGERED",
            source=node.node_id,
            target=detection_node.node_id,
            observed_at=result.detection_observed_at,
            provenance=detector_provenance,
            evidence_ids=node.evidence_ids,
            confidence=1.0,
            reason="Normalized file-activity evidence contributed to the advisory ransomware-like detector result.",
        )

    return builder.build(
        graph_id=f"b81-ransomware:{result.digest()[:16]}",
        incident_id=f"b81-ransomware:{_stable_hash(result.event_ids)[:16]}",
        created_at=result.detection_observed_at,
        metadata={
            "scenario_id": TARGET_SCENARIO_ID,
            "coverage_status": "PARTIAL",
            "synthetic_fixture_only": True,
            "detector_digest": result.digest(),
        },
    )


def correlate_evidence_graph(graph: security_graph.SecurityGraph) -> incident_correlation.CorrelationResult:
    return incident_correlation.IncidentCorrelator(max_time_delta=120.0).correlate(graph)


def _provenance(source_id: str) -> dict[str, Any]:
    return {
        "source": "b81-controlled-in-memory-fixture",
        "source_id": source_id,
        "collector": "sentinel.ransomware_detector",
        "trust": "DIRECT",
    }


def positive_fixture() -> tuple[FileActivityObservation, ...]:
    key = "b81:controlled-ransomware-like"
    return (
        FileActivityObservation(
            event_id="b81-positive-001",
            observed_at=100.0,
            logical_path="fixture/docs/a.txt",
            evidence_id="ev-b81-positive-001",
            provenance=_provenance("positive-001"),
            write_count_window=28,
            rename_count_window=18,
            entropy_delta=0.42,
            extension_changed=True,
            canary_touched=False,
            correlation_key=key,
        ),
        FileActivityObservation(
            event_id="b81-positive-002",
            observed_at=102.0,
            logical_path="fixture/docs/b.txt",
            evidence_id="ev-b81-positive-002",
            provenance=_provenance("positive-002"),
            write_count_window=31,
            rename_count_window=20,
            entropy_delta=0.38,
            extension_changed=True,
            canary_touched=True,
            correlation_key=key,
        ),
    )


def backup_fixture() -> tuple[FileActivityObservation, ...]:
    key = "b81:controlled-backup"
    return (
        FileActivityObservation(
            event_id="b81-backup-001",
            observed_at=200.0,
            logical_path="fixture/backup/a.bin",
            evidence_id="ev-b81-backup-001",
            provenance=_provenance("backup-001"),
            write_count_window=45,
            rename_count_window=22,
            entropy_delta=0.36,
            extension_changed=True,
            known_backup_workflow=True,
            correlation_key=key,
        ),
    )


def benign_fixture() -> tuple[FileActivityObservation, ...]:
    return (
        FileActivityObservation(
            event_id="b81-benign-001",
            observed_at=300.0,
            logical_path="fixture/docs/note.txt",
            evidence_id="ev-b81-benign-001",
            provenance=_provenance("benign-001"),
            write_count_window=1,
            rename_count_window=0,
            entropy_delta=0.01,
            extension_changed=False,
            canary_touched=False,
            correlation_key="b81:benign-save",
        ),
    )


def self_check() -> dict[str, Any]:
    failures: list[str] = []
    baseline = beta8_coverage_baseline.self_check()
    if baseline.get("passed") is not True:
        failures.append("b81:beta8_baseline_invalid")
    if baseline.get("summary") != {"PARTIAL": 3, "GAP": 3, "VERIFIED": 0}:
        failures.append("b81:beta8_baseline_summary_changed")

    positive = positive_fixture()
    positive_result = detect(positive)
    positive_validation = validate_result(positive_result.to_dict())
    if not positive_validation.passed:
        failures.extend("b81:positive:" + item for item in positive_validation.failures)
    if positive_result.outcome != OUTCOME_DETECTED:
        failures.append("b81:positive_not_detected")

    backup_result = detect(backup_fixture())
    if backup_result.outcome == OUTCOME_DETECTED:
        failures.append("b81:backup_false_positive_detected")
    if "KNOWN_BACKUP_WORKFLOW" not in backup_result.suppressor_reasons:
        failures.append("b81:backup_suppressor_missing")

    benign_result = detect(benign_fixture())
    if benign_result.outcome != OUTCOME_NO_MATCH:
        failures.append("b81:benign_false_positive")

    graph = build_evidence_graph(positive, positive_result)
    graph_validation = security_graph.validate_graph(graph.to_dict())
    if not graph_validation.passed:
        failures.append("b81:graph_invalid")
    correlation = correlate_evidence_graph(graph)
    corr_validation = incident_correlation.validate_result(correlation, graph)
    if not corr_validation.passed:
        failures.append("b81:correlation_invalid")
    if correlation.source_graph_digest != graph.digest():
        failures.append("b81:correlation_graph_digest_mismatch")

    round_trip = DetectionResult.from_dict(json.loads(positive_result.stable_json()))
    stable_round_trip = round_trip.to_dict() == positive_result.to_dict()
    deterministic = detect(positive_fixture()).stable_json() == positive_result.stable_json()
    if not stable_round_trip:
        failures.append("b81:round_trip_unstable")
    if not deterministic:
        failures.append("b81:serialization_unstable")

    result_payload = positive_result.to_dict()
    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "passed": not failures,
        "failures": failures,
        "target_scenario_id": TARGET_SCENARIO_ID,
        "coverage_status": "PARTIAL",
        "positive_outcome": positive_result.outcome,
        "backup_outcome": backup_result.outcome,
        "benign_outcome": benign_result.outcome,
        "positive_score": positive_result.score,
        "positive_signals": list(positive_result.matched_signals),
        "detection_latency": positive_result.detection_latency,
        "detector_digest": positive_result.digest(),
        "graph_digest": graph.digest(),
        "correlation_digest": correlation.digest(),
        "incident_count": len(correlation.incidents),
        "stable_round_trip": stable_round_trip,
        "deterministic_serialization": deterministic,
        "evidence_ids_preserved": set(positive_result.evidence_ids).issubset(
            {evidence_id for node in graph.nodes for evidence_id in node.evidence_ids}
        ),
        "read_only": result_payload["read_only"],
        "synthetic_fixture_only": result_payload["synthetic_fixture_only"],
        **{field_name: result_payload[field_name] for field_name in FALSE_SAFETY_FIELDS},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel Beta8 B8-1 ransomware-like detector")
    parser.add_argument("--self-check", action="store_true")
    args = parser.parse_args()
    if not args.self_check:
        parser.error("only --self-check is supported")
    result = self_check()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

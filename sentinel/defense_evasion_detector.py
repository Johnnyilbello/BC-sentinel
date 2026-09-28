from __future__ import annotations

"""B8-2 deterministic defense-evasion / tamper detector acceptance path.

The detector consumes normalized, already-observed control-tamper indicators.
It never disables security controls, stops services, changes exclusions, edits
policy, mutates registry state, or performs remediation. It emits advisory
evidence only and preserves provenance for the accepted Security Graph and
Incident Correlation foundations.
"""

from dataclasses import dataclass, field
import argparse
import hashlib
import json
import math
import time
import tracemalloc
from typing import Any, Final, Iterable

from sentinel import (
    beta8_coverage_baseline,
    incident_correlation,
    ransomware_detector,
    security_graph,
)

SCHEMA: Final[str] = "bc-sentinel-defense-evasion-detector-v1"
PROFILE: Final[str] = "v0.11.0-beta.8-b82-defense-evasion-detector"
SOURCE_CHECKPOINT: Final[str] = "checkpoint/v011-beta8-b81-pass"
SOURCE_CHECKPOINT_COMMIT: Final[str] = "5d25da3fcb8cd67d9faefbf2440eda19a6086eba"
TARGET_SCENARIO_ID: Final[str] = "B7-DEFENSE-EVASION-001"

OUTCOME_DETECTED: Final[str] = "DETECTED"
OUTCOME_REVIEW: Final[str] = "REVIEW_REQUIRED"
OUTCOME_NO_MATCH: Final[str] = "NO_MATCH"
ALLOWED_OUTCOMES: Final[set[str]] = {OUTCOME_DETECTED, OUTCOME_REVIEW, OUTCOME_NO_MATCH}

SIGNAL_PROTECTION_DISABLE: Final[str] = "PROTECTION_DISABLE_ATTEMPT"
SIGNAL_TELEMETRY_SUPPRESSION: Final[str] = "TELEMETRY_SUPPRESSION"
SIGNAL_EXCLUSION_EXPANSION: Final[str] = "EXCLUSION_SCOPE_EXPANSION"
SIGNAL_POLICY_WEAKENING: Final[str] = "POLICY_WEAKENING"
SIGNAL_SERVICE_STOP: Final[str] = "SECURITY_SERVICE_STOP_ATTEMPT"
ALLOWED_SIGNALS: Final[set[str]] = {
    SIGNAL_PROTECTION_DISABLE,
    SIGNAL_TELEMETRY_SUPPRESSION,
    SIGNAL_EXCLUSION_EXPANSION,
    SIGNAL_POLICY_WEAKENING,
    SIGNAL_SERVICE_STOP,
}

DETECT_SCORE: Final[int] = 6
REVIEW_SCORE: Final[int] = 3
MAX_SELF_CHECK_SECONDS: Final[float] = 5.0
MAX_SELF_CHECK_PEAK_BYTES: Final[int] = 64 * 1024 * 1024

FALSE_SAFETY_FIELDS: Final[tuple[str, ...]] = (
    "process_execution",
    "file_read",
    "file_write",
    "file_rename",
    "file_delete",
    "network_io",
    "registry_read",
    "registry_mutation",
    "service_control",
    "security_control_mutation",
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
class ControlTamperObservation:
    event_id: str
    observed_at: float
    control_surface: str
    evidence_id: str
    provenance: dict[str, Any]
    protection_disable_attempted: bool = False
    telemetry_suppressed: bool = False
    exclusion_scope_expanded: bool = False
    policy_weakened: bool = False
    security_service_stop_attempted: bool = False
    approved_change: bool = False
    maintenance_window: bool = False
    signed_admin_workflow: bool = False
    correlation_key: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "observed_at": self.observed_at,
            "control_surface": self.control_surface,
            "evidence_id": self.evidence_id,
            "provenance": dict(self.provenance),
            "protection_disable_attempted": self.protection_disable_attempted,
            "telemetry_suppressed": self.telemetry_suppressed,
            "exclusion_scope_expanded": self.exclusion_scope_expanded,
            "policy_weakened": self.policy_weakened,
            "security_service_stop_attempted": self.security_service_stop_attempted,
            "approved_change": self.approved_change,
            "maintenance_window": self.maintenance_window,
            "signed_admin_workflow": self.signed_admin_workflow,
            "correlation_key": self.correlation_key,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ControlTamperObservation":
        if not isinstance(payload, dict):
            raise ValueError("defense_evasion_detector_observation_not_object")
        candidate = cls(
            event_id=payload.get("event_id", ""),
            observed_at=payload.get("observed_at", 0.0),
            control_surface=payload.get("control_surface", ""),
            evidence_id=payload.get("evidence_id", ""),
            provenance=payload.get("provenance", {}),
            protection_disable_attempted=payload.get("protection_disable_attempted", False),
            telemetry_suppressed=payload.get("telemetry_suppressed", False),
            exclusion_scope_expanded=payload.get("exclusion_scope_expanded", False),
            policy_weakened=payload.get("policy_weakened", False),
            security_service_stop_attempted=payload.get("security_service_stop_attempted", False),
            approved_change=payload.get("approved_change", False),
            maintenance_window=payload.get("maintenance_window", False),
            signed_admin_workflow=payload.get("signed_admin_workflow", False),
            correlation_key=payload.get("correlation_key", ""),
        )
        validation = validate_observations((candidate,))
        if not validation.passed:
            raise ValueError(
                "defense_evasion_detector_invalid_observation:"
                + ",".join(validation.failures)
            )
        return candidate


@dataclass(frozen=True)
class DetectionResult:
    outcome: str
    score: int
    matched_signals: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    event_ids: tuple[str, ...]
    control_surfaces: tuple[str, ...]
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
            "control_surfaces": list(self.control_surfaces),
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
            "registry_read": False,
            "registry_mutation": False,
            "service_control": False,
            "security_control_mutation": False,
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
        validation = validate_result(payload)
        if not validation.passed:
            raise ValueError(
                "defense_evasion_detector_invalid_result:"
                + ",".join(validation.failures)
            )
        return cls(
            outcome=payload["outcome"],
            score=payload["score"],
            matched_signals=tuple(sorted(payload["matched_signals"])),
            evidence_ids=tuple(sorted(payload["evidence_ids"])),
            event_ids=tuple(sorted(payload["event_ids"])),
            control_surfaces=tuple(sorted(payload["control_surfaces"])),
            first_observed_at=payload["first_observed_at"],
            detection_observed_at=payload["detection_observed_at"],
            detection_latency=payload["detection_latency"],
            suppressor_reasons=tuple(sorted(payload["suppressor_reasons"])),
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


def validate_observations(observations: Iterable[ControlTamperObservation]) -> DetectorValidation:
    failures: list[str] = []
    items = tuple(observations)
    if not items:
        return DetectorValidation(False, ("observations:empty",))
    seen_events: set[str] = set()
    seen_evidence: set[str] = set()
    for index, item in enumerate(items):
        prefix = f"observation[{index}]"
        if not isinstance(item, ControlTamperObservation):
            failures.append(f"{prefix}:type_invalid")
            continue
        if not _nonempty(item.event_id):
            failures.append(f"{prefix}:event_id_invalid")
        elif item.event_id in seen_events:
            failures.append(f"{prefix}:duplicate_event_id")
        else:
            seen_events.add(item.event_id)
        if not _nonempty(item.evidence_id):
            failures.append(f"{prefix}:evidence_id_invalid")
        elif item.evidence_id in seen_evidence:
            failures.append(f"{prefix}:duplicate_evidence_id")
        else:
            seen_evidence.add(item.evidence_id)
        if not _nonempty(item.control_surface):
            failures.append(f"{prefix}:control_surface_invalid")
        if not _valid_number(item.observed_at) or item.observed_at < 0:
            failures.append(f"{prefix}:observed_at_invalid")
        for field_name in (
            "protection_disable_attempted",
            "telemetry_suppressed",
            "exclusion_scope_expanded",
            "policy_weakened",
            "security_service_stop_attempted",
            "approved_change",
            "maintenance_window",
            "signed_admin_workflow",
        ):
            if not isinstance(getattr(item, field_name), bool):
                failures.append(f"{prefix}:{field_name}_invalid")
        failures.extend(_validate_provenance(item.provenance, prefix))
        if not isinstance(item.correlation_key, str):
            failures.append(f"{prefix}:correlation_key_invalid")
        elif item.correlation_key and not item.correlation_key.strip():
            failures.append(f"{prefix}:correlation_key_invalid")

    valid_items = tuple(item for item in items if isinstance(item, ControlTamperObservation))
    if len(valid_items) > 1:
        keys = tuple(item.correlation_key for item in valid_items)
        if any(not isinstance(key, str) or not key.strip() for key in keys):
            failures.append("observations:correlation_key_required_for_batch")
        elif len(set(keys)) != 1:
            failures.append("observations:mixed_correlation_keys")
    return DetectorValidation(not failures, tuple(dict.fromkeys(failures)))


def _signals(observation: ControlTamperObservation) -> set[str]:
    signals: set[str] = set()
    if observation.protection_disable_attempted:
        signals.add(SIGNAL_PROTECTION_DISABLE)
    if observation.telemetry_suppressed:
        signals.add(SIGNAL_TELEMETRY_SUPPRESSION)
    if observation.exclusion_scope_expanded:
        signals.add(SIGNAL_EXCLUSION_EXPANSION)
    if observation.policy_weakened:
        signals.add(SIGNAL_POLICY_WEAKENING)
    if observation.security_service_stop_attempted:
        signals.add(SIGNAL_SERVICE_STOP)
    return signals


def _score(signals: set[str]) -> int:
    weights = {
        SIGNAL_PROTECTION_DISABLE: 3,
        SIGNAL_TELEMETRY_SUPPRESSION: 2,
        SIGNAL_EXCLUSION_EXPANSION: 2,
        SIGNAL_POLICY_WEAKENING: 2,
        SIGNAL_SERVICE_STOP: 3,
    }
    return sum(weights[item] for item in signals)


def detect(observations: Iterable[ControlTamperObservation]) -> DetectionResult:
    items = tuple(observations)
    validation = validate_observations(items)
    if not validation.passed:
        raise ValueError("defense_evasion_detector_invalid_input:" + ",".join(validation.failures))
    items = tuple(sorted(items, key=lambda item: (item.observed_at, item.event_id)))

    all_signals: set[str] = set()
    evidence_ids: set[str] = set()
    event_ids: set[str] = set()
    control_surfaces: set[str] = set()
    suppressors: set[str] = set()
    for item in items:
        all_signals.update(_signals(item))
        evidence_ids.add(item.evidence_id)
        event_ids.add(item.event_id)
        control_surfaces.add(item.control_surface)
        if item.approved_change:
            suppressors.add("APPROVED_CHANGE")
        if item.maintenance_window:
            suppressors.add("MAINTENANCE_WINDOW")
        if item.signed_admin_workflow:
            suppressors.add("SIGNED_ADMIN_WORKFLOW")

    score = _score(all_signals)
    direct_control_interference = bool(
        {SIGNAL_PROTECTION_DISABLE, SIGNAL_SERVICE_STOP} & all_signals
    )
    concealment_or_weakening = bool(
        {
            SIGNAL_TELEMETRY_SUPPRESSION,
            SIGNAL_EXCLUSION_EXPANSION,
            SIGNAL_POLICY_WEAKENING,
        }
        & all_signals
    )
    high_confidence_shape = direct_control_interference and concealment_or_weakening and score >= DETECT_SCORE

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
        control_surfaces=tuple(sorted(control_surfaces)),
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
    if isinstance(score, bool) or not isinstance(score, int) or not (0 <= score <= 12):
        failures.append("result:score_invalid")
    signals = payload.get("matched_signals")
    signals_valid = isinstance(signals, list) and all(
        isinstance(item, str) and item in ALLOWED_SIGNALS for item in signals
    )
    if not signals_valid:
        failures.append("result:signals_invalid")
    for field_name in ("evidence_ids", "event_ids", "control_surfaces"):
        value = payload.get(field_name)
        if (
            not isinstance(value, list)
            or not value
            or any(not _nonempty(item) for item in value)
        ):
            failures.append(f"result:{field_name}_invalid")
    suppressor_reasons = payload.get("suppressor_reasons")
    allowed_suppressors = {
        "APPROVED_CHANGE",
        "MAINTENANCE_WINDOW",
        "SIGNED_ADMIN_WORKFLOW",
    }
    suppressors_valid = isinstance(suppressor_reasons, list) and all(
        isinstance(item, str) and item in allowed_suppressors
        for item in suppressor_reasons
    )
    if not suppressors_valid:
        failures.append("result:suppressor_reasons_invalid")
    for field_name in ("first_observed_at", "detection_observed_at", "detection_latency"):
        value = payload.get(field_name)
        if not _valid_number(value) or value < 0:
            failures.append(f"result:{field_name}_invalid")
    first_observed = payload.get("first_observed_at")
    detection_observed = payload.get("detection_observed_at")
    latency = payload.get("detection_latency")
    if (
        _valid_number(first_observed)
        and _valid_number(detection_observed)
        and detection_observed < first_observed
    ):
        failures.append("result:time_order_invalid")
    if (
        _valid_number(first_observed)
        and _valid_number(detection_observed)
        and _valid_number(latency)
        and abs((detection_observed - first_observed) - latency) > 1e-9
    ):
        failures.append("result:detection_latency_mismatch")
    if signals_valid and isinstance(score, int) and not isinstance(score, bool):
        signal_set = set(signals)
        expected_score = _score(signal_set)
        if score != expected_score:
            failures.append("result:score_signal_mismatch")
        direct_control_interference = bool(
            {SIGNAL_PROTECTION_DISABLE, SIGNAL_SERVICE_STOP} & signal_set
        )
        concealment_or_weakening = bool(
            {
                SIGNAL_TELEMETRY_SUPPRESSION,
                SIGNAL_EXCLUSION_EXPANSION,
                SIGNAL_POLICY_WEAKENING,
            }
            & signal_set
        )
        expected_detect_shape = (
            direct_control_interference
            and concealment_or_weakening
            and score >= DETECT_SCORE
        )
        has_suppressors = bool(suppressor_reasons) if suppressors_valid else False
        if has_suppressors:
            expected_outcome = OUTCOME_REVIEW if score >= REVIEW_SCORE else OUTCOME_NO_MATCH
        elif expected_detect_shape:
            expected_outcome = OUTCOME_DETECTED
        elif score >= REVIEW_SCORE:
            expected_outcome = OUTCOME_REVIEW
        else:
            expected_outcome = OUTCOME_NO_MATCH
        if isinstance(outcome, str) and outcome in ALLOWED_OUTCOMES and outcome != expected_outcome:
            failures.append("result:outcome_signal_mismatch")
    if payload.get("read_only") is not True:
        failures.append("result:read_only_required")
    if payload.get("synthetic_fixture_only") is not True:
        failures.append("result:synthetic_fixture_only_required")
    for field_name in FALSE_SAFETY_FIELDS:
        if payload.get(field_name) is not False:
            failures.append(f"result:{field_name}_must_be_false")
    return DetectorValidation(not failures, tuple(failures))


def build_evidence_graph(
    observations: Iterable[ControlTamperObservation],
    result: DetectionResult,
) -> security_graph.SecurityGraph:
    items = tuple(observations)
    validation = validate_observations(items)
    if not validation.passed:
        raise ValueError("defense_evasion_detector_invalid_graph_input:" + ",".join(validation.failures))
    items = tuple(sorted(items, key=lambda item: (item.observed_at, item.event_id)))
    result_validation = validate_result(result.to_dict())
    if not result_validation.passed:
        raise ValueError("defense_evasion_detector_invalid_result:" + ",".join(result_validation.failures))

    builder = security_graph.SecurityGraphBuilder()
    action_nodes: list[security_graph.GraphNode] = []
    for item in items:
        attributes: dict[str, Any] = {
            "fixture": True,
            "protection_disable_attempted": item.protection_disable_attempted,
            "telemetry_suppressed": item.telemetry_suppressed,
            "exclusion_scope_expanded": item.exclusion_scope_expanded,
            "policy_weakened": item.policy_weakened,
            "security_service_stop_attempted": item.security_service_stop_attempted,
            "approved_change": item.approved_change,
            "maintenance_window": item.maintenance_window,
            "signed_admin_workflow": item.signed_admin_workflow,
        }
        if item.correlation_key:
            attributes["correlation_keys"] = [item.correlation_key]
        node = builder.ingest_observation({
            "node_type": "ACTION",
            "identity": {"event_id": item.event_id, "control_surface": item.control_surface},
            "label": item.control_surface,
            "observed_at": item.observed_at,
            "provenance": item.provenance,
            "evidence_ids": [item.evidence_id],
            "confidence": 1.0,
            "attributes": attributes,
        })
        action_nodes.append(node)

    detector_provenance = {
        "source": "b82-defense-evasion-detector",
        "source_id": TARGET_SCENARIO_ID,
        "collector": "sentinel.defense_evasion_detector",
        "trust": "DERIVED",
    }
    corr_keys = sorted({item.correlation_key for item in items if item.correlation_key})
    detection_node = builder.ingest_observation({
        "node_type": "DETECTION",
        "identity": {"scenario": TARGET_SCENARIO_ID, "digest": result.digest()},
        "label": f"Defense-evasion / tamper detector: {result.outcome}",
        "observed_at": result.detection_observed_at,
        "provenance": detector_provenance,
        "evidence_ids": list(result.evidence_ids),
        "confidence": min(1.0, result.score / 12.0),
        "attributes": {
            "fixture": True,
            "outcome": result.outcome,
            "score": result.score,
            "matched_signals": list(result.matched_signals),
            "correlation_keys": corr_keys,
        },
    })

    for node in action_nodes:
        builder.link(
            edge_type="TRIGGERED",
            source=node.node_id,
            target=detection_node.node_id,
            observed_at=result.detection_observed_at,
            provenance=detector_provenance,
            evidence_ids=node.evidence_ids,
            confidence=1.0,
            reason="Normalized control-tamper evidence contributed to the advisory defense-evasion detector result.",
        )

    return builder.build(
        graph_id=f"b82-defense-evasion:{result.digest()[:16]}",
        incident_id=f"b82-defense-evasion:{_stable_hash(result.event_ids)[:16]}",
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
        "source": "b82-controlled-in-memory-fixture",
        "source_id": source_id,
        "collector": "sentinel.defense_evasion_detector",
        "trust": "DIRECT",
    }


def positive_fixture() -> tuple[ControlTamperObservation, ...]:
    key = "b82:controlled-defense-evasion"
    return (
        ControlTamperObservation(
            event_id="b82-positive-001",
            observed_at=100.0,
            control_surface="fixture/security-control/protection",
            evidence_id="ev-b82-positive-001",
            provenance=_provenance("positive-001"),
            protection_disable_attempted=True,
            telemetry_suppressed=True,
            policy_weakened=True,
            correlation_key=key,
        ),
        ControlTamperObservation(
            event_id="b82-positive-002",
            observed_at=102.0,
            control_surface="fixture/security-control/service",
            evidence_id="ev-b82-positive-002",
            provenance=_provenance("positive-002"),
            exclusion_scope_expanded=True,
            security_service_stop_attempted=True,
            correlation_key=key,
        ),
    )


def admin_fixture() -> tuple[ControlTamperObservation, ...]:
    return (
        ControlTamperObservation(
            event_id="b82-admin-001",
            observed_at=200.0,
            control_surface="fixture/security-control/maintenance",
            evidence_id="ev-b82-admin-001",
            provenance=_provenance("admin-001"),
            exclusion_scope_expanded=True,
            policy_weakened=True,
            security_service_stop_attempted=True,
            approved_change=True,
            maintenance_window=True,
            signed_admin_workflow=True,
            correlation_key="b82:approved-maintenance",
        ),
    )


def benign_fixture() -> tuple[ControlTamperObservation, ...]:
    return (
        ControlTamperObservation(
            event_id="b82-benign-001",
            observed_at=300.0,
            control_surface="fixture/security-control/status-read",
            evidence_id="ev-b82-benign-001",
            provenance=_provenance("benign-001"),
            correlation_key="b82:benign-status",
        ),
    )


def self_check() -> dict[str, Any]:
    failures: list[str] = []

    baseline = beta8_coverage_baseline.self_check()
    if baseline.get("passed") is not True:
        failures.append("b82:beta8_baseline_invalid")
    if baseline.get("summary") != {"PARTIAL": 3, "GAP": 3, "VERIFIED": 0}:
        failures.append("b82:beta8_baseline_summary_changed")

    predecessor = ransomware_detector.self_check()
    if predecessor.get("passed") is not True:
        failures.append("b82:b81_predecessor_invalid")
    if predecessor.get("coverage_status") != "PARTIAL":
        failures.append("b82:b81_coverage_status_changed")

    tracemalloc.start()
    started = time.perf_counter()
    try:
        positive = positive_fixture()
        positive_result = detect(positive)
        positive_validation = validate_result(positive_result.to_dict())
        admin_result = detect(admin_fixture())
        benign_result = detect(benign_fixture())
        graph = build_evidence_graph(positive, positive_result)
        correlation = correlate_evidence_graph(graph)
        elapsed = time.perf_counter() - started
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    if not positive_validation.passed:
        failures.extend("b82:positive:" + item for item in positive_validation.failures)
    if positive_result.outcome != OUTCOME_DETECTED:
        failures.append("b82:positive_not_detected")
    if admin_result.outcome == OUTCOME_DETECTED:
        failures.append("b82:approved_admin_false_positive_detected")
    if "APPROVED_CHANGE" not in admin_result.suppressor_reasons:
        failures.append("b82:approved_change_suppressor_missing")
    if benign_result.outcome != OUTCOME_NO_MATCH:
        failures.append("b82:benign_false_positive")

    graph_validation = security_graph.validate_graph(graph.to_dict())
    if not graph_validation.passed:
        failures.append("b82:graph_invalid")
    corr_validation = incident_correlation.validate_result(correlation, graph)
    if not corr_validation.passed:
        failures.append("b82:correlation_invalid")
    if correlation.source_graph_digest != graph.digest():
        failures.append("b82:correlation_graph_digest_mismatch")

    round_trip = DetectionResult.from_dict(json.loads(positive_result.stable_json()))
    stable_round_trip = round_trip.to_dict() == positive_result.to_dict()
    deterministic = detect(positive_fixture()).stable_json() == positive_result.stable_json()
    if not stable_round_trip:
        failures.append("b82:round_trip_unstable")
    if not deterministic:
        failures.append("b82:serialization_unstable")
    if elapsed > MAX_SELF_CHECK_SECONDS:
        failures.append("b82:resource_time_budget_exceeded")
    if peak > MAX_SELF_CHECK_PEAK_BYTES:
        failures.append("b82:resource_memory_budget_exceeded")

    result_payload = positive_result.to_dict()
    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "passed": not failures,
        "failures": failures,
        "target_scenario_id": TARGET_SCENARIO_ID,
        "coverage_status": "PARTIAL",
        "positive_outcome": positive_result.outcome,
        "admin_outcome": admin_result.outcome,
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
        "resource_cost": {
            "elapsed_seconds": elapsed,
            "peak_memory_bytes": peak,
            "max_seconds": MAX_SELF_CHECK_SECONDS,
            "max_peak_memory_bytes": MAX_SELF_CHECK_PEAK_BYTES,
        },
        "read_only": result_payload["read_only"],
        "synthetic_fixture_only": result_payload["synthetic_fixture_only"],
        **{field_name: result_payload[field_name] for field_name in FALSE_SAFETY_FIELDS},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel Beta8 B8-2 defense-evasion / tamper detector")
    parser.add_argument("--self-check", action="store_true")
    args = parser.parse_args()
    if not args.self_check:
        parser.error("only --self-check is supported")
    result = self_check()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

"""B8-3 deterministic credential-access *indicator* detector.

This module consumes harmless, normalized metadata describing already-observed
security indicators. It does not read process memory, files, browser stores,
registry secrets, token caches, protected stores, passwords, cookies, tokens,
keys, or any other credential material. Results are advisory evidence only.
"""

from dataclasses import dataclass, field
import argparse
import hashlib
import json
import time
import tracemalloc
from typing import Any, Final, Iterable, Mapping

from sentinel import (
    beta8_coverage_baseline,
    defense_evasion_detector,
    incident_correlation,
    security_graph,
)

SCHEMA: Final[str] = "bc-sentinel-credential-access-indicator-detector-v1"
PROFILE: Final[str] = "v0.11.0-beta.8-b83-credential-indicator-detector"
SOURCE_CHECKPOINT: Final[str] = "checkpoint/v011-beta8-b82-pass"
SOURCE_CHECKPOINT_COMMIT: Final[str] = "a4f4b53bf2ea2dcd00744438c716a18ef5287262"
TARGET_SCENARIO_ID: Final[str] = "B7-CREDENTIAL-001"

OUTCOME_DETECTED: Final[str] = "DETECTED"
OUTCOME_REVIEW: Final[str] = "REVIEW_REQUIRED"
OUTCOME_NO_MATCH: Final[str] = "NO_MATCH"
ALLOWED_OUTCOMES: Final[set[str]] = {OUTCOME_DETECTED, OUTCOME_REVIEW, OUTCOME_NO_MATCH}

SIGNAL_PROTECTED_AUTH_TARGET: Final[str] = "PROTECTED_AUTH_PROCESS_TARGETING"
SIGNAL_CREDENTIAL_STORE_TARGET: Final[str] = "CREDENTIAL_STORE_TARGETING"
SIGNAL_BROWSER_AUTH_STORE_TARGET: Final[str] = "BROWSER_AUTH_STORE_TARGETING"
SIGNAL_TOKEN_CACHE_TARGET: Final[str] = "TOKEN_CACHE_TARGETING"
SIGNAL_CREDENTIAL_TOOL_MARKER: Final[str] = "CREDENTIAL_TOOL_MARKER"
ALLOWED_SIGNALS: Final[set[str]] = {
    SIGNAL_PROTECTED_AUTH_TARGET,
    SIGNAL_CREDENTIAL_STORE_TARGET,
    SIGNAL_BROWSER_AUTH_STORE_TARGET,
    SIGNAL_TOKEN_CACHE_TARGET,
    SIGNAL_CREDENTIAL_TOOL_MARKER,
}

DETECT_SCORE: Final[int] = 6
REVIEW_SCORE: Final[int] = 3
MAX_SELF_CHECK_SECONDS: Final[float] = 5.0
MAX_SELF_CHECK_PEAK_BYTES: Final[int] = 64 * 1024 * 1024

# These names are rejected if they appear in caller-supplied provenance. The
# detector accepts metadata about an indicator, never secret-bearing payloads.
FORBIDDEN_PROVENANCE_KEY_PARTS: Final[tuple[str, ...]] = (
    "password",
    "passwd",
    "pwd",
    "token",
    "cookie",
    "secret",
    "credential",
    "private_key",
    "session_key",
    "key_material",
)

FALSE_SAFETY_FIELDS: Final[tuple[str, ...]] = (
    "process_execution",
    "process_memory_read",
    "file_read",
    "file_write",
    "file_rename",
    "file_delete",
    "network_io",
    "registry_read",
    "registry_mutation",
    "protected_store_read",
    "browser_store_read",
    "token_cache_read",
    "credential_access",
    "credential_material_collected",
    "credential_values_serialized",
    "credential_values_emitted",
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
    return not isinstance(value, bool) and isinstance(value, (int, float))


def _contains_forbidden_provenance_key(value: Any) -> bool:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            normalized = str(key).strip().lower()
            if any(part in normalized for part in FORBIDDEN_PROVENANCE_KEY_PARTS):
                return True
            if _contains_forbidden_provenance_key(nested):
                return True
    elif isinstance(value, (list, tuple)):
        return any(_contains_forbidden_provenance_key(item) for item in value)
    return False


def _validate_provenance(value: Any, prefix: str) -> list[str]:
    failures: list[str] = []
    if not isinstance(value, dict):
        return [f"{prefix}:provenance_not_object"]
    if _contains_forbidden_provenance_key(value):
        failures.append(f"{prefix}:secret_bearing_provenance_rejected")
    for field_name in ("source", "source_id", "collector"):
        if not _nonempty(value.get(field_name)):
            failures.append(f"{prefix}:provenance_{field_name}_invalid")
    trust = str(value.get("trust") or "").upper()
    if trust not in security_graph.ALLOWED_PROVENANCE_TRUST:
        failures.append(f"{prefix}:provenance_trust_invalid")
    return failures


@dataclass(frozen=True)
class CredentialIndicatorObservation:
    event_id: str
    observed_at: float
    source_surface: str
    evidence_id: str
    provenance: dict[str, Any]
    protected_auth_process_targeted: bool = False
    credential_store_targeted: bool = False
    browser_auth_store_targeted: bool = False
    token_cache_targeted: bool = False
    credential_tool_marker: bool = False
    approved_security_tool: bool = False
    maintenance_window: bool = False
    signed_admin_workflow: bool = False
    correlation_key: str = ""

    def to_metadata_dict(self) -> dict[str, Any]:
        """Return secret-free metadata only; provenance is intentionally excluded."""
        return {
            "event_id": self.event_id,
            "observed_at": self.observed_at,
            "source_surface": self.source_surface,
            "evidence_id": self.evidence_id,
            "protected_auth_process_targeted": self.protected_auth_process_targeted,
            "credential_store_targeted": self.credential_store_targeted,
            "browser_auth_store_targeted": self.browser_auth_store_targeted,
            "token_cache_targeted": self.token_cache_targeted,
            "credential_tool_marker": self.credential_tool_marker,
            "approved_security_tool": self.approved_security_tool,
            "maintenance_window": self.maintenance_window,
            "signed_admin_workflow": self.signed_admin_workflow,
            "correlation_key": self.correlation_key,
        }


@dataclass(frozen=True)
class DetectionResult:
    outcome: str
    score: int
    matched_signals: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    event_ids: tuple[str, ...]
    source_surfaces: tuple[str, ...]
    first_observed_at: float
    detection_observed_at: float
    detection_latency: float
    suppressor_reasons: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        payload = {
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
            "source_surfaces": list(self.source_surfaces),
            "first_observed_at": self.first_observed_at,
            "detection_observed_at": self.detection_observed_at,
            "detection_latency": self.detection_latency,
            "suppressor_reasons": list(self.suppressor_reasons),
            "coverage_status": "PARTIAL",
            "read_only": True,
            "synthetic_fixture_only": True,
            "metadata_only": True,
        }
        payload.update({field_name: False for field_name in FALSE_SAFETY_FIELDS})
        return payload

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
            source_surfaces=tuple(sorted(str(item) for item in (payload.get("source_surfaces") or []))),
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
            "metadata_only": True,
            "execution_authority_added": False,
        }


def validate_observations(observations: Iterable[CredentialIndicatorObservation]) -> DetectorValidation:
    failures: list[str] = []
    items = tuple(observations)
    if not items:
        return DetectorValidation(False, ("observations:empty",))
    seen_events: set[str] = set()
    seen_evidence: set[str] = set()
    for index, item in enumerate(items):
        prefix = f"observation[{index}]"
        if not isinstance(item, CredentialIndicatorObservation):
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
        if not _nonempty(item.source_surface):
            failures.append(f"{prefix}:source_surface_invalid")
        if not _valid_number(item.observed_at) or item.observed_at < 0:
            failures.append(f"{prefix}:observed_at_invalid")
        failures.extend(_validate_provenance(item.provenance, prefix))
        if item.correlation_key and not item.correlation_key.strip():
            failures.append(f"{prefix}:correlation_key_invalid")
    return DetectorValidation(not failures, tuple(failures))


def _signals(observation: CredentialIndicatorObservation) -> set[str]:
    signals: set[str] = set()
    if observation.protected_auth_process_targeted:
        signals.add(SIGNAL_PROTECTED_AUTH_TARGET)
    if observation.credential_store_targeted:
        signals.add(SIGNAL_CREDENTIAL_STORE_TARGET)
    if observation.browser_auth_store_targeted:
        signals.add(SIGNAL_BROWSER_AUTH_STORE_TARGET)
    if observation.token_cache_targeted:
        signals.add(SIGNAL_TOKEN_CACHE_TARGET)
    if observation.credential_tool_marker:
        signals.add(SIGNAL_CREDENTIAL_TOOL_MARKER)
    return signals


def _score(signals: set[str]) -> int:
    weights = {
        SIGNAL_PROTECTED_AUTH_TARGET: 3,
        SIGNAL_CREDENTIAL_STORE_TARGET: 3,
        SIGNAL_BROWSER_AUTH_STORE_TARGET: 2,
        SIGNAL_TOKEN_CACHE_TARGET: 2,
        SIGNAL_CREDENTIAL_TOOL_MARKER: 2,
    }
    return sum(weights[item] for item in signals)


def detect(observations: Iterable[CredentialIndicatorObservation]) -> DetectionResult:
    items = tuple(sorted(observations, key=lambda item: (item.observed_at, item.event_id)))
    validation = validate_observations(items)
    if not validation.passed:
        raise ValueError("credential_access_detector_invalid_input:" + ",".join(validation.failures))

    all_signals: set[str] = set()
    evidence_ids: set[str] = set()
    event_ids: set[str] = set()
    surfaces: set[str] = set()
    suppressors: set[str] = set()
    for item in items:
        all_signals.update(_signals(item))
        evidence_ids.add(item.evidence_id)
        event_ids.add(item.event_id)
        surfaces.add(item.source_surface)
        if item.approved_security_tool:
            suppressors.add("APPROVED_SECURITY_TOOL")
        if item.maintenance_window:
            suppressors.add("MAINTENANCE_WINDOW")
        if item.signed_admin_workflow:
            suppressors.add("SIGNED_ADMIN_WORKFLOW")

    score = _score(all_signals)
    direct_target = bool(
        {SIGNAL_PROTECTED_AUTH_TARGET, SIGNAL_CREDENTIAL_STORE_TARGET} & all_signals
    )
    corroboration = bool(
        {
            SIGNAL_BROWSER_AUTH_STORE_TARGET,
            SIGNAL_TOKEN_CACHE_TARGET,
            SIGNAL_CREDENTIAL_TOOL_MARKER,
        }
        & all_signals
    )
    high_confidence_shape = direct_target and corroboration and score >= DETECT_SCORE

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
        source_surfaces=tuple(sorted(surfaces)),
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
    if payload.get("outcome") not in ALLOWED_OUTCOMES:
        failures.append("result:outcome_invalid")
    score = payload.get("score")
    if isinstance(score, bool) or not isinstance(score, int) or score < 0:
        failures.append("result:score_invalid")
    signals = payload.get("matched_signals")
    if not isinstance(signals, list) or any(item not in ALLOWED_SIGNALS for item in signals):
        failures.append("result:signals_invalid")
    for field_name in ("evidence_ids", "event_ids", "source_surfaces", "suppressor_reasons"):
        value = payload.get(field_name)
        if not isinstance(value, list) or any(not _nonempty(item) for item in value):
            failures.append(f"result:{field_name}_invalid")
    for field_name in ("first_observed_at", "detection_observed_at", "detection_latency"):
        value = payload.get(field_name)
        if not _valid_number(value) or value < 0:
            failures.append(f"result:{field_name}_invalid")
    if payload.get("read_only") is not True:
        failures.append("result:read_only_required")
    if payload.get("synthetic_fixture_only") is not True:
        failures.append("result:synthetic_fixture_only_required")
    if payload.get("metadata_only") is not True:
        failures.append("result:metadata_only_required")
    for field_name in FALSE_SAFETY_FIELDS:
        if payload.get(field_name) is not False:
            failures.append(f"result:{field_name}_must_be_false")
    return DetectorValidation(not failures, tuple(failures))


def build_evidence_graph(
    observations: Iterable[CredentialIndicatorObservation],
    result: DetectionResult,
) -> security_graph.SecurityGraph:
    items = tuple(sorted(observations, key=lambda item: (item.observed_at, item.event_id)))
    validation = validate_observations(items)
    if not validation.passed:
        raise ValueError("credential_access_detector_invalid_graph_input:" + ",".join(validation.failures))
    result_validation = validate_result(result.to_dict())
    if not result_validation.passed:
        raise ValueError("credential_access_detector_invalid_result:" + ",".join(result_validation.failures))

    builder = security_graph.SecurityGraphBuilder()
    action_nodes: list[security_graph.GraphNode] = []
    for item in items:
        attributes: dict[str, Any] = {
            "fixture": True,
            "metadata_only": True,
            "protected_auth_process_targeted": item.protected_auth_process_targeted,
            "credential_store_targeted": item.credential_store_targeted,
            "browser_auth_store_targeted": item.browser_auth_store_targeted,
            "token_cache_targeted": item.token_cache_targeted,
            "credential_tool_marker": item.credential_tool_marker,
            "approved_security_tool": item.approved_security_tool,
            "maintenance_window": item.maintenance_window,
            "signed_admin_workflow": item.signed_admin_workflow,
        }
        if item.correlation_key:
            attributes["correlation_keys"] = [item.correlation_key]
        node = builder.ingest_observation({
            "node_type": "ACTION",
            "identity": {"event_id": item.event_id, "source_surface": item.source_surface},
            "label": item.source_surface,
            "observed_at": item.observed_at,
            "provenance": item.provenance,
            "evidence_ids": [item.evidence_id],
            "confidence": 1.0,
            "attributes": attributes,
        })
        action_nodes.append(node)

    detector_provenance = {
        "source": "b83-credential-indicator-detector",
        "source_id": TARGET_SCENARIO_ID,
        "collector": "sentinel.credential_access_detector",
        "trust": "DERIVED",
    }
    corr_keys = sorted({item.correlation_key for item in items if item.correlation_key})
    detection_node = builder.ingest_observation({
        "node_type": "DETECTION",
        "identity": {"scenario": TARGET_SCENARIO_ID, "digest": result.digest()},
        "label": f"Credential-access indicator detector: {result.outcome}",
        "observed_at": result.detection_observed_at,
        "provenance": detector_provenance,
        "evidence_ids": list(result.evidence_ids),
        "confidence": min(1.0, result.score / 12.0),
        "attributes": {
            "fixture": True,
            "metadata_only": True,
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
            reason="Normalized secret-free indicator metadata contributed to the advisory credential-access result.",
        )

    return builder.build(
        graph_id=f"b83-credential-indicators:{result.digest()[:16]}",
        incident_id=f"b83-credential-indicators:{_stable_hash(result.event_ids)[:16]}",
        created_at=result.detection_observed_at,
        metadata={
            "scenario_id": TARGET_SCENARIO_ID,
            "coverage_status": "PARTIAL",
            "synthetic_fixture_only": True,
            "metadata_only": True,
            "detector_digest": result.digest(),
        },
    )


def correlate_evidence_graph(graph: security_graph.SecurityGraph) -> incident_correlation.CorrelationResult:
    return incident_correlation.IncidentCorrelator(max_time_delta=120.0).correlate(graph)


def _provenance(source_id: str) -> dict[str, Any]:
    return {
        "source": "b83-controlled-in-memory-fixture",
        "source_id": source_id,
        "collector": "sentinel.credential_access_detector",
        "trust": "DIRECT",
    }


def positive_fixture() -> tuple[CredentialIndicatorObservation, ...]:
    key = "b83:controlled-credential-indicators"
    return (
        CredentialIndicatorObservation(
            event_id="b83-positive-001",
            observed_at=100.0,
            source_surface="fixture/auth-process-target-metadata",
            evidence_id="ev-b83-positive-001",
            provenance=_provenance("positive-001"),
            protected_auth_process_targeted=True,
            token_cache_targeted=True,
            correlation_key=key,
        ),
        CredentialIndicatorObservation(
            event_id="b83-positive-002",
            observed_at=102.0,
            source_surface="fixture/protected-store-target-metadata",
            evidence_id="ev-b83-positive-002",
            provenance=_provenance("positive-002"),
            credential_store_targeted=True,
            credential_tool_marker=True,
            correlation_key=key,
        ),
    )


def admin_fixture() -> tuple[CredentialIndicatorObservation, ...]:
    return (
        CredentialIndicatorObservation(
            event_id="b83-admin-001",
            observed_at=200.0,
            source_surface="fixture/approved-security-audit-metadata",
            evidence_id="ev-b83-admin-001",
            provenance=_provenance("admin-001"),
            credential_store_targeted=True,
            token_cache_targeted=True,
            approved_security_tool=True,
            maintenance_window=True,
            signed_admin_workflow=True,
            correlation_key="b83:approved-security-audit",
        ),
    )


def benign_fixture() -> tuple[CredentialIndicatorObservation, ...]:
    return (
        CredentialIndicatorObservation(
            event_id="b83-benign-001",
            observed_at=300.0,
            source_surface="fixture/auth-status-metadata",
            evidence_id="ev-b83-benign-001",
            provenance=_provenance("benign-001"),
            correlation_key="b83:benign-status",
        ),
    )


def rejected_secret_bearing_fixture() -> tuple[CredentialIndicatorObservation, ...]:
    return (
        CredentialIndicatorObservation(
            event_id="b83-rejected-001",
            observed_at=400.0,
            source_surface="fixture/rejected-secret-bearing-metadata",
            evidence_id="ev-b83-rejected-001",
            provenance={
                "source": "b83-rejection-test",
                "source_id": "rejected-001",
                "collector": "sentinel.credential_access_detector",
                "trust": "DIRECT",
                "password": "[REDACTED]",
            },
        ),
    )


def self_check() -> dict[str, Any]:
    failures: list[str] = []

    baseline = beta8_coverage_baseline.self_check()
    if baseline.get("passed") is not True:
        failures.append("b83:beta8_baseline_invalid")
    if baseline.get("summary") != {"PARTIAL": 3, "GAP": 3, "VERIFIED": 0}:
        failures.append("b83:beta8_baseline_summary_changed")

    predecessor = defense_evasion_detector.self_check()
    if predecessor.get("passed") is not True:
        failures.append("b83:b82_predecessor_invalid")
    if predecessor.get("coverage_status") != "PARTIAL":
        failures.append("b83:b82_coverage_status_changed")

    rejected_validation = validate_observations(rejected_secret_bearing_fixture())
    sensitive_input_rejected = (
        rejected_validation.passed is False
        and any("secret_bearing_provenance_rejected" in item for item in rejected_validation.failures)
    )
    if not sensitive_input_rejected:
        failures.append("b83:secret_bearing_input_not_rejected")

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
        failures.extend("b83:positive:" + item for item in positive_validation.failures)
    if positive_result.outcome != OUTCOME_DETECTED:
        failures.append("b83:positive_not_detected")
    if admin_result.outcome == OUTCOME_DETECTED:
        failures.append("b83:approved_admin_false_positive_detected")
    if "APPROVED_SECURITY_TOOL" not in admin_result.suppressor_reasons:
        failures.append("b83:approved_security_tool_suppressor_missing")
    if benign_result.outcome != OUTCOME_NO_MATCH:
        failures.append("b83:benign_false_positive")

    graph_validation = security_graph.validate_graph(graph.to_dict())
    if not graph_validation.passed:
        failures.append("b83:graph_invalid")
    corr_validation = incident_correlation.validate_result(correlation, graph)
    if not corr_validation.passed:
        failures.append("b83:correlation_invalid")
    if correlation.source_graph_digest != graph.digest():
        failures.append("b83:correlation_graph_digest_mismatch")

    round_trip = DetectionResult.from_dict(json.loads(positive_result.stable_json()))
    stable_round_trip = round_trip.to_dict() == positive_result.to_dict()
    deterministic = detect(positive_fixture()).stable_json() == positive_result.stable_json()
    if not stable_round_trip:
        failures.append("b83:round_trip_unstable")
    if not deterministic:
        failures.append("b83:serialization_unstable")
    if elapsed > MAX_SELF_CHECK_SECONDS:
        failures.append("b83:resource_time_budget_exceeded")
    if peak > MAX_SELF_CHECK_PEAK_BYTES:
        failures.append("b83:resource_memory_budget_exceeded")

    result_payload = positive_result.to_dict()
    evidence_ids_preserved = set(positive_result.evidence_ids).issubset(
        {evidence_id for node in graph.nodes for evidence_id in node.evidence_ids}
    )
    if not evidence_ids_preserved:
        failures.append("b83:evidence_ids_not_preserved")

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
        "evidence_ids_preserved": evidence_ids_preserved,
        "sensitive_input_rejected": sensitive_input_rejected,
        "resource_cost": {
            "elapsed_seconds": elapsed,
            "peak_memory_bytes": peak,
            "max_seconds": MAX_SELF_CHECK_SECONDS,
            "max_peak_memory_bytes": MAX_SELF_CHECK_PEAK_BYTES,
        },
        "read_only": result_payload["read_only"],
        "synthetic_fixture_only": result_payload["synthetic_fixture_only"],
        "metadata_only": result_payload["metadata_only"],
        **{field_name: result_payload[field_name] for field_name in FALSE_SAFETY_FIELDS},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel Beta8 B8-3 credential-access indicator detector")
    parser.add_argument("--self-check", action="store_true")
    args = parser.parse_args()
    if not args.self_check:
        parser.error("only --self-check is supported")
    result = self_check()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

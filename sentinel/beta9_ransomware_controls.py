"""B9-3: evaluate live ransomware-like false-positive controls and coverage decisions.

This module consumes privacy-minimal aggregate evidence produced by the explicit
B9-3 acceptance harness. It never writes, renames, opens, encrypts or deletes
files itself. The only detector algorithm exercised is the accepted
``sentinel.ransomware_detector.detect`` path.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from sentinel import incident_correlation, ransomware_detector, security_graph

SCHEMA = "bc-sentinel-beta9-ransomware-live-controls-v1"
SOURCE = "LOCAL_TEMP_FILE_ACTIVITY_LIVE_CONTROLS"
TARGET_SCENARIO = "B7-RANSOMWARE-001"
MAX_EVENT_COUNT = 1_000_000
CONTROL_IDS = (
    "positive-ransomware-like",
    "administrative-backup-like",
    "benign-save",
)
CONTROL_FIELDS = {
    "control_id",
    "live_observation",
    "sandbox_scope",
    "observer_backend",
    "write_event_count",
    "rename_event_count",
    "entropy_delta",
    "extension_changed",
    "canary_touched",
    "known_backup_workflow",
    "user_initiated_bulk_operation",
    "started_at_utc",
    "completed_at_utc",
    "cleanup_state",
}
BOUNDARIES = {
    "local_only": True,
    "explicit_opt_in_required": True,
    "dedicated_temp_directory_only": True,
    "acceptance_harness_file_mutation": True,
    "user_file_access": False,
    "file_content_collected": False,
    "absolute_paths_exported": False,
    "personal_data_collected": False,
    "remote_access": False,
    "real_malware_executed": False,
    "product_file_write_authority": False,
    "product_file_rename_authority": False,
    "product_file_delete_authority": False,
    "remediation_authority": False,
    "automatic_quarantine": False,
    "privileged_system_mutation": False,
}
SCENARIOS = (
    "B7-POWERSHELL-001",
    "B7-PERSISTENCE-001",
    "B7-RANSOMWARE-001",
    "B7-DEFENSE-EVASION-001",
    "B7-C2-DNS-001",
    "B7-CREDENTIAL-001",
)
PARTIAL_BLOCKERS = {
    "B7-POWERSHELL-001": "No accepted live positive threat-detector path without reading script or command payload data.",
    "B7-PERSISTENCE-001": "No accepted live persistence detector source is wired to a harmless positive control.",
    "B7-DEFENSE-EVASION-001": "Positive live control would require security-control mutation outside the current authority boundary.",
    "B7-C2-DNS-001": "No accepted live DNS threat-detector path is available without enabling network test authority.",
    "B7-CREDENTIAL-001": "Positive live credential-access control would require sensitive access prohibited by the privacy boundary.",
}


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _parse_utc(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(timezone.utc)


def _valid_int(value: object) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= MAX_EVENT_COUNT
    )


def _valid_float(value: object) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
        and 0.0 <= float(value) <= 1.0
    )


def validate_evidence(data: object) -> tuple[str, ...]:
    if not isinstance(data, dict):
        return ("evidence:not_object",)
    failures: list[str] = []
    if set(data) != {"schema", "source", "controls", "boundaries"}:
        failures.append("evidence:unexpected_or_missing_fields")
    if data.get("schema") != SCHEMA or data.get("source") != SOURCE:
        failures.append("evidence:source_or_schema_invalid")
    boundaries = data.get("boundaries")
    if not isinstance(boundaries, dict) or set(boundaries) != set(BOUNDARIES) or any(
        boundaries.get(key) is not value for key, value in BOUNDARIES.items()
    ):
        failures.append("evidence:boundary_invalid")

    controls = data.get("controls")
    if not isinstance(controls, list) or len(controls) != len(CONTROL_IDS):
        return tuple(failures + ["evidence:control_count_invalid"])

    for index, (expected_id, row) in enumerate(zip(CONTROL_IDS, controls)):
        prefix = f"control[{index}]"
        if not isinstance(row, dict) or set(row) != CONTROL_FIELDS:
            failures.append(f"{prefix}:fields_invalid")
            continue
        if row.get("control_id") != expected_id:
            failures.append(f"{prefix}:identity_invalid")
        if row.get("live_observation") is not True:
            failures.append(f"{prefix}:live_observation_required")
        if row.get("sandbox_scope") != "DEDICATED_TEMP_DIRECTORY":
            failures.append(f"{prefix}:sandbox_scope_invalid")
        if row.get("observer_backend") != "WATCHDOG_LOCAL_FILESYSTEM":
            failures.append(f"{prefix}:observer_backend_invalid")
        if not _valid_int(row.get("write_event_count")):
            failures.append(f"{prefix}:write_event_count_invalid")
        if not _valid_int(row.get("rename_event_count")):
            failures.append(f"{prefix}:rename_event_count_invalid")
        if not _valid_float(row.get("entropy_delta")):
            failures.append(f"{prefix}:entropy_delta_invalid")
        for field_name in (
            "extension_changed",
            "canary_touched",
            "known_backup_workflow",
            "user_initiated_bulk_operation",
        ):
            if not isinstance(row.get(field_name), bool):
                failures.append(f"{prefix}:{field_name}_invalid")
        started = _parse_utc(row.get("started_at_utc"))
        completed = _parse_utc(row.get("completed_at_utc"))
        if started is None or completed is None:
            failures.append(f"{prefix}:time_invalid")
        elif completed < started or completed - started > timedelta(seconds=20):
            failures.append(f"{prefix}:time_window_invalid")
        if row.get("cleanup_state") != "CLEAN":
            failures.append(f"{prefix}:cleanup_not_confirmed")

    if isinstance(controls, list) and len(controls) == 3 and all(isinstance(row, dict) for row in controls):
        positive, administrative, benign = controls
        if positive.get("known_backup_workflow") is not False or positive.get("user_initiated_bulk_operation") is not False:
            failures.append("positive:suppressor_not_allowed")
        if positive.get("extension_changed") is not True or positive.get("canary_touched") is not True:
            failures.append("positive:required_safe_signals_missing")
        if administrative.get("known_backup_workflow") is not True or administrative.get("user_initiated_bulk_operation") is not True:
            failures.append("administrative:explicit_suppressors_required")
        if benign.get("known_backup_workflow") is not False or benign.get("user_initiated_bulk_operation") is not False:
            failures.append("benign:suppressor_invalid")
        if benign.get("extension_changed") is not False or benign.get("canary_touched") is not False:
            failures.append("benign:unexpected_signal")
    return tuple(failures)


def _observation(row: dict[str, Any]) -> tuple[ransomware_detector.FileActivityObservation, str]:
    completed = _parse_utc(row["completed_at_utc"])
    assert completed is not None
    evidence_material = {
        "control_id": row["control_id"],
        "write_event_count": row["write_event_count"],
        "rename_event_count": row["rename_event_count"],
        "entropy_delta": row["entropy_delta"],
        "extension_changed": row["extension_changed"],
        "canary_touched": row["canary_touched"],
        "started_at_utc": row["started_at_utc"],
        "completed_at_utc": row["completed_at_utc"],
    }
    evidence_id = "b93-live-file:" + _sha(evidence_material)[:24]
    observation = ransomware_detector.FileActivityObservation(
        event_id="b93:" + row["control_id"],
        observed_at=completed.timestamp(),
        logical_path="b93://" + row["control_id"],
        evidence_id=evidence_id,
        provenance={
            "source": "b93-live-temp-file-activity",
            "source_id": evidence_id,
            "collector": "sentinel.beta9_ransomware_controls",
            "trust": "DIRECT",
        },
        write_count_window=int(row["write_event_count"]),
        rename_count_window=int(row["rename_event_count"]),
        entropy_delta=float(row["entropy_delta"]),
        extension_changed=bool(row["extension_changed"]),
        canary_touched=bool(row["canary_touched"]),
        known_backup_workflow=bool(row["known_backup_workflow"]),
        user_initiated_bulk_operation=bool(row["user_initiated_bulk_operation"]),
        correlation_key="b93:" + row["control_id"],
    )
    return observation, evidence_id


def _positive_graph(
    observation: ransomware_detector.FileActivityObservation,
    result: ransomware_detector.DetectionResult,
    evidence_id: str,
) -> tuple[security_graph.SecurityGraph, incident_correlation.CorrelationResult]:
    provenance_event = {
        "source": "b93-live-temp-file-activity",
        "source_id": evidence_id,
        "collector": "sentinel.beta9_ransomware_controls",
        "trust": "DIRECT",
    }
    provenance_detector = {
        "source": "accepted-ransomware-detector",
        "source_id": TARGET_SCENARIO,
        "collector": "sentinel.ransomware_detector.detect",
        "trust": "DERIVED",
    }
    builder = security_graph.SecurityGraphBuilder()
    evidence_node = builder.ingest_observation(
        {
            "node_type": "EVIDENCE",
            "identity": {"evidence_id": evidence_id},
            "label": "B9-3 controlled live local file-activity aggregate",
            "observed_at": observation.observed_at,
            "provenance": provenance_event,
            "evidence_ids": [evidence_id],
            "confidence": 1.0,
            "attributes": {
                "live_control": True,
                "write_event_count": observation.write_count_window,
                "rename_event_count": observation.rename_count_window,
                "entropy_delta": observation.entropy_delta,
                "extension_changed": observation.extension_changed,
                "canary_touched": observation.canary_touched,
                "correlation_keys": [observation.correlation_key],
            },
        }
    )
    detection_node = builder.ingest_observation(
        {
            "node_type": "DETECTION",
            "identity": {"scenario": TARGET_SCENARIO, "evidence_id": evidence_id},
            "label": "B9-3 live ransomware-like detector control",
            "observed_at": observation.observed_at,
            "provenance": provenance_detector,
            "evidence_ids": [evidence_id],
            "confidence": min(1.0, result.score / 10.0),
            "attributes": {
                "live_control": True,
                "outcome": result.outcome,
                "score": result.score,
                "matched_signals": list(result.matched_signals),
                "correlation_keys": [observation.correlation_key],
            },
        }
    )
    builder.link(
        edge_type="SUPPORTED_BY",
        source=detection_node.node_id,
        target=evidence_node.node_id,
        observed_at=observation.observed_at,
        provenance=provenance_detector,
        evidence_ids=[evidence_id],
        confidence=1.0,
        reason="Accepted ransomware-like detector result is supported by the controlled live local file-activity evidence.",
    )
    graph = builder.build(
        graph_id="b93-ransomware:" + _sha({"evidence_id": evidence_id})[:20],
        incident_id="b93-ransomware:" + _sha({"evidence_id": evidence_id, "scenario": TARGET_SCENARIO})[:20],
        created_at=observation.observed_at,
        metadata={
            "exercise": "B9-3",
            "scenario_id": TARGET_SCENARIO,
            "live_control": True,
            "real_malware": False,
        },
    )
    correlation = incident_correlation.IncidentCorrelator(max_time_delta=30.0).correlate(graph)
    return graph, correlation


def summarize(data: object) -> dict[str, Any]:
    failures = validate_evidence(data)
    if failures:
        return {"passed": False, "failures": list(failures)}
    assert isinstance(data, dict)
    controls = data["controls"]
    observations: dict[str, ransomware_detector.FileActivityObservation] = {}
    evidence_ids: dict[str, str] = {}
    outcomes: dict[str, ransomware_detector.DetectionResult] = {}
    for row in controls:
        observation, evidence_id = _observation(row)
        observations[row["control_id"]] = observation
        evidence_ids[row["control_id"]] = evidence_id
        outcomes[row["control_id"]] = ransomware_detector.detect((observation,))

    positive = outcomes["positive-ransomware-like"]
    administrative = outcomes["administrative-backup-like"]
    benign = outcomes["benign-save"]
    positive_observation = observations["positive-ransomware-like"]
    positive_id = evidence_ids["positive-ransomware-like"]
    graph, correlation = _positive_graph(positive_observation, positive, positive_id)
    graph_validation = security_graph.validate_graph(graph.to_dict())
    correlation_validation = incident_correlation.validate_result(correlation, graph)
    binding_ok = (
        graph_validation.passed
        and correlation_validation.passed
        and len(graph.nodes) == 2
        and len(graph.edges) == 1
        and len(correlation.incidents) == 1
        and all(positive_id in node.evidence_ids for node in graph.nodes)
        and positive_id in graph.edges[0].evidence_ids
    )

    live_thresholds_ok = (
        positive_observation.write_count_window >= ransomware_detector.MIN_BULK_WRITES
        and positive_observation.rename_count_window >= ransomware_detector.MIN_BULK_RENAMES
        and positive_observation.entropy_delta >= ransomware_detector.MIN_ENTROPY_DELTA
    )
    controls_ok = (
        positive.outcome == ransomware_detector.OUTCOME_DETECTED
        and administrative.outcome == ransomware_detector.OUTCOME_REVIEW
        and benign.outcome == ransomware_detector.OUTCOME_NO_MATCH
        and live_thresholds_ok
        and binding_ok
    )

    decisions: list[dict[str, Any]] = []
    for scenario_id in SCENARIOS:
        if scenario_id == TARGET_SCENARIO:
            decisions.append(
                {
                    "scenario_id": scenario_id,
                    "status": "VERIFIED" if controls_ok else "PARTIAL",
                    "evidence_basis": (
                        "CONTROLLED_LIVE_LOCAL_DETECTOR_PATH"
                        if controls_ok
                        else "LIVE_CONTROL_ACCEPTANCE_INCOMPLETE"
                    ),
                    "limitation": "Scenario-specific controlled local detector-path verification; not a claim of broad ransomware-family coverage.",
                }
            )
        else:
            decisions.append(
                {
                    "scenario_id": scenario_id,
                    "status": "PARTIAL",
                    "evidence_basis": "NO_ACCEPTED_LIVE_POSITIVE_CONTROL",
                    "limitation": PARTIAL_BLOCKERS[scenario_id],
                }
            )
    summary = {
        "PARTIAL": sum(1 for item in decisions if item["status"] == "PARTIAL"),
        "GAP": sum(1 for item in decisions if item["status"] == "GAP"),
        "VERIFIED": sum(1 for item in decisions if item["status"] == "VERIFIED"),
    }
    passed = controls_ok and summary == {"PARTIAL": 5, "GAP": 0, "VERIFIED": 1}
    return {
        "passed": bool(passed),
        "target_scenario_id": TARGET_SCENARIO,
        "detector_module": "sentinel.ransomware_detector.detect",
        "control_outcomes": {
            "positive-ransomware-like": positive.outcome,
            "administrative-backup-like": administrative.outcome,
            "benign-save": benign.outcome,
        },
        "positive_score": positive.score,
        "positive_matched_signals": list(positive.matched_signals),
        "live_thresholds_met": bool(live_thresholds_ok),
        "positive_evidence_id": positive_id,
        "detector_to_security_graph_bound": bool(binding_ok),
        "security_graph_to_incident_bound": bool(binding_ok),
        "graph_digest": graph.digest(),
        "correlation_digest": correlation.digest(),
        "coverage_summary": summary,
        "coverage_decisions": decisions,
        "controlled_threat_detector_verification_performed": bool(controls_ok),
        "broad_ransomware_protection_claimed": False,
        "synthetic_fallback_used": False,
        "boundaries": dict(BOUNDARIES),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    try:
        data = json.loads(args.evidence.read_text(encoding="utf-8-sig"))
        result = summarize(data)
    except (OSError, UnicodeError, ValueError):
        result = {"passed": False, "failures": ["evidence:unreadable_or_invalid_json"]}
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if result.get("passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())

"""B9-2: bind one fresh harmless Windows event to acceptance detector, graph and incident.

The input is produced by the local B9-2 exercise harness. Only allowlisted event
metadata is accepted. This module performs no process launch, Windows-log access,
remediation, or threat classification itself.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from sentinel import incident_correlation, security_graph

SCHEMA = "bc-sentinel-beta9-harmless-event-v1"
SOURCE = "WINDOWS_POWERSHELL_ENGINE_LIVE_EXERCISE"
CHANNEL = "Windows PowerShell"
PROVIDER = "PowerShell"
EVENT_IDS = {400, 403}
EXERCISE_FIELDS = {
    "live_observation",
    "child_process_id",
    "baseline_record_id",
    "launched_at_utc",
    "completed_at_utc",
    "cleanup_state",
    "exit_code",
}
EVENT_FIELDS = {
    "channel",
    "provider",
    "event_id",
    "level",
    "record_id",
    "process_id",
    "time_created_utc",
}
BOUNDARIES = {
    "local_only": True,
    "explicit_opt_in_required": True,
    "harmless_exercise_only": True,
    "event_message_read": False,
    "event_payload_read": False,
    "event_properties_read": False,
    "personal_data_collected": False,
    "remote_access": False,
    "logging_configuration_mutation": False,
    "audit_policy_mutation": False,
    "elevation_requested": False,
    "product_process_launch_authority": False,
    "product_process_termination_authority": False,
    "remediation_authority": False,
    "threat_classification": False,
    "verified_coverage": False,
}
COVERAGE = {"PARTIAL": 6, "GAP": 0, "VERIFIED": 0}


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


def _valid_int(value: object, *, minimum: int = 0) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= minimum


def validate_exercise(data: object) -> tuple[str, ...]:
    if not isinstance(data, dict):
        return ("exercise:not_object",)
    failures: list[str] = []
    if set(data) != {"schema", "source", "exercise", "event", "boundaries"}:
        failures.append("exercise:unexpected_or_missing_fields")
    if data.get("schema") != SCHEMA or data.get("source") != SOURCE:
        failures.append("exercise:source_or_schema_invalid")

    boundaries = data.get("boundaries")
    if not isinstance(boundaries, dict) or set(boundaries) != set(BOUNDARIES) or any(
        boundaries.get(key) is not value for key, value in BOUNDARIES.items()
    ):
        failures.append("exercise:boundary_invalid")

    exercise = data.get("exercise")
    if not isinstance(exercise, dict) or set(exercise) != EXERCISE_FIELDS:
        failures.append("exercise:exercise_fields_invalid")
        exercise = {}
    if exercise.get("live_observation") is not True:
        failures.append("exercise:live_observation_required")
    child_pid = exercise.get("child_process_id")
    if not _valid_int(child_pid, minimum=1):
        failures.append("exercise:child_process_id_invalid")
    baseline = exercise.get("baseline_record_id")
    if baseline is not None and not _valid_int(baseline):
        failures.append("exercise:baseline_record_id_invalid")
    launched = _parse_utc(exercise.get("launched_at_utc"))
    completed = _parse_utc(exercise.get("completed_at_utc"))
    if launched is None or completed is None:
        failures.append("exercise:time_invalid")
    elif completed < launched or completed - launched > timedelta(seconds=15):
        failures.append("exercise:time_window_invalid")
    if exercise.get("cleanup_state") != "EXITED":
        failures.append("exercise:cleanup_not_confirmed")
    if exercise.get("exit_code") != 0:
        failures.append("exercise:child_exit_invalid")

    event = data.get("event")
    if not isinstance(event, dict) or set(event) != EVENT_FIELDS:
        failures.append("exercise:event_fields_invalid")
        event = {}
    if event.get("channel") != CHANNEL or event.get("provider") != PROVIDER:
        failures.append("exercise:event_source_invalid")
    event_id = event.get("event_id")
    if not _valid_int(event_id) or event_id not in EVENT_IDS:
        failures.append("exercise:event_id_invalid")
    level = event.get("level")
    if level is not None and (not _valid_int(level) or level > 255):
        failures.append("exercise:event_level_invalid")
    record_id = event.get("record_id")
    if not _valid_int(record_id):
        failures.append("exercise:event_record_id_invalid")
    process_id = event.get("process_id")
    if not _valid_int(process_id, minimum=1):
        failures.append("exercise:event_process_id_invalid")
    elif _valid_int(child_pid, minimum=1) and process_id != child_pid:
        failures.append("exercise:event_process_binding_mismatch")
    if _valid_int(record_id) and _valid_int(baseline) and record_id <= baseline:
        failures.append("exercise:event_not_fresh_by_record_id")

    event_time = _parse_utc(event.get("time_created_utc"))
    if event_time is None:
        failures.append("exercise:event_time_invalid")
    elif launched is not None and completed is not None:
        if event_time < launched - timedelta(seconds=2) or event_time > completed + timedelta(seconds=10):
            failures.append("exercise:event_not_fresh_by_time")
    return tuple(failures)


def _material(data: dict[str, Any]) -> tuple[str, str, float]:
    exercise = data["exercise"]
    event = data["event"]
    marker_material = {
        "child_process_id": exercise["child_process_id"],
        "baseline_record_id": exercise["baseline_record_id"],
        "launched_at_utc": exercise["launched_at_utc"],
    }
    marker = "b92-marker:" + _sha(marker_material)[:24]
    evidence_material = {
        "marker": marker,
        "channel": event["channel"],
        "provider": event["provider"],
        "event_id": event["event_id"],
        "record_id": event["record_id"],
        "process_id": event["process_id"],
        "time_created_utc": event["time_created_utc"],
    }
    evidence_id = "b92-event:" + _sha(evidence_material)[:24]
    observed_at = _parse_utc(event["time_created_utc"])
    assert observed_at is not None
    return marker, evidence_id, observed_at.timestamp()


def _build_graph(data: dict[str, Any]) -> tuple[security_graph.SecurityGraph, incident_correlation.CorrelationResult, str, str]:
    marker, evidence_id, observed_at = _material(data)
    event = data["event"]
    provenance_event = {
        "source": "windows-event-log-metadata",
        "source_id": evidence_id,
        "collector": "sentinel.beta9_event_to_incident",
        "trust": "DIRECT",
    }
    provenance_detector = {
        "source": "b92-benign-acceptance-detector",
        "source_id": marker,
        "collector": "sentinel.beta9_event_to_incident",
        "trust": "DERIVED",
    }
    builder = security_graph.SecurityGraphBuilder()
    evidence_node = builder.ingest_observation(
        {
            "node_type": "EVIDENCE",
            "identity": {"evidence_id": evidence_id},
            "label": "Allowlisted Windows PowerShell engine lifecycle metadata",
            "observed_at": observed_at,
            "provenance": provenance_event,
            "evidence_ids": [evidence_id],
            "confidence": 1.0,
            "attributes": {
                "channel": event["channel"],
                "provider": event["provider"],
                "event_id": event["event_id"],
                "record_id": event["record_id"],
                "correlation_keys": [marker],
            },
        }
    )
    detection_node = builder.ingest_observation(
        {
            "node_type": "DETECTION",
            "identity": {"marker": marker, "outcome": "BENIGN_EXERCISE_OBSERVED"},
            "label": "B9-2 benign acceptance observation",
            "observed_at": observed_at,
            "provenance": provenance_detector,
            "evidence_ids": [evidence_id],
            "confidence": 1.0,
            "attributes": {
                "outcome": "BENIGN_EXERCISE_OBSERVED",
                "threat_classification": False,
                "correlation_keys": [marker],
            },
        }
    )
    builder.link(
        edge_type="SUPPORTED_BY",
        source=detection_node.node_id,
        target=evidence_node.node_id,
        observed_at=observed_at,
        provenance=provenance_detector,
        evidence_ids=[evidence_id],
        confidence=1.0,
        reason="Benign acceptance observation is supported by the freshly bound allowlisted event metadata.",
    )
    graph = builder.build(
        graph_id="b92-graph:" + _sha({"marker": marker})[:20],
        incident_id="b92-exercise:" + _sha({"marker": marker, "evidence": evidence_id})[:20],
        created_at=observed_at,
        metadata={
            "exercise": "B9-2",
            "harmless": True,
            "threat_classification": False,
            "correlation_marker": marker,
        },
    )
    correlation = incident_correlation.IncidentCorrelator(max_time_delta=30.0).correlate(graph)
    return graph, correlation, marker, evidence_id


def summarize(data: object) -> dict[str, Any]:
    failures = validate_exercise(data)
    if failures:
        # Fail closed without echoing rejected input or any unexpected fields.
        return {"passed": False, "failures": list(failures)}
    assert isinstance(data, dict)
    graph, correlation, marker, evidence_id = _build_graph(data)
    graph_validation = security_graph.validate_graph(graph.to_dict())
    correlation_validation = incident_correlation.validate_result(correlation, graph)
    incidents_with_both = [
        incident
        for incident in correlation.incidents
        if len(incident.node_ids) == 2 and evidence_id in {
            evidence
            for node_id in incident.node_ids
            for node in graph.nodes
            if node.node_id == node_id
            for evidence in node.evidence_ids
        }
    ]
    binding_ok = (
        graph_validation.passed
        and correlation_validation.passed
        and len(graph.nodes) == 2
        and len(graph.edges) == 1
        and len(correlation.incidents) == 1
        and len(incidents_with_both) == 1
        and all(evidence_id in node.evidence_ids for node in graph.nodes)
        and evidence_id in graph.edges[0].evidence_ids
    )
    return {
        "passed": bool(binding_ok),
        "exercise_marker_digest": marker,
        "evidence_id": evidence_id,
        "acceptance_detector_outcome": "BENIGN_EXERCISE_OBSERVED",
        "live_event_bound": True,
        "event_to_acceptance_detector_bound": bool(binding_ok),
        "detector_to_security_graph_bound": bool(binding_ok),
        "security_graph_to_incident_bound": bool(binding_ok),
        "graph_digest": graph.digest(),
        "correlation_digest": correlation.digest(),
        "incident_count": len(correlation.incidents),
        "graph_node_count": len(graph.nodes),
        "graph_edge_count": len(graph.edges),
        "threat_detector_verification_performed": False,
        "threat_classification_performed": False,
        "coverage_summary": dict(COVERAGE),
        "boundaries": dict(BOUNDARIES),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exercise", type=Path, required=True)
    args = parser.parse_args()
    try:
        data = json.loads(args.exercise.read_text(encoding="utf-8-sig"))
        result = summarize(data)
    except (OSError, UnicodeError, ValueError):
        result = {"passed": False, "failures": ["exercise:unreadable_or_invalid_json"]}
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if result.get("passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())

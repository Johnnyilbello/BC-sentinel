"""B10-3 controlled live PowerShell metadata detector-path verification.

This module consumes aggregate metadata emitted by the explicit Windows acceptance
harness. It never reads PowerShell command/script content, event messages,
Properties/ToXml payloads, user files, credentials, or remote data. The detector
is intentionally narrow: it detects a rapid burst of short-lived Windows
PowerShell engine sessions from lifecycle metadata only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Final

from sentinel import incident_correlation, security_graph

SCHEMA: Final[str] = "bc-sentinel-beta10-powershell-live-controls-v1"
SOURCE: Final[str] = "WINDOWS_POWERSHELL_METADATA_LIVE_CONTROLS"
TARGET_SCENARIO: Final[str] = "B7-POWERSHELL-001"
RANSOMWARE_SCENARIO: Final[str] = "B7-RANSOMWARE-001"
CONTROL_IDS: Final[tuple[str, ...]] = (
    "positive-powershell-burst",
    "administrative-powershell-burst",
    "benign-powershell-session",
)
OUTCOME_DETECTED = "DETECTED"
OUTCOME_REVIEW = "REVIEW_REQUIRED"
OUTCOME_NO_MATCH = "NO_MATCH"
MIN_BURST_SESSIONS = 6
MAX_BURST_SECONDS = 12.0

CONTROL_FIELDS = {
    "control_id", "live_observation", "channel", "provider", "session_count",
    "start_event_count", "stop_event_count", "unique_process_count",
    "duration_seconds", "known_admin_automation", "user_initiated_bulk_operation",
    "started_at_utc", "completed_at_utc", "cleanup_state",
}
BOUNDARIES: Final[dict[str, bool]] = {
    "local_only": True,
    "explicit_opt_in_required": True,
    "harmless_exercise_only": True,
    "event_message_read": False,
    "event_payload_read": False,
    "event_properties_read": False,
    "powershell_command_read": False,
    "powershell_script_read": False,
    "personal_data_collected": False,
    "user_file_access": False,
    "file_content_collected": False,
    "absolute_paths_exported": False,
    "remote_access": False,
    "network_io": False,
    "logging_configuration_mutation": False,
    "audit_policy_mutation": False,
    "registry_mutation": False,
    "credential_access": False,
    "real_malware_executed": False,
    "product_process_launch_authority": False,
    "product_process_termination_authority": False,
    "remediation_authority": False,
    "automatic_quarantine": False,
    "privileged_system_mutation": False,
}
SCENARIOS = (
    "B7-POWERSHELL-001", "B7-PERSISTENCE-001", "B7-RANSOMWARE-001",
    "B7-DEFENSE-EVASION-001", "B7-C2-DNS-001", "B7-CREDENTIAL-001",
)
PARTIAL_BLOCKERS = {
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


def _nonnegative_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _nonnegative_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and float(value) >= 0.0


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
        boundaries.get(k) is not v for k, v in BOUNDARIES.items()
    ):
        failures.append("evidence:boundary_invalid")
    controls = data.get("controls")
    if not isinstance(controls, list) or len(controls) != 3:
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
        if row.get("channel") != "Windows PowerShell" or row.get("provider") != "PowerShell":
            failures.append(f"{prefix}:event_source_invalid")
        for field in ("session_count", "start_event_count", "stop_event_count", "unique_process_count"):
            if not _nonnegative_int(row.get(field)):
                failures.append(f"{prefix}:{field}_invalid")
        if not _nonnegative_number(row.get("duration_seconds")) or float(row.get("duration_seconds", 0)) > 20.0:
            failures.append(f"{prefix}:duration_invalid")
        for field in ("known_admin_automation", "user_initiated_bulk_operation"):
            if not isinstance(row.get(field), bool):
                failures.append(f"{prefix}:{field}_invalid")
        started = _parse_utc(row.get("started_at_utc"))
        completed = _parse_utc(row.get("completed_at_utc"))
        if started is None or completed is None or completed < started or completed - started > timedelta(seconds=20):
            failures.append(f"{prefix}:time_invalid")
        if row.get("cleanup_state") != "EXITED":
            failures.append(f"{prefix}:cleanup_not_confirmed")
    if all(isinstance(row, dict) for row in controls):
        positive, administrative, benign = controls
        if positive.get("known_admin_automation") is not False or positive.get("user_initiated_bulk_operation") is not False:
            failures.append("positive:suppressor_not_allowed")
        if administrative.get("known_admin_automation") is not True or administrative.get("user_initiated_bulk_operation") is not True:
            failures.append("administrative:suppressors_required")
        if benign.get("known_admin_automation") is not False or benign.get("user_initiated_bulk_operation") is not False:
            failures.append("benign:suppressor_invalid")
    return tuple(failures)


def detect_control(row: dict[str, Any]) -> dict[str, Any]:
    session_count = int(row["session_count"])
    unique_count = int(row["unique_process_count"])
    starts = int(row["start_event_count"])
    stops = int(row["stop_event_count"])
    duration = float(row["duration_seconds"])
    signals: list[str] = []
    score = 0
    if session_count >= MIN_BURST_SESSIONS and unique_count >= MIN_BURST_SESSIONS:
        signals.append("RAPID_SESSION_BURST"); score += 4
    if starts >= MIN_BURST_SESSIONS and duration <= MAX_BURST_SECONDS:
        signals.append("HIGH_START_DENSITY"); score += 2
    if starts >= MIN_BURST_SESSIONS and stops >= MIN_BURST_SESSIONS:
        signals.append("LIFECYCLE_COMPLETENESS"); score += 1
    suppressor = bool(row["known_admin_automation"] or row["user_initiated_bulk_operation"])
    if score >= 6 and suppressor:
        outcome = OUTCOME_REVIEW
    elif score >= 6:
        outcome = OUTCOME_DETECTED
    else:
        outcome = OUTCOME_NO_MATCH
    return {"outcome": outcome, "score": score, "matched_signals": signals, "suppressor": suppressor}


def _positive_graph(row: dict[str, Any], result: dict[str, Any]) -> tuple[security_graph.SecurityGraph, incident_correlation.CorrelationResult, str]:
    material = {
        "control_id": row["control_id"], "session_count": row["session_count"],
        "start_event_count": row["start_event_count"], "stop_event_count": row["stop_event_count"],
        "unique_process_count": row["unique_process_count"], "started_at_utc": row["started_at_utc"],
        "completed_at_utc": row["completed_at_utc"],
    }
    evidence_id = "b103-powershell:" + _sha(material)[:24]
    observed = _parse_utc(row["completed_at_utc"]); assert observed is not None
    key = "b103:" + evidence_id
    event_prov = {"source": "windows-powershell-lifecycle-metadata", "source_id": evidence_id, "collector": "sentinel.beta10_powershell_controls", "trust": "DIRECT"}
    det_prov = {"source": "b103-powershell-lifecycle-burst-detector", "source_id": TARGET_SCENARIO, "collector": "sentinel.beta10_powershell_controls.detect_control", "trust": "DERIVED"}
    builder = security_graph.SecurityGraphBuilder()
    ev = builder.ingest_observation({
        "node_type": "EVIDENCE", "identity": {"evidence_id": evidence_id},
        "label": "Controlled live Windows PowerShell lifecycle metadata aggregate",
        "observed_at": observed.timestamp(), "provenance": event_prov, "evidence_ids": [evidence_id], "confidence": 1.0,
        "attributes": {"session_count": row["session_count"], "start_event_count": row["start_event_count"], "stop_event_count": row["stop_event_count"], "unique_process_count": row["unique_process_count"], "correlation_keys": [key]},
    })
    det = builder.ingest_observation({
        "node_type": "DETECTION", "identity": {"scenario": TARGET_SCENARIO, "evidence_id": evidence_id},
        "label": "B10-3 live PowerShell lifecycle-burst detection",
        "observed_at": observed.timestamp(), "provenance": det_prov, "evidence_ids": [evidence_id], "confidence": min(1.0, result["score"] / 7.0),
        "attributes": {"outcome": result["outcome"], "score": result["score"], "matched_signals": list(result["matched_signals"]), "correlation_keys": [key]},
    })
    builder.link(edge_type="SUPPORTED_BY", source=det.node_id, target=ev.node_id, observed_at=observed.timestamp(), provenance=det_prov, evidence_ids=[evidence_id], confidence=1.0, reason="PowerShell lifecycle-burst detection is supported by fresh allowlisted lifecycle metadata only.")
    graph = builder.build(graph_id="b103-ps:" + _sha({"e": evidence_id})[:20], incident_id="b103-ps:" + _sha({"e": evidence_id, "s": TARGET_SCENARIO})[:20], created_at=observed.timestamp(), metadata={"exercise": "B10-3", "scenario_id": TARGET_SCENARIO, "live_control": True, "content_read": False})
    correlation = incident_correlation.IncidentCorrelator(max_time_delta=30.0).correlate(graph)
    return graph, correlation, evidence_id


def summarize(data: object) -> dict[str, Any]:
    failures = validate_evidence(data)
    if failures:
        return {"passed": False, "failures": list(failures)}
    assert isinstance(data, dict)
    rows = {row["control_id"]: row for row in data["controls"]}
    results = {cid: detect_control(row) for cid, row in rows.items()}
    positive = results[CONTROL_IDS[0]]; administrative = results[CONTROL_IDS[1]]; benign = results[CONTROL_IDS[2]]
    graph, correlation, evidence_id = _positive_graph(rows[CONTROL_IDS[0]], positive)
    graph_ok = security_graph.validate_graph(graph.to_dict()).passed
    corr_ok = incident_correlation.validate_result(correlation, graph).passed
    binding_ok = graph_ok and corr_ok and len(graph.nodes) == 2 and len(graph.edges) == 1 and len(correlation.incidents) == 1 and all(evidence_id in n.evidence_ids for n in graph.nodes) and evidence_id in graph.edges[0].evidence_ids
    controls_ok = positive["outcome"] == OUTCOME_DETECTED and administrative["outcome"] == OUTCOME_REVIEW and benign["outcome"] == OUTCOME_NO_MATCH and binding_ok

    decisions: list[dict[str, str]] = []
    for scenario in SCENARIOS:
        if scenario == TARGET_SCENARIO:
            decisions.append({"scenario_id": scenario, "status": "VERIFIED" if controls_ok else "PARTIAL", "evidence_basis": "CONTROLLED_LIVE_POWERSHELL_METADATA_DETECTOR_PATH" if controls_ok else "LIVE_CONTROL_ACCEPTANCE_INCOMPLETE", "limitation": "Metadata-only lifecycle-burst verification; no PowerShell command/script content was inspected and this is not broad script-abuse coverage."})
        elif scenario == RANSOMWARE_SCENARIO:
            decisions.append({"scenario_id": scenario, "status": "VERIFIED", "evidence_basis": "ACCEPTED_B9_CONTROLLED_LIVE_LOCAL_DETECTOR_PATH", "limitation": "Scenario-specific controlled local ransomware-like verification; not broad ransomware-family coverage."})
        else:
            decisions.append({"scenario_id": scenario, "status": "PARTIAL", "evidence_basis": "NO_ACCEPTED_LIVE_POSITIVE_CONTROL", "limitation": PARTIAL_BLOCKERS[scenario]})
    coverage = {k: sum(1 for d in decisions if d["status"] == k) for k in ("PARTIAL", "GAP", "VERIFIED")}
    return {
        "schema": SCHEMA, "profile": "v0.11.0-beta.10-b103-live-coverage-expansion-i",
        "passed": bool(controls_ok), "failures": [] if controls_ok else ["powershell_live_controls_incomplete"],
        "target_scenario_id": TARGET_SCENARIO, "control_results": results,
        "detector_to_security_graph_bound": bool(binding_ok), "security_graph_to_incident_bound": bool(binding_ok),
        "graph_digest": graph.digest(), "correlation_digest": correlation.digest(), "evidence_id": evidence_id,
        "coverage_summary": coverage, "coverage_decisions": decisions,
        "controlled_threat_detector_verification_performed": bool(controls_ok),
        "powershell_content_read": False, "synthetic_fallback_used": False,
        "broad_powershell_protection_claimed": False, "broad_protection_claimed": False,
        "authority_expanded": False, "boundaries": dict(BOUNDARIES),
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
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())

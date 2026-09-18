from __future__ import annotations

"""B12-2 PowerShell & Script Abuse Expansion.

Consumes privacy-minimal evidence produced by an explicit harmless Windows
control harness. The verified path is intentionally narrow: a PowerShell script
running inside a disposable temp workspace creates a short burst of harmless
files. Positive, administrative and benign controls are required. No command
line, script content, raw path, user data, credential material, network traffic,
remediation or privileged mutation is collected or authorized.
"""

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Final

from sentinel import beta12_process_file_correlation as b121
from sentinel import incident_correlation, security_graph

SCHEMA: Final[str] = "bc-sentinel-beta12-script-abuse-live-controls-v1"
PROFILE: Final[str] = "v0.12.0-beta.12-b122-powershell-script-abuse-expansion"
SOURCE: Final[str] = "WINDOWS_POWERSHELL_SCRIPT_ABUSE_LIVE_CONTROLS"
SOURCE_CHECKPOINT: Final[str] = "checkpoint/v012-beta12-b121-pass"
SOURCE_CHECKPOINT_COMMIT: Final[str] = "cd8b3e89211afe29bf32a2646f4210c73179bc1f"

TARGET_SCENARIO: Final[str] = "B12-SCRIPT-ABUSE-001"
BASELINE_VERIFIED: Final[tuple[str, ...]] = (
    "B7-POWERSHELL-001",
    "B7-RANSOMWARE-001",
)
CONTROL_IDS: Final[tuple[str, ...]] = (
    "positive-script-mutation-burst",
    "administrative-script-mutation-burst",
    "benign-powershell-script",
)

OUTCOME_DETECTED: Final[str] = "DETECTED"
OUTCOME_REVIEW: Final[str] = "REVIEW_REQUIRED"
OUTCOME_NO_MATCH: Final[str] = "NO_MATCH"

MIN_MUTATIONS: Final[int] = 6
MAX_DURATION_SECONDS: Final[float] = 12.0

CONTROL_FIELDS: Final[set[str]] = {
    "control_id",
    "live_observation",
    "script_execution_observed",
    "script_sha256",
    "script_path_digest",
    "file_mutation_count",
    "duration_seconds",
    "known_admin_automation",
    "user_initiated_bulk_operation",
    "cleanup_state",
    "correlation_observation",
}

BOUNDARIES: Final[dict[str, bool]] = {
    "local_only": True,
    "explicit_opt_in_required": True,
    "harmless_exercise_only": True,
    "disposable_temp_workspace_only": True,
    "script_content_exported": False,
    "command_line_exported": False,
    "raw_path_exported": False,
    "username_collected": False,
    "event_payload_collected": False,
    "credential_access": False,
    "network_io": False,
    "remote_access": False,
    "registry_mutation": False,
    "logging_configuration_mutation": False,
    "audit_policy_mutation": False,
    "real_malware_executed": False,
    "automatic_quarantine": False,
    "automatic_repair": False,
    "automatic_restore": False,
    "terminate_process_authority": False,
    "trust_allowlist_mutation": False,
    "privileged_system_mutation": False,
}

COVERAGE_DECISIONS: Final[tuple[dict[str, str], ...]] = (
    {
        "scenario_id": "B7-POWERSHELL-001",
        "status": "VERIFIED",
        "evidence_basis": "ACCEPTED_B10_METADATA_LIFECYCLE_BURST_CONTROL",
        "limitation": "Metadata-only lifecycle-burst verification; not broad script-abuse coverage.",
    },
    {
        "scenario_id": "B7-RANSOMWARE-001",
        "status": "VERIFIED",
        "evidence_basis": "ACCEPTED_B9_CONTROLLED_LOCAL_RANSOMWARE_LIKE_PATH",
        "limitation": "Controlled local scenario only; not broad ransomware-family coverage.",
    },
    {
        "scenario_id": "B7-PERSISTENCE-001",
        "status": "PARTIAL",
        "evidence_basis": "NO_ACCEPTED_LIVE_POSITIVE_CONTROL",
        "limitation": "Persistence verification is reserved for B12-3.",
    },
    {
        "scenario_id": "B7-DEFENSE-EVASION-001",
        "status": "PARTIAL",
        "evidence_basis": "NO_ACCEPTED_SAFE_LIVE_POSITIVE_CONTROL",
        "limitation": "No security-control impairment is performed.",
    },
    {
        "scenario_id": "B7-C2-DNS-001",
        "status": "PARTIAL",
        "evidence_basis": "NO_ACCEPTED_NETWORK_CONTROL",
        "limitation": "Core acceptance remains network-free.",
    },
    {
        "scenario_id": "B7-CREDENTIAL-001",
        "status": "PARTIAL",
        "evidence_basis": "NO_ACCEPTED_SENSITIVE_ACCESS_CONTROL",
        "limitation": "Credential access remains prohibited.",
    },
)


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _valid_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(ch in "0123456789abcdef" for ch in value.lower())
    )


def _valid_nonnegative_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and float(value) >= 0.0


def _valid_nonnegative_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def validate_evidence(data: object) -> tuple[str, ...]:
    if not isinstance(data, dict):
        return ("b122:not_object",)

    failures: list[str] = []
    if set(data) != {"schema", "source", "controls", "boundaries"}:
        failures.append("b122:unexpected_or_missing_fields")
    if data.get("schema") != SCHEMA or data.get("source") != SOURCE:
        failures.append("b122:schema_or_source_invalid")
    if data.get("boundaries") != BOUNDARIES:
        failures.append("b122:boundary_invalid")

    controls = data.get("controls")
    if not isinstance(controls, list) or len(controls) != len(CONTROL_IDS):
        return tuple(dict.fromkeys(failures + ["b122:control_count_invalid"]))

    observation_ids: list[str] = []
    for index, (expected_id, row) in enumerate(zip(CONTROL_IDS, controls)):
        prefix = f"b122:control[{index}]"
        if not isinstance(row, dict) or set(row) != CONTROL_FIELDS:
            failures.append(f"{prefix}:fields_invalid")
            continue
        if row.get("control_id") != expected_id:
            failures.append(f"{prefix}:identity_invalid")
        if row.get("live_observation") is not True:
            failures.append(f"{prefix}:live_observation_required")
        if row.get("script_execution_observed") is not True:
            failures.append(f"{prefix}:script_execution_required")
        if not _valid_sha256(row.get("script_sha256")):
            failures.append(f"{prefix}:script_sha256_invalid")
        if not _valid_sha256(row.get("script_path_digest")):
            failures.append(f"{prefix}:script_path_digest_invalid")
        if not _valid_nonnegative_int(row.get("file_mutation_count")):
            failures.append(f"{prefix}:file_mutation_count_invalid")
        if not _valid_nonnegative_number(row.get("duration_seconds")):
            failures.append(f"{prefix}:duration_invalid")
        elif float(row["duration_seconds"]) > 20.0:
            failures.append(f"{prefix}:duration_too_long")
        for flag in ("known_admin_automation", "user_initiated_bulk_operation"):
            if not isinstance(row.get(flag), bool):
                failures.append(f"{prefix}:{flag}_invalid")
        if row.get("cleanup_state") != "EXITED":
            failures.append(f"{prefix}:cleanup_not_confirmed")

        observation = row.get("correlation_observation")
        obs_failures = b121.validate_observation(observation)
        if obs_failures:
            failures.append(f"{prefix}:correlation_observation_invalid")
        elif isinstance(observation, dict):
            if observation["file"]["operation"] != "CREATED":
                failures.append(f"{prefix}:correlation_operation_invalid")
            observation_ids.append(str(observation["observation_id"]))

    if len(observation_ids) != len(set(observation_ids)):
        failures.append("b122:observation_ids_not_distinct")

    if all(isinstance(row, dict) for row in controls):
        positive, administrative, benign = controls
        if positive.get("known_admin_automation") is not False or positive.get("user_initiated_bulk_operation") is not False:
            failures.append("b122:positive_suppressor_forbidden")
        if administrative.get("known_admin_automation") is not True or administrative.get("user_initiated_bulk_operation") is not True:
            failures.append("b122:administrative_suppressors_required")
        if benign.get("known_admin_automation") is not False or benign.get("user_initiated_bulk_operation") is not False:
            failures.append("b122:benign_suppressor_forbidden")

    return tuple(dict.fromkeys(failures))


def detect_control(row: dict[str, Any]) -> dict[str, Any]:
    correlation = b121.summarize(row["correlation_observation"])
    signals: list[str] = []
    score = 0

    if row["script_execution_observed"]:
        signals.append("POWERSHELL_SCRIPT_EXECUTION")
        score += 2
    if int(row["file_mutation_count"]) >= MIN_MUTATIONS:
        signals.append("SCRIPT_DRIVEN_FILE_MUTATION_BURST")
        score += 4
    if float(row["duration_seconds"]) <= MAX_DURATION_SECONDS:
        signals.append("SHORT_EXECUTION_WINDOW")
        score += 1
    if correlation.get("passed") and correlation.get("process_file_bound"):
        signals.append("PROCESS_FILE_RELATION_BOUND")
        score += 1

    suppressor = bool(row["known_admin_automation"] or row["user_initiated_bulk_operation"])
    if score >= 7 and suppressor:
        outcome = OUTCOME_REVIEW
    elif score >= 7:
        outcome = OUTCOME_DETECTED
    else:
        outcome = OUTCOME_NO_MATCH

    return {
        "outcome": outcome,
        "score": score,
        "matched_signals": signals,
        "suppressor": suppressor,
        "correlation_passed": correlation.get("passed") is True,
        "process_file_bound": correlation.get("process_file_bound") is True,
    }


def _positive_graph(
    row: dict[str, Any],
    result: dict[str, Any],
) -> tuple[security_graph.SecurityGraph, incident_correlation.CorrelationResult, str]:
    source_graph, _ = b121.build_graph(row["correlation_observation"])
    builder = security_graph.SecurityGraphBuilder()
    for node in source_graph.nodes:
        builder.add_node(node)
    for edge in source_graph.edges:
        builder.add_edge(edge)

    evidence = row["correlation_observation"]["evidence"]
    detection_evidence = "b122-detection:" + _sha(
        {
            "control_id": row["control_id"],
            "script_sha256": row["script_sha256"],
            "file_mutation_count": row["file_mutation_count"],
            "relation_evidence_id": evidence["relation_evidence_id"],
        }
    )[:24]
    observed_at = float(row["correlation_observation"]["observed_at"])
    provenance = {
        "source": "b122-script-abuse-detector",
        "source_id": TARGET_SCENARIO,
        "collector": "sentinel.beta12_script_abuse_controls.detect_control",
        "trust": "DERIVED",
    }
    detection = builder.ingest_observation(
        {
            "node_type": "DETECTION",
            "identity": {
                "scenario_id": TARGET_SCENARIO,
                "detection_evidence": detection_evidence,
            },
            "label": "B12-2 controlled PowerShell script-driven mutation burst",
            "observed_at": observed_at,
            "provenance": provenance,
            "evidence_ids": [detection_evidence, evidence["relation_evidence_id"]],
            "confidence": min(1.0, float(result["score"]) / 8.0),
            "attributes": {
                "scenario_id": TARGET_SCENARIO,
                "outcome": result["outcome"],
                "matched_signals": list(result["matched_signals"]),
                "correlation_keys": [f"b122:{detection_evidence}"],
            },
        }
    )
    file_node = source_graph.nodes_by_type("FILE")[0]
    builder.link(
        edge_type="SUPPORTED_BY",
        source=detection.node_id,
        target=file_node.node_id,
        observed_at=observed_at,
        provenance=provenance,
        evidence_ids=[detection_evidence, evidence["relation_evidence_id"]],
        confidence=1.0,
        reason="Controlled script-abuse detection is supported by the explicitly bound process/file relation and harmless mutation-count metadata.",
    )
    graph = builder.build(
        graph_id="b122-graph:" + _sha({"evidence": detection_evidence})[:20],
        incident_id="b122-incident:" + _sha({"scenario": TARGET_SCENARIO, "evidence": detection_evidence})[:20],
        created_at=observed_at,
        metadata={
            "milestone": "B12-2",
            "scenario_id": TARGET_SCENARIO,
            "harmless": True,
            "disposable_workspace": True,
            "content_exported": False,
        },
    )
    correlation = incident_correlation.IncidentCorrelator(max_time_delta=30.0).correlate(graph)
    return graph, correlation, detection_evidence


def summarize(data: object) -> dict[str, Any]:
    failures = validate_evidence(data)
    if failures:
        return {"passed": False, "failures": list(failures)}

    assert isinstance(data, dict)
    rows = {row["control_id"]: row for row in data["controls"]}
    results = {control_id: detect_control(row) for control_id, row in rows.items()}
    positive = results[CONTROL_IDS[0]]
    administrative = results[CONTROL_IDS[1]]
    benign = results[CONTROL_IDS[2]]

    graph, correlation, detection_evidence = _positive_graph(rows[CONTROL_IDS[0]], positive)
    graph_ok = security_graph.validate_graph(graph.to_dict()).passed
    correlation_ok = incident_correlation.validate_result(correlation, graph).passed
    binding_ok = (
        graph_ok
        and correlation_ok
        and len(graph.nodes_by_type("DETECTION")) == 1
        and len(graph.nodes_by_type("FILE")) == 1
        and len(correlation.incidents) == 1
        and any(edge.edge_type == "SUPPORTED_BY" for edge in graph.edges)
    )

    controls_ok = (
        positive["outcome"] == OUTCOME_DETECTED
        and administrative["outcome"] == OUTCOME_REVIEW
        and benign["outcome"] == OUTCOME_NO_MATCH
        and all(result["correlation_passed"] for result in results.values())
        and all(result["process_file_bound"] for result in results.values())
        and binding_ok
    )

    decisions = [dict(item) for item in COVERAGE_DECISIONS]
    decisions.append(
        {
            "scenario_id": TARGET_SCENARIO,
            "status": "VERIFIED" if controls_ok else "PARTIAL",
            "evidence_basis": (
                "CONTROLLED_LIVE_WINDOWS_POWERSHELL_SCRIPT_MUTATION_PATH"
                if controls_ok
                else "LIVE_CONTROL_ACCEPTANCE_INCOMPLETE"
            ),
            "limitation": "Harmless disposable-workspace script-driven file-mutation burst only; no command/script-content inspection and no broad PowerShell protection claim.",
        }
    )
    coverage = {
        key: sum(1 for item in decisions if item["status"] == key)
        for key in ("PARTIAL", "GAP", "VERIFIED")
    }

    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "passed": bool(controls_ok),
        "failures": [] if controls_ok else ["b122:live_controls_incomplete"],
        "target_scenario_id": TARGET_SCENARIO,
        "control_results": results,
        "detector_to_security_graph_bound": bool(binding_ok),
        "security_graph_to_incident_bound": bool(binding_ok),
        "detection_evidence_id": detection_evidence,
        "graph_digest": graph.digest(),
        "correlation_digest": correlation.digest(),
        "coverage_summary": coverage,
        "coverage_decisions": decisions,
        "verified_scenarios": [
            item["scenario_id"] for item in decisions if item["status"] == "VERIFIED"
        ],
        "new_verified_scenario_earned": bool(controls_ok),
        "script_content_exported": False,
        "command_line_exported": False,
        "raw_path_exported": False,
        "synthetic_fallback_used": False,
        "broad_powershell_protection_claimed": False,
        "authority_expanded": False,
        "network_required": False,
        "cloud_required": False,
        "boundaries": dict(BOUNDARIES),
    }


def self_check() -> dict[str, Any]:
    contract = {
        "schema": SCHEMA,
        "profile": PROFILE,
        "source": SOURCE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "target_scenario": TARGET_SCENARIO,
        "baseline_verified": list(BASELINE_VERIFIED),
        "control_ids": list(CONTROL_IDS),
        "min_mutations": MIN_MUTATIONS,
        "max_duration_seconds": MAX_DURATION_SECONDS,
        "boundaries": dict(BOUNDARIES),
    }
    return {
        "passed": True,
        "failures": [],
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "target_scenario_id": TARGET_SCENARIO,
        "baseline_verified_scenarios": list(BASELINE_VERIFIED),
        "contract_digest": _sha(contract),
        "live_windows_evidence_required": True,
        "positive_and_negative_controls_required": True,
        "script_content_exported": False,
        "command_line_exported": False,
        "raw_path_exported": False,
        "coverage_promoted_by_self_check": False,
        "authority_expanded": False,
        "network_required": False,
        "cloud_required": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--self-check", action="store_true")
    args = parser.parse_args()
    if args.evidence is None:
        result = self_check()
    else:
        try:
            data = json.loads(args.evidence.read_text(encoding="utf-8-sig"))
            result = summarize(data)
        except (OSError, UnicodeError, ValueError):
            result = {"passed": False, "failures": ["b122:evidence_unreadable_or_invalid_json"]}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())

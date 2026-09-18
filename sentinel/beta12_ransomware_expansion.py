from __future__ import annotations

"""B12-5 Ransomware Protection Expansion.

Consumes privacy-minimal live Windows file-activity evidence generated only in
disposable temporary directories. This milestone expands the already accepted
ransomware-like path by binding a real observing process to a representative
modified file and to the accepted ransomware detector result.

It does not execute malware, touch user files, export file contents or absolute
paths, require network/cloud access, or grant remediation/process-control
authority.
"""

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Final

from sentinel import incident_correlation, ransomware_detector, security_graph

SCHEMA: Final[str] = "bc-sentinel-beta12-ransomware-process-live-controls-v1"
PROFILE: Final[str] = "v0.12.0-beta.12-b125-ransomware-protection-expansion"
SOURCE: Final[str] = "WINDOWS_RANSOMWARE_PROCESS_LIVE_CONTROLS"
SOURCE_CHECKPOINT: Final[str] = "checkpoint/v012-beta12-b124-pass"
SOURCE_CHECKPOINT_COMMIT: Final[str] = "8e1cb119ef225efbf89471bddc645dc5416c8e01"
TARGET_SCENARIO: Final[str] = "B12-RANSOMWARE-PROCESS-001"

BASELINE_VERIFIED: Final[tuple[str, ...]] = (
    "B7-POWERSHELL-001",
    "B7-RANSOMWARE-001",
    "B12-SCRIPT-ABUSE-001",
    "B12-AUTOSTART-LINK-001",
    "B12-PROCESS-TREE-001",
)
CONTROL_IDS: Final[tuple[str, ...]] = (
    "positive-process-attributed-ransomware-like",
    "administrative-process-attributed-backup-like",
    "benign-process-attributed-save",
)

PROCESS_FIELDS: Final[set[str]] = {
    "pid",
    "image_sha256",
    "image_path_digest",
    "image_user_writable",
}
CONTROL_FIELDS: Final[set[str]] = {
    "control_id",
    "live_observation",
    "sandbox_scope",
    "observer_backend",
    "process",
    "write_event_count",
    "rename_event_count",
    "entropy_delta",
    "extension_changed",
    "canary_touched",
    "representative_file_sha256",
    "representative_path_digest",
    "known_backup_workflow",
    "user_initiated_bulk_operation",
    "duration_seconds",
    "cleanup_state",
}
BOUNDARIES: Final[dict[str, bool]] = {
    "local_only": True,
    "explicit_opt_in_required": True,
    "dedicated_temp_directory_only": True,
    "acceptance_harness_file_mutation": True,
    "user_file_access": False,
    "file_content_exported": False,
    "absolute_paths_exported": False,
    "personal_data_collected": False,
    "remote_access": False,
    "network_io": False,
    "real_malware_executed": False,
    "product_file_write_authority": False,
    "product_file_rename_authority": False,
    "product_file_delete_authority": False,
    "remediation_authority": False,
    "automatic_quarantine": False,
    "automatic_repair": False,
    "automatic_restore": False,
    "terminate_process_authority": False,
    "trust_allowlist_mutation": False,
    "privileged_system_mutation": False,
}

BASELINE_DECISIONS: Final[tuple[dict[str, str], ...]] = (
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
        "scenario_id": "B12-SCRIPT-ABUSE-001",
        "status": "VERIFIED",
        "evidence_basis": "ACCEPTED_B12_2_LIVE_WINDOWS_SCRIPT_MUTATION_PATH",
        "limitation": "Disposable-workspace PowerShell script-driven file-mutation burst only.",
    },
    {
        "scenario_id": "B12-AUTOSTART-LINK-001",
        "status": "VERIFIED",
        "evidence_basis": "ACCEPTED_B12_3_LIVE_WINDOWS_SHORTCUT_PATTERN",
        "limitation": "Disposable-workspace shortcut metadata only; actual persistence execution not claimed.",
    },
    {
        "scenario_id": "B12-PROCESS-TREE-001",
        "status": "VERIFIED",
        "evidence_basis": "ACCEPTED_B12_4_LIVE_WINDOWS_PROCESS_TREE",
        "limitation": "Bounded live ancestry pattern only; not broad process-tree protection.",
    },
    {
        "scenario_id": "B7-PERSISTENCE-001",
        "status": "PARTIAL",
        "evidence_basis": "NO_REAL_PERSISTENCE_SURFACE_MUTATION",
        "limitation": "Actual persistence execution remains unverified.",
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


def _valid_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _valid_float(value: object) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and 0.0 <= float(value) <= 1.0
    )


def validate_evidence(data: object) -> tuple[str, ...]:
    if not isinstance(data, dict):
        return ("b125:not_object",)

    failures: list[str] = []
    if set(data) != {"schema", "source", "controls", "boundaries"}:
        failures.append("b125:unexpected_or_missing_fields")
    if data.get("schema") != SCHEMA or data.get("source") != SOURCE:
        failures.append("b125:schema_or_source_invalid")
    if data.get("boundaries") != BOUNDARIES:
        failures.append("b125:boundary_invalid")

    controls = data.get("controls")
    if not isinstance(controls, list) or len(controls) != len(CONTROL_IDS):
        return tuple(dict.fromkeys(failures + ["b125:control_count_invalid"]))

    for index, (expected_id, row) in enumerate(zip(CONTROL_IDS, controls)):
        prefix = f"b125:control[{index}]"
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

        process = row.get("process")
        if not isinstance(process, dict) or set(process) != PROCESS_FIELDS:
            failures.append(f"{prefix}:process_fields_invalid")
        else:
            if not isinstance(process.get("pid"), int) or isinstance(process.get("pid"), bool) or process["pid"] <= 0:
                failures.append(f"{prefix}:process_pid_invalid")
            if not _valid_sha256(process.get("image_sha256")):
                failures.append(f"{prefix}:process_image_sha256_invalid")
            if not _valid_sha256(process.get("image_path_digest")):
                failures.append(f"{prefix}:process_image_path_digest_invalid")
            if not isinstance(process.get("image_user_writable"), bool):
                failures.append(f"{prefix}:process_image_user_writable_invalid")

        if not _valid_int(row.get("write_event_count")):
            failures.append(f"{prefix}:write_event_count_invalid")
        if not _valid_int(row.get("rename_event_count")):
            failures.append(f"{prefix}:rename_event_count_invalid")
        if not _valid_float(row.get("entropy_delta")):
            failures.append(f"{prefix}:entropy_delta_invalid")
        for field in (
            "extension_changed",
            "canary_touched",
            "known_backup_workflow",
            "user_initiated_bulk_operation",
        ):
            if not isinstance(row.get(field), bool):
                failures.append(f"{prefix}:{field}_invalid")
        if not _valid_sha256(row.get("representative_file_sha256")):
            failures.append(f"{prefix}:representative_file_sha256_invalid")
        if not _valid_sha256(row.get("representative_path_digest")):
            failures.append(f"{prefix}:representative_path_digest_invalid")
        duration = row.get("duration_seconds")
        if (
            not isinstance(duration, (int, float))
            or isinstance(duration, bool)
            or float(duration) < 0.0
            or float(duration) > 20.0
        ):
            failures.append(f"{prefix}:duration_invalid")
        if row.get("cleanup_state") != "CLEAN":
            failures.append(f"{prefix}:cleanup_not_confirmed")

    if all(isinstance(row, dict) for row in controls):
        positive, administrative, benign = controls
        if positive.get("known_backup_workflow") is not False or positive.get("user_initiated_bulk_operation") is not False:
            failures.append("b125:positive_suppressor_forbidden")
        if positive.get("extension_changed") is not True or positive.get("canary_touched") is not True:
            failures.append("b125:positive_required_signals_missing")
        if administrative.get("known_backup_workflow") is not True or administrative.get("user_initiated_bulk_operation") is not True:
            failures.append("b125:administrative_suppressors_required")
        if benign.get("extension_changed") is not False or benign.get("canary_touched") is not False:
            failures.append("b125:benign_unexpected_signal")

    return tuple(dict.fromkeys(failures))


def _observation(row: dict[str, Any]) -> tuple[ransomware_detector.FileActivityObservation, str]:
    evidence_material = {
        "control_id": row["control_id"],
        "process_pid": row["process"]["pid"],
        "process_image_sha256": row["process"]["image_sha256"],
        "write_event_count": row["write_event_count"],
        "rename_event_count": row["rename_event_count"],
        "entropy_delta": row["entropy_delta"],
        "extension_changed": row["extension_changed"],
        "canary_touched": row["canary_touched"],
        "representative_file_sha256": row["representative_file_sha256"],
    }
    evidence_id = "b125-live:" + _sha(evidence_material)[:24]
    observation = ransomware_detector.FileActivityObservation(
        event_id="b125:" + row["control_id"],
        observed_at=1.0,
        logical_path="b125://" + row["control_id"],
        evidence_id=evidence_id,
        provenance={
            "source": "b125-live-temp-file-activity",
            "source_id": evidence_id,
            "collector": "sentinel.beta12_ransomware_expansion",
            "trust": "DIRECT",
        },
        write_count_window=int(row["write_event_count"]),
        rename_count_window=int(row["rename_event_count"]),
        entropy_delta=float(row["entropy_delta"]),
        extension_changed=bool(row["extension_changed"]),
        canary_touched=bool(row["canary_touched"]),
        known_backup_workflow=bool(row["known_backup_workflow"]),
        user_initiated_bulk_operation=bool(row["user_initiated_bulk_operation"]),
        correlation_key="b125:" + row["control_id"],
    )
    return observation, evidence_id


def _positive_graph(
    row: dict[str, Any],
    observation: ransomware_detector.FileActivityObservation,
    result: ransomware_detector.DetectionResult,
    evidence_id: str,
) -> tuple[security_graph.SecurityGraph, incident_correlation.CorrelationResult]:
    direct = {
        "source": "b125-live-temp-file-activity",
        "source_id": evidence_id,
        "collector": "sentinel.beta12_ransomware_expansion",
        "trust": "DIRECT",
    }
    derived = {
        "source": "accepted-ransomware-detector",
        "source_id": TARGET_SCENARIO,
        "collector": "sentinel.ransomware_detector.detect",
        "trust": "DERIVED",
    }
    builder = security_graph.SecurityGraphBuilder()
    process = builder.ingest_observation(
        {
            "node_type": "PROCESS",
            "identity": {
                "pid": row["process"]["pid"],
                "image_sha256": row["process"]["image_sha256"],
            },
            "label": "Observed ransomware-control process",
            "observed_at": 1.0,
            "provenance": direct,
            "evidence_ids": [evidence_id],
            "confidence": 1.0,
            "attributes": {
                "pid": row["process"]["pid"],
                "image_sha256": row["process"]["image_sha256"],
                "image_path_digest": row["process"]["image_path_digest"],
                "image_user_writable": row["process"]["image_user_writable"],
                "correlation_keys": [observation.correlation_key],
            },
        }
    )
    file_node = builder.ingest_observation(
        {
            "node_type": "FILE",
            "identity": {
                "sha256": row["representative_file_sha256"],
                "path_digest": row["representative_path_digest"],
            },
            "label": "Representative modified file",
            "observed_at": 1.0,
            "provenance": direct,
            "evidence_ids": [evidence_id],
            "confidence": 1.0,
            "attributes": {
                "sha256": row["representative_file_sha256"],
                "path_digest": row["representative_path_digest"],
                "write_event_count": row["write_event_count"],
                "rename_event_count": row["rename_event_count"],
                "entropy_delta": row["entropy_delta"],
                "canary_touched": row["canary_touched"],
                "correlation_keys": [observation.correlation_key],
            },
        }
    )
    detection = builder.ingest_observation(
        {
            "node_type": "DETECTION",
            "identity": {"scenario": TARGET_SCENARIO, "evidence_id": evidence_id},
            "label": "B12-5 process-attributed ransomware-like detection",
            "observed_at": 1.0,
            "provenance": derived,
            "evidence_ids": [evidence_id],
            "confidence": min(1.0, result.score / 10.0),
            "attributes": {
                "outcome": result.outcome,
                "score": result.score,
                "matched_signals": list(result.matched_signals),
                "correlation_keys": [observation.correlation_key],
            },
        }
    )
    builder.link(
        edge_type="MODIFIED",
        source=process.node_id,
        target=file_node.node_id,
        observed_at=1.0,
        provenance=direct,
        evidence_ids=[evidence_id],
        confidence=1.0,
        reason="Live acceptance evidence attributes the representative temp-file mutation to the observed control process.",
    )
    builder.link(
        edge_type="TRIGGERED",
        source=file_node.node_id,
        target=detection.node_id,
        observed_at=1.0,
        provenance=derived,
        evidence_ids=[evidence_id],
        confidence=1.0,
        reason="Bounded live file-activity evidence contributed to the accepted ransomware-like detector result.",
    )
    graph = builder.build(
        graph_id="b125-ransomware:" + _sha({"evidence": evidence_id})[:20],
        incident_id="b125-ransomware:" + _sha({"scenario": TARGET_SCENARIO, "evidence": evidence_id})[:20],
        created_at=1.0,
        metadata={
            "milestone": "B12-5",
            "scenario_id": TARGET_SCENARIO,
            "real_malware": False,
            "user_files_touched": False,
            "process_attribution": True,
        },
    )
    correlation = incident_correlation.IncidentCorrelator(max_time_delta=30.0).correlate(graph)
    return graph, correlation


def summarize(data: object) -> dict[str, Any]:
    failures = validate_evidence(data)
    if failures:
        return {"passed": False, "failures": list(failures)}
    assert isinstance(data, dict)

    rows = {row["control_id"]: row for row in data["controls"]}
    observations: dict[str, ransomware_detector.FileActivityObservation] = {}
    evidence_ids: dict[str, str] = {}
    results: dict[str, ransomware_detector.DetectionResult] = {}
    for control_id, row in rows.items():
        observation, evidence_id = _observation(row)
        observations[control_id] = observation
        evidence_ids[control_id] = evidence_id
        results[control_id] = ransomware_detector.detect((observation,))

    positive = results[CONTROL_IDS[0]]
    administrative = results[CONTROL_IDS[1]]
    benign = results[CONTROL_IDS[2]]
    positive_observation = observations[CONTROL_IDS[0]]
    graph, correlation = _positive_graph(
        rows[CONTROL_IDS[0]],
        positive_observation,
        positive,
        evidence_ids[CONTROL_IDS[0]],
    )

    graph_ok = security_graph.validate_graph(graph.to_dict()).passed
    correlation_ok = incident_correlation.validate_result(correlation, graph).passed
    binding_ok = (
        graph_ok
        and correlation_ok
        and len(graph.nodes_by_type("PROCESS")) == 1
        and len(graph.nodes_by_type("FILE")) == 1
        and len(graph.nodes_by_type("DETECTION")) == 1
        and len(correlation.incidents) == 1
        and any(edge.edge_type == "MODIFIED" for edge in graph.edges)
        and any(edge.edge_type == "TRIGGERED" for edge in graph.edges)
    )

    thresholds_ok = (
        positive_observation.write_count_window >= ransomware_detector.MIN_BULK_WRITES
        and positive_observation.rename_count_window >= ransomware_detector.MIN_BULK_RENAMES
        and positive_observation.entropy_delta >= ransomware_detector.MIN_ENTROPY_DELTA
        and positive_observation.canary_touched
    )
    controls_ok = (
        positive.outcome == ransomware_detector.OUTCOME_DETECTED
        and administrative.outcome == ransomware_detector.OUTCOME_REVIEW
        and benign.outcome == ransomware_detector.OUTCOME_NO_MATCH
        and thresholds_ok
        and binding_ok
    )

    decisions = [dict(item) for item in BASELINE_DECISIONS]
    decisions.append(
        {
            "scenario_id": TARGET_SCENARIO,
            "status": "VERIFIED" if controls_ok else "PARTIAL",
            "evidence_basis": (
                "CONTROLLED_LIVE_PROCESS_ATTRIBUTED_RANSOMWARE_LIKE_PATH"
                if controls_ok
                else "LIVE_PROCESS_ATTRIBUTION_ACCEPTANCE_INCOMPLETE"
            ),
            "limitation": "Verified only for the harmless disposable-temp process-attributed rewrite/rename/entropy/canary pattern exercised by B12-5; no broad ransomware-family protection claim.",
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
        "failures": [] if controls_ok else ["b125:live_controls_incomplete"],
        "target_scenario_id": TARGET_SCENARIO,
        "detector_module": "sentinel.ransomware_detector.detect",
        "control_outcomes": {
            control_id: results[control_id].outcome for control_id in CONTROL_IDS
        },
        "positive_score": positive.score,
        "positive_matched_signals": list(positive.matched_signals),
        "live_thresholds_met": bool(thresholds_ok),
        "process_to_file_bound": bool(binding_ok),
        "detector_to_security_graph_bound": bool(binding_ok),
        "security_graph_to_incident_bound": bool(binding_ok),
        "graph_digest": graph.digest(),
        "correlation_digest": correlation.digest(),
        "coverage_summary": coverage,
        "coverage_decisions": decisions,
        "verified_scenarios": [
            item["scenario_id"] for item in decisions if item["status"] == "VERIFIED"
        ],
        "new_verified_scenario_earned": bool(controls_ok),
        "broad_ransomware_protection_claimed": False,
        "synthetic_fallback_used": False,
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
        "live_process_attribution_required": True,
        "positive_and_negative_controls_required": True,
        "user_file_access": False,
        "real_malware_executed": False,
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
            result = {"passed": False, "failures": ["b125:evidence_unreadable_or_invalid_json"]}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

"""B12-3 Persistence & Autostart Detection.

Consumes privacy-minimal metadata from a harmless live Windows shortcut-control
harness. Real .lnk artifacts are created and inspected only inside a disposable
temp workspace. Registry Run keys, the real Startup folder, Scheduled Tasks and
services are never modified.

The verified scenario is intentionally narrow: detecting an autostart-like
shortcut pattern from live Windows shortcut metadata with positive,
administrative and benign controls. Actual persistence execution is not claimed.
"""

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Final

from sentinel import incident_correlation, security_graph

SCHEMA: Final[str] = "bc-sentinel-beta12-autostart-shortcut-live-controls-v1"
PROFILE: Final[str] = "v0.12.0-beta.12-b123-persistence-autostart-detection"
SOURCE: Final[str] = "WINDOWS_AUTOSTART_SHORTCUT_LIVE_CONTROLS"
SOURCE_CHECKPOINT: Final[str] = "checkpoint/v012-beta12-b122-pass"
SOURCE_CHECKPOINT_COMMIT: Final[str] = "dedf78ae920b87f44636a0b9bd0c9708d2ae760b"
TARGET_SCENARIO: Final[str] = "B12-AUTOSTART-LINK-001"

BASELINE_VERIFIED: Final[tuple[str, ...]] = (
    "B7-POWERSHELL-001",
    "B7-RANSOMWARE-001",
    "B12-SCRIPT-ABUSE-001",
)
CONTROL_IDS: Final[tuple[str, ...]] = (
    "positive-autostart-like-shortcut",
    "administrative-autostart-like-shortcut",
    "benign-shortcut",
)
OUTCOME_DETECTED: Final[str] = "DETECTED"
OUTCOME_REVIEW: Final[str] = "REVIEW_REQUIRED"
OUTCOME_NO_MATCH: Final[str] = "NO_MATCH"

TARGET_KINDS: Final[set[str]] = {
    "SCRIPT_OR_BATCH",
    "SCRIPT_HOST",
    "SIGNED_APPLICATION",
    "OTHER",
}
SIGNER_STATES: Final[set[str]] = {
    "UNKNOWN",
    "UNSIGNED",
    "SIGNED_UNVERIFIED",
    "SIGNED_VERIFIED",
}
CONTROL_FIELDS: Final[set[str]] = {
    "control_id",
    "live_observation",
    "windows_shortcut_created",
    "windows_shortcut_resolved",
    "shortcut_sha256",
    "shortcut_path_digest",
    "target_sha256",
    "target_path_digest",
    "target_signer_state",
    "target_signer_subject_digest",
    "target_kind",
    "target_user_writable",
    "arguments_present",
    "known_admin_automation",
    "user_initiated_configuration",
    "startup_surface_mutated",
    "workspace_scope",
    "cleanup_state",
}
BOUNDARIES: Final[dict[str, bool]] = {
    "local_only": True,
    "explicit_opt_in_required": True,
    "harmless_exercise_only": True,
    "disposable_temp_workspace_only": True,
    "real_startup_folder_mutated": False,
    "registry_run_key_mutated": False,
    "scheduled_task_mutated": False,
    "service_mutated": False,
    "shell_extension_mutated": False,
    "raw_path_exported": False,
    "shortcut_arguments_exported": False,
    "username_collected": False,
    "credential_access": False,
    "network_io": False,
    "remote_access": False,
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
        "scenario_id": "B7-PERSISTENCE-001",
        "status": "PARTIAL",
        "evidence_basis": "NO_REAL_PERSISTENCE_SURFACE_MUTATION",
        "limitation": "Registry Run keys and the real Startup folder are not modified; actual persistence execution remains unverified.",
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
    return isinstance(value, str) and len(value) == 64 and all(
        ch in "0123456789abcdef" for ch in value.lower()
    )


def _valid_signer(state: object, subject_digest: object) -> bool:
    if state not in SIGNER_STATES:
        return False
    if state in {"SIGNED_UNVERIFIED", "SIGNED_VERIFIED"}:
        return _valid_sha256(subject_digest)
    return subject_digest is None


def validate_evidence(data: object) -> tuple[str, ...]:
    if not isinstance(data, dict):
        return ("b123:not_object",)
    failures: list[str] = []
    if set(data) != {"schema", "source", "controls", "boundaries"}:
        failures.append("b123:unexpected_or_missing_fields")
    if data.get("schema") != SCHEMA or data.get("source") != SOURCE:
        failures.append("b123:schema_or_source_invalid")
    if data.get("boundaries") != BOUNDARIES:
        failures.append("b123:boundary_invalid")

    controls = data.get("controls")
    if not isinstance(controls, list) or len(controls) != len(CONTROL_IDS):
        return tuple(dict.fromkeys(failures + ["b123:control_count_invalid"]))

    path_digests: list[str] = []
    for index, (expected_id, row) in enumerate(zip(CONTROL_IDS, controls)):
        prefix = f"b123:control[{index}]"
        if not isinstance(row, dict) or set(row) != CONTROL_FIELDS:
            failures.append(f"{prefix}:fields_invalid")
            continue
        if row.get("control_id") != expected_id:
            failures.append(f"{prefix}:identity_invalid")
        if row.get("live_observation") is not True:
            failures.append(f"{prefix}:live_observation_required")
        if row.get("windows_shortcut_created") is not True:
            failures.append(f"{prefix}:shortcut_creation_required")
        if row.get("windows_shortcut_resolved") is not True:
            failures.append(f"{prefix}:shortcut_resolution_required")

        for field in ("shortcut_sha256", "shortcut_path_digest", "target_sha256", "target_path_digest"):
            if not _valid_sha256(row.get(field)):
                failures.append(f"{prefix}:{field}_invalid")
        if not _valid_signer(row.get("target_signer_state"), row.get("target_signer_subject_digest")):
            failures.append(f"{prefix}:target_signer_invalid")
        if row.get("target_kind") not in TARGET_KINDS:
            failures.append(f"{prefix}:target_kind_invalid")
        for field in (
            "target_user_writable",
            "arguments_present",
            "known_admin_automation",
            "user_initiated_configuration",
            "startup_surface_mutated",
        ):
            if not isinstance(row.get(field), bool):
                failures.append(f"{prefix}:{field}_invalid")
        if row.get("startup_surface_mutated") is not False:
            failures.append(f"{prefix}:startup_surface_mutation_forbidden")
        if row.get("workspace_scope") != "DISPOSABLE_TEMP_ONLY":
            failures.append(f"{prefix}:workspace_scope_invalid")
        if row.get("cleanup_state") != "REMOVED":
            failures.append(f"{prefix}:cleanup_not_confirmed")
        if _valid_sha256(row.get("shortcut_path_digest")):
            path_digests.append(str(row["shortcut_path_digest"]).lower())

    if len(path_digests) != len(set(path_digests)):
        failures.append("b123:shortcut_paths_not_distinct")

    if all(isinstance(row, dict) for row in controls):
        positive, administrative, benign = controls
        if positive.get("known_admin_automation") is not False or positive.get("user_initiated_configuration") is not False:
            failures.append("b123:positive_suppressor_forbidden")
        if administrative.get("known_admin_automation") is not True or administrative.get("user_initiated_configuration") is not True:
            failures.append("b123:administrative_suppressors_required")
        if benign.get("known_admin_automation") is not False or benign.get("user_initiated_configuration") is not False:
            failures.append("b123:benign_suppressor_forbidden")
    return tuple(dict.fromkeys(failures))


def detect_control(row: dict[str, Any]) -> dict[str, Any]:
    signals = ["WINDOWS_SHORTCUT_AUTOSTART_PATTERN"]
    score = 2
    if row["target_kind"] in {"SCRIPT_OR_BATCH", "SCRIPT_HOST"}:
        signals.append("SCRIPT_CAPABLE_TARGET")
        score += 3
    if row["target_signer_state"] in {"UNSIGNED", "UNKNOWN"}:
        signals.append("UNTRUSTED_OR_UNSIGNED_TARGET")
        score += 2
    if row["target_user_writable"]:
        signals.append("USER_WRITABLE_TARGET")
        score += 2
    if row["arguments_present"]:
        signals.append("SHORTCUT_ARGUMENTS_PRESENT")
        score += 2

    suppressor = bool(row["known_admin_automation"] or row["user_initiated_configuration"])
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
    }


def _build_graph(
    row: dict[str, Any],
    result: dict[str, Any],
) -> tuple[security_graph.SecurityGraph, incident_correlation.CorrelationResult, str]:
    evidence_id = "b123-shortcut:" + _sha(
        {
            "shortcut_sha256": row["shortcut_sha256"],
            "target_sha256": row["target_sha256"],
            "target_kind": row["target_kind"],
            "arguments_present": row["arguments_present"],
            "control_id": row["control_id"],
        }
    )[:24]
    observed_at = 1.0
    direct = {
        "source": "windows-shell-shortcut-live-metadata",
        "source_id": evidence_id,
        "collector": "sentinel.beta12_autostart_detection",
        "trust": "DIRECT",
    }
    derived = {
        "source": "b123-autostart-shortcut-detector",
        "source_id": TARGET_SCENARIO,
        "collector": "sentinel.beta12_autostart_detection.detect_control",
        "trust": "DERIVED",
    }

    builder = security_graph.SecurityGraphBuilder()
    shortcut = builder.ingest_observation(
        {
            "node_type": "FILE",
            "identity": {
                "shortcut_sha256": row["shortcut_sha256"],
                "shortcut_path_digest": row["shortcut_path_digest"],
            },
            "label": "Windows shortcut artifact",
            "observed_at": observed_at,
            "provenance": direct,
            "evidence_ids": [evidence_id],
            "confidence": 1.0,
            "attributes": {
                "sha256": row["shortcut_sha256"],
                "path_digest": row["shortcut_path_digest"],
                "extension": ".lnk",
                "correlation_keys": [evidence_id],
            },
        }
    )
    target = builder.ingest_observation(
        {
            "node_type": "FILE",
            "identity": {
                "target_sha256": row["target_sha256"],
                "target_path_digest": row["target_path_digest"],
            },
            "label": "Resolved shortcut target",
            "observed_at": observed_at,
            "provenance": direct,
            "evidence_ids": [evidence_id],
            "confidence": 1.0,
            "attributes": {
                "sha256": row["target_sha256"],
                "path_digest": row["target_path_digest"],
                "signer_state": row["target_signer_state"],
                "signer_subject_digest": row["target_signer_subject_digest"],
                "target_kind": row["target_kind"],
                "target_user_writable": row["target_user_writable"],
                "arguments_present": row["arguments_present"],
                "correlation_keys": [evidence_id],
            },
        }
    )
    persistence = builder.ingest_observation(
        {
            "node_type": "PERSISTENCE",
            "identity": {
                "scenario": TARGET_SCENARIO,
                "shortcut_sha256": row["shortcut_sha256"],
            },
            "label": "Autostart-like shortcut pattern",
            "observed_at": observed_at,
            "provenance": derived,
            "evidence_ids": [evidence_id],
            "confidence": min(1.0, float(result["score"]) / 11.0),
            "attributes": {
                "scenario_id": TARGET_SCENARIO,
                "actual_startup_surface_mutated": False,
                "correlation_keys": [evidence_id],
            },
        }
    )
    detection = builder.ingest_observation(
        {
            "node_type": "DETECTION",
            "identity": {"scenario": TARGET_SCENARIO, "evidence_id": evidence_id},
            "label": "B12-3 autostart shortcut detection",
            "observed_at": observed_at,
            "provenance": derived,
            "evidence_ids": [evidence_id],
            "confidence": min(1.0, float(result["score"]) / 11.0),
            "attributes": {
                "outcome": result["outcome"],
                "score": result["score"],
                "matched_signals": list(result["matched_signals"]),
                "correlation_keys": [evidence_id],
            },
        }
    )
    builder.link(
        edge_type="PERSISTED_VIA",
        source=target.node_id,
        target=persistence.node_id,
        observed_at=observed_at,
        provenance=derived,
        evidence_ids=[evidence_id],
        confidence=1.0,
        reason="Resolved target is represented as an autostart-like shortcut pattern from the live disposable Windows shortcut control.",
    )
    builder.link(
        edge_type="OBSERVED_WITH",
        source=shortcut.node_id,
        target=persistence.node_id,
        observed_at=observed_at,
        provenance=direct,
        evidence_ids=[evidence_id],
        confidence=1.0,
        reason="The live Windows shortcut artifact supplies bounded shortcut metadata for this pattern.",
    )
    builder.link(
        edge_type="SUPPORTED_BY",
        source=detection.node_id,
        target=persistence.node_id,
        observed_at=observed_at,
        provenance=derived,
        evidence_ids=[evidence_id],
        confidence=1.0,
        reason="Autostart shortcut detection is supported by the bounded persistence-pattern node and live shortcut metadata.",
    )
    graph = builder.build(
        graph_id="b123-graph:" + _sha({"evidence": evidence_id})[:20],
        incident_id="b123-incident:" + _sha({"scenario": TARGET_SCENARIO, "evidence": evidence_id})[:20],
        created_at=observed_at,
        metadata={
            "milestone": "B12-3",
            "scenario_id": TARGET_SCENARIO,
            "live_windows_shortcut": True,
            "actual_persistence_surface_mutated": False,
            "actual_persistence_execution_verified": False,
        },
    )
    correlation = incident_correlation.IncidentCorrelator(max_time_delta=30.0).correlate(graph)
    return graph, correlation, evidence_id


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

    graph, correlation, evidence_id = _build_graph(rows[CONTROL_IDS[0]], positive)
    graph_ok = security_graph.validate_graph(graph.to_dict()).passed
    correlation_ok = incident_correlation.validate_result(correlation, graph).passed
    binding_ok = (
        graph_ok
        and correlation_ok
        and len(graph.nodes_by_type("PERSISTENCE")) == 1
        and len(graph.nodes_by_type("DETECTION")) == 1
        and len(correlation.incidents) == 1
        and any(edge.edge_type == "PERSISTED_VIA" for edge in graph.edges)
        and any(edge.edge_type == "SUPPORTED_BY" for edge in graph.edges)
    )
    controls_ok = (
        positive["outcome"] == OUTCOME_DETECTED
        and administrative["outcome"] == OUTCOME_REVIEW
        and benign["outcome"] == OUTCOME_NO_MATCH
        and binding_ok
    )

    decisions = [dict(item) for item in BASELINE_DECISIONS]
    decisions.append(
        {
            "scenario_id": TARGET_SCENARIO,
            "status": "VERIFIED" if controls_ok else "PARTIAL",
            "evidence_basis": "CONTROLLED_LIVE_WINDOWS_SHORTCUT_PATTERN" if controls_ok else "LIVE_SHORTCUT_CONTROL_INCOMPLETE",
            "limitation": "Verified only for live Windows shortcut metadata created and inspected in a disposable temp workspace; actual Startup-folder or Run-key persistence execution is not claimed.",
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
        "failures": [] if controls_ok else ["b123:live_controls_incomplete"],
        "target_scenario_id": TARGET_SCENARIO,
        "control_results": results,
        "detector_to_security_graph_bound": bool(binding_ok),
        "security_graph_to_incident_bound": bool(binding_ok),
        "evidence_id": evidence_id,
        "graph_digest": graph.digest(),
        "correlation_digest": correlation.digest(),
        "coverage_summary": coverage,
        "coverage_decisions": decisions,
        "verified_scenarios": [
            item["scenario_id"] for item in decisions if item["status"] == "VERIFIED"
        ],
        "new_verified_scenario_earned": bool(controls_ok),
        "actual_persistence_surface_mutated": False,
        "actual_persistence_execution_verified": False,
        "legacy_persistence_scenario_promoted": False,
        "raw_path_exported": False,
        "shortcut_arguments_exported": False,
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
        "target_kinds": sorted(TARGET_KINDS),
        "signer_states": sorted(SIGNER_STATES),
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
        "live_windows_shortcut_evidence_required": True,
        "positive_and_negative_controls_required": True,
        "real_startup_folder_mutated": False,
        "registry_run_key_mutated": False,
        "actual_persistence_execution_verified_by_self_check": False,
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
            result = {"passed": False, "failures": ["b123:evidence_unreadable_or_invalid_json"]}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())

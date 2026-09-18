from __future__ import annotations

"""B12-4 Suspicious Process Tree Intelligence.

Consumes bounded live Windows process-tree observations and produces a
deterministic, explainable score. Positive, administrative and benign controls
are required. The milestone is local/read-only from Sentinel's perspective:
it does not terminate processes, quarantine files, collect command lines,
change trust, require network access, or claim broad process-tree protection.
"""

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Final

from sentinel import incident_correlation, security_graph

SCHEMA: Final[str] = "bc-sentinel-beta12-process-tree-live-controls-v1"
PROFILE: Final[str] = "v0.12.0-beta.12-b124-suspicious-process-tree-intelligence"
SOURCE: Final[str] = "WINDOWS_PROCESS_TREE_LIVE_CONTROLS"
SOURCE_CHECKPOINT: Final[str] = "checkpoint/v012-beta12-b123-pass"
SOURCE_CHECKPOINT_COMMIT: Final[str] = "90776f9b0e3f1a9c034b79a5886b30df0db41e5c"
TARGET_SCENARIO: Final[str] = "B12-PROCESS-TREE-001"

BASELINE_VERIFIED: Final[tuple[str, ...]] = (
    "B7-POWERSHELL-001",
    "B7-RANSOMWARE-001",
    "B12-SCRIPT-ABUSE-001",
    "B12-AUTOSTART-LINK-001",
)
CONTROL_IDS: Final[tuple[str, ...]] = (
    "positive-user-writable-script-shell-chain",
    "administrative-script-shell-chain",
    "benign-application-child",
)
PROCESS_ROLES: Final[set[str]] = {"ROOT", "INTERMEDIATE", "LEAF"}
IMAGE_KINDS: Final[set[str]] = {"SCRIPT_HOST", "SHELL", "SIGNED_APPLICATION", "OTHER"}
SIGNER_STATES: Final[set[str]] = {
    "UNKNOWN",
    "UNSIGNED",
    "SIGNED_UNVERIFIED",
    "SIGNED_VERIFIED",
}
OUTCOME_DETECTED: Final[str] = "DETECTED"
OUTCOME_REVIEW: Final[str] = "REVIEW_REQUIRED"
OUTCOME_NO_MATCH: Final[str] = "NO_MATCH"
PROCESS_FIELDS: Final[set[str]] = {
    "role",
    "pid",
    "parent_pid",
    "image_sha256",
    "image_path_digest",
    "signer_state",
    "signer_subject_digest",
    "image_kind",
    "image_user_writable",
}
CONTROL_FIELDS: Final[set[str]] = {
    "control_id",
    "live_observation",
    "processes",
    "known_admin_automation",
    "user_initiated_operation",
    "cleanup_state",
}
BOUNDARIES: Final[dict[str, bool]] = {
    "local_only": True,
    "explicit_opt_in_required": True,
    "harmless_exercise_only": True,
    "disposable_temp_workspace_only": True,
    "command_line_exported": False,
    "raw_path_exported": False,
    "username_collected": False,
    "event_payload_collected": False,
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
        "scenario_id": "B12-AUTOSTART-LINK-001",
        "status": "VERIFIED",
        "evidence_basis": "ACCEPTED_B12_3_LIVE_WINDOWS_SHORTCUT_PATTERN",
        "limitation": "Disposable-workspace shortcut metadata only; actual persistence execution not claimed.",
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


def _valid_pid(value: object, *, allow_none: bool = False) -> bool:
    if value is None:
        return allow_none
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _valid_signer(state: object, subject_digest: object) -> bool:
    if state not in SIGNER_STATES:
        return False
    if state in {"SIGNED_UNVERIFIED", "SIGNED_VERIFIED"}:
        return _valid_sha256(subject_digest)
    return subject_digest is None


def _validate_process(row: object, index: int) -> list[str]:
    prefix = f"b124:process[{index}]"
    if not isinstance(row, dict) or set(row) != PROCESS_FIELDS:
        return [f"{prefix}:fields_invalid"]
    failures: list[str] = []
    if row.get("role") not in PROCESS_ROLES:
        failures.append(f"{prefix}:role_invalid")
    if not _valid_pid(row.get("pid")):
        failures.append(f"{prefix}:pid_invalid")
    if not _valid_pid(row.get("parent_pid"), allow_none=True):
        failures.append(f"{prefix}:parent_pid_invalid")
    if not _valid_sha256(row.get("image_sha256")):
        failures.append(f"{prefix}:image_sha256_invalid")
    if not _valid_sha256(row.get("image_path_digest")):
        failures.append(f"{prefix}:image_path_digest_invalid")
    if not _valid_signer(row.get("signer_state"), row.get("signer_subject_digest")):
        failures.append(f"{prefix}:signer_invalid")
    if row.get("image_kind") not in IMAGE_KINDS:
        failures.append(f"{prefix}:image_kind_invalid")
    if not isinstance(row.get("image_user_writable"), bool):
        failures.append(f"{prefix}:image_user_writable_invalid")
    return failures


def _validate_chain(processes: list[dict[str, Any]], control_index: int) -> list[str]:
    prefix = f"b124:control[{control_index}]"
    failures: list[str] = []
    pids = [row["pid"] for row in processes]
    if len(pids) != len(set(pids)):
        failures.append(f"{prefix}:duplicate_pid")

    roots = [row for row in processes if row["role"] == "ROOT"]
    if len(roots) != 1:
        failures.append(f"{prefix}:root_count_invalid")
        return failures
    if roots[0]["parent_pid"] is not None:
        failures.append(f"{prefix}:root_parent_must_be_unknown")

    by_pid = {row["pid"]: row for row in processes}
    for row in processes:
        if row["role"] == "ROOT":
            continue
        parent_pid = row["parent_pid"]
        if parent_pid not in by_pid:
            failures.append(f"{prefix}:parent_missing")
        elif parent_pid == row["pid"]:
            failures.append(f"{prefix}:self_parent_forbidden")

    # Reject cycles even if every referenced parent exists.
    for row in processes:
        seen: set[int] = set()
        current = row
        while current["parent_pid"] is not None:
            pid = current["pid"]
            if pid in seen:
                failures.append(f"{prefix}:cycle_detected")
                break
            seen.add(pid)
            parent = by_pid.get(current["parent_pid"])
            if parent is None:
                break
            current = parent
    return failures


def validate_evidence(data: object) -> tuple[str, ...]:
    if not isinstance(data, dict):
        return ("b124:not_object",)

    failures: list[str] = []
    if set(data) != {"schema", "source", "controls", "boundaries"}:
        failures.append("b124:unexpected_or_missing_fields")
    if data.get("schema") != SCHEMA or data.get("source") != SOURCE:
        failures.append("b124:schema_or_source_invalid")
    if data.get("boundaries") != BOUNDARIES:
        failures.append("b124:boundary_invalid")

    controls = data.get("controls")
    if not isinstance(controls, list) or len(controls) != len(CONTROL_IDS):
        return tuple(dict.fromkeys(failures + ["b124:control_count_invalid"]))

    for index, (expected_id, control) in enumerate(zip(CONTROL_IDS, controls)):
        prefix = f"b124:control[{index}]"
        if not isinstance(control, dict) or set(control) != CONTROL_FIELDS:
            failures.append(f"{prefix}:fields_invalid")
            continue
        if control.get("control_id") != expected_id:
            failures.append(f"{prefix}:identity_invalid")
        if control.get("live_observation") is not True:
            failures.append(f"{prefix}:live_observation_required")
        for field in ("known_admin_automation", "user_initiated_operation"):
            if not isinstance(control.get(field), bool):
                failures.append(f"{prefix}:{field}_invalid")
        if control.get("cleanup_state") != "EXITED":
            failures.append(f"{prefix}:cleanup_not_confirmed")

        processes = control.get("processes")
        if not isinstance(processes, list) or not (2 <= len(processes) <= 4):
            failures.append(f"{prefix}:process_count_invalid")
            continue
        for pindex, row in enumerate(processes):
            failures.extend(_validate_process(row, pindex))
        if all(isinstance(row, dict) and set(row) == PROCESS_FIELDS for row in processes):
            failures.extend(_validate_chain(processes, index))

    if all(isinstance(row, dict) for row in controls):
        positive, administrative, benign = controls
        if positive.get("known_admin_automation") is not False or positive.get("user_initiated_operation") is not False:
            failures.append("b124:positive_suppressor_forbidden")
        if administrative.get("known_admin_automation") is not True or administrative.get("user_initiated_operation") is not True:
            failures.append("b124:administrative_suppressors_required")
        if benign.get("known_admin_automation") is not False or benign.get("user_initiated_operation") is not False:
            failures.append("b124:benign_suppressor_forbidden")

    return tuple(dict.fromkeys(failures))


def _depth(processes: list[dict[str, Any]]) -> int:
    by_pid = {row["pid"]: row for row in processes}
    best = 1
    for row in processes:
        depth = 1
        current = row
        seen: set[int] = set()
        while current["parent_pid"] is not None and current["parent_pid"] in by_pid:
            if current["pid"] in seen:
                break
            seen.add(current["pid"])
            current = by_pid[current["parent_pid"]]
            depth += 1
        best = max(best, depth)
    return best


def _has_script_host_to_shell(processes: list[dict[str, Any]]) -> bool:
    by_pid = {row["pid"]: row for row in processes}
    for row in processes:
        if row["image_kind"] != "SHELL" or row["parent_pid"] is None:
            continue
        parent = by_pid.get(row["parent_pid"])
        if parent and parent["image_kind"] == "SCRIPT_HOST":
            return True
    return False


def detect_control(control: dict[str, Any]) -> dict[str, Any]:
    processes = control["processes"]
    depth = _depth(processes)
    user_writable = sum(1 for row in processes if row["image_user_writable"])
    script_host_to_shell = _has_script_host_to_shell(processes)

    score = 0
    signals: list[str] = []
    if depth >= 3:
        score += 2
        signals.append("MULTI_GENERATION_PROCESS_CHAIN")
    if script_host_to_shell:
        score += 3
        signals.append("SCRIPT_HOST_TO_SHELL_DESCENDANT")
    if user_writable >= 1:
        score += 2
        signals.append("USER_WRITABLE_EXECUTABLE_IMAGE")
    if user_writable >= 2:
        score += 1
        signals.append("MULTIPLE_USER_WRITABLE_EXECUTABLES")

    suppressor = bool(control["known_admin_automation"] or control["user_initiated_operation"])
    if score >= 5 and suppressor:
        outcome = OUTCOME_REVIEW
    elif score >= 5:
        outcome = OUTCOME_DETECTED
    else:
        outcome = OUTCOME_NO_MATCH

    return {
        "outcome": outcome,
        "score": score,
        "matched_signals": signals,
        "suppressor": suppressor,
        "chain_depth": depth,
        "user_writable_image_count": user_writable,
    }


def _build_graph(
    control: dict[str, Any],
    result: dict[str, Any],
) -> tuple[security_graph.SecurityGraph, incident_correlation.CorrelationResult, str]:
    evidence_id = "b124-tree:" + _sha(
        {
            "control_id": control["control_id"],
            "pids": [row["pid"] for row in control["processes"]],
            "hashes": [row["image_sha256"] for row in control["processes"]],
        }
    )[:24]
    observed_at = 1.0
    direct = {
        "source": "windows-live-process-tree",
        "source_id": evidence_id,
        "collector": "sentinel.beta12_process_tree_intelligence",
        "trust": "DIRECT",
    }
    derived = {
        "source": "b124-process-tree-detector",
        "source_id": TARGET_SCENARIO,
        "collector": "sentinel.beta12_process_tree_intelligence.detect_control",
        "trust": "DERIVED",
    }

    builder = security_graph.SecurityGraphBuilder()
    node_by_pid: dict[int, security_graph.GraphNode] = {}
    for row in control["processes"]:
        node = builder.ingest_observation(
            {
                "node_type": "PROCESS",
                "identity": {"pid": row["pid"], "image_sha256": row["image_sha256"]},
                "label": f"Observed {row['role'].lower()} process",
                "observed_at": observed_at,
                "provenance": direct,
                "evidence_ids": [evidence_id],
                "confidence": 1.0,
                "attributes": {
                    "pid": row["pid"],
                    "parent_pid": row["parent_pid"],
                    "image_sha256": row["image_sha256"],
                    "image_path_digest": row["image_path_digest"],
                    "signer_state": row["signer_state"],
                    "signer_subject_digest": row["signer_subject_digest"],
                    "image_kind": row["image_kind"],
                    "image_user_writable": row["image_user_writable"],
                    "correlation_keys": [evidence_id],
                },
            }
        )
        node_by_pid[row["pid"]] = node

    for row in control["processes"]:
        if row["parent_pid"] is None:
            continue
        parent = node_by_pid[row["parent_pid"]]
        child = node_by_pid[row["pid"]]
        builder.link(
            edge_type="SPAWNED",
            source=parent.node_id,
            target=child.node_id,
            observed_at=observed_at,
            provenance=direct,
            evidence_ids=[evidence_id],
            confidence=1.0,
            reason="Live Windows process creation evidence binds this explicit parent/child relationship.",
        )

    detection = builder.ingest_observation(
        {
            "node_type": "DETECTION",
            "identity": {"scenario": TARGET_SCENARIO, "evidence_id": evidence_id},
            "label": "B12-4 suspicious process-tree detection",
            "observed_at": observed_at,
            "provenance": derived,
            "evidence_ids": [evidence_id],
            "confidence": min(1.0, float(result["score"]) / 8.0),
            "attributes": {
                "outcome": result["outcome"],
                "score": result["score"],
                "matched_signals": list(result["matched_signals"]),
                "correlation_keys": [evidence_id],
            },
        }
    )
    leaf = max(control["processes"], key=lambda row: _depth([candidate for candidate in control["processes"] if True]))
    # Bind detection to a deterministic non-root process; explicit scoring remains in detection attributes.
    candidate_nodes = [
        node_by_pid[row["pid"]]
        for row in control["processes"]
        if row["role"] != "ROOT"
    ]
    target_node = sorted(candidate_nodes, key=lambda node: node.node_id)[-1]
    builder.link(
        edge_type="SUPPORTED_BY",
        source=detection.node_id,
        target=target_node.node_id,
        observed_at=observed_at,
        provenance=derived,
        evidence_ids=[evidence_id],
        confidence=1.0,
        reason="Process-tree detection is supported by the bounded live ancestry metadata and explainable scoring signals.",
    )

    graph = builder.build(
        graph_id="b124-graph:" + _sha({"evidence": evidence_id})[:20],
        incident_id="b124-incident:" + _sha({"scenario": TARGET_SCENARIO, "evidence": evidence_id})[:20],
        created_at=observed_at,
        metadata={
            "milestone": "B12-4",
            "scenario_id": TARGET_SCENARIO,
            "live_windows_process_tree": True,
            "command_line_exported": False,
            "automatic_response": False,
        },
    )
    correlation = incident_correlation.IncidentCorrelator(max_time_delta=30.0).correlate(graph)
    return graph, correlation, evidence_id


def summarize(data: object) -> dict[str, Any]:
    failures = validate_evidence(data)
    if failures:
        return {"passed": False, "failures": list(failures)}
    assert isinstance(data, dict)

    controls = {row["control_id"]: row for row in data["controls"]}
    results = {control_id: detect_control(row) for control_id, row in controls.items()}
    positive = results[CONTROL_IDS[0]]
    administrative = results[CONTROL_IDS[1]]
    benign = results[CONTROL_IDS[2]]

    graph, correlation, evidence_id = _build_graph(controls[CONTROL_IDS[0]], positive)
    graph_ok = security_graph.validate_graph(graph.to_dict()).passed
    correlation_ok = incident_correlation.validate_result(correlation, graph).passed
    binding_ok = (
        graph_ok
        and correlation_ok
        and len(graph.nodes_by_type("PROCESS")) == 3
        and len(graph.nodes_by_type("DETECTION")) == 1
        and len(correlation.incidents) == 1
        and len([edge for edge in graph.edges if edge.edge_type == "SPAWNED"]) == 2
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
            "evidence_basis": (
                "CONTROLLED_LIVE_WINDOWS_PROCESS_TREE"
                if controls_ok
                else "LIVE_PROCESS_TREE_CONTROL_INCOMPLETE"
            ),
            "limitation": "Verified only for the bounded live Windows ancestry pattern exercised by B12-4; no broad process-tree or malware-family protection claim.",
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
        "failures": [] if controls_ok else ["b124:live_controls_incomplete"],
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
        "command_line_exported": False,
        "raw_path_exported": False,
        "broad_process_tree_protection_claimed": False,
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
        "process_roles": sorted(PROCESS_ROLES),
        "image_kinds": sorted(IMAGE_KINDS),
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
        "live_windows_process_tree_required": True,
        "positive_and_negative_controls_required": True,
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
            result = {"passed": False, "failures": ["b124:evidence_unreadable_or_invalid_json"]}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())

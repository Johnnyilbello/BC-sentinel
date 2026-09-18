from __future__ import annotations

"""B12-5 Ransomware Protection Expansion.

Reuses the already accepted B9 harmless live-temp ransomware controls and adds
privacy-minimal attribution for the exact harness process. B12-5 does not add a
second mutation harness. It binds process -> accepted live evidence -> accepted
ransomware detector -> incident while preserving the existing safety boundary.
"""

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Final

from sentinel import beta9_ransomware_controls as b93
from sentinel import incident_correlation, ransomware_detector, security_graph

SCHEMA: Final[str] = "bc-sentinel-beta12-ransomware-process-attribution-v1"
PROFILE: Final[str] = "v0.12.0-beta.12-b125-ransomware-protection-expansion"
SOURCE: Final[str] = "B9_ACCEPTED_LIVE_CONTROLS_WITH_PROCESS_ATTRIBUTION"
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
PROCESS_FIELDS: Final[set[str]] = {"pid", "image_sha256", "image_path_digest"}
TOP_FIELDS: Final[set[str]] = {"schema", "source", "b9_evidence", "process", "boundaries"}
BOUNDARIES: Final[dict[str, bool]] = {
    "local_only": True,
    "explicit_opt_in_required": True,
    "reuses_accepted_b9_live_harness": True,
    "new_file_mutation_harness_added": False,
    "user_file_access": False,
    "file_content_exported": False,
    "absolute_paths_exported": False,
    "command_line_exported": False,
    "personal_data_collected": False,
    "network_io": False,
    "remote_access": False,
    "real_malware_executed": False,
    "remediation_authority": False,
    "automatic_quarantine": False,
    "automatic_repair": False,
    "automatic_restore": False,
    "terminate_process_authority": False,
    "trust_allowlist_mutation": False,
    "privileged_system_mutation": False,
}

BASELINE_DECISIONS: Final[tuple[dict[str, str], ...]] = (
    {"scenario_id":"B7-POWERSHELL-001","status":"VERIFIED","evidence_basis":"ACCEPTED_B10_METADATA_LIFECYCLE_BURST_CONTROL","limitation":"Metadata-only lifecycle-burst verification."},
    {"scenario_id":"B7-RANSOMWARE-001","status":"VERIFIED","evidence_basis":"ACCEPTED_B9_CONTROLLED_LOCAL_RANSOMWARE_LIKE_PATH","limitation":"Controlled local scenario only; not broad ransomware-family coverage."},
    {"scenario_id":"B12-SCRIPT-ABUSE-001","status":"VERIFIED","evidence_basis":"ACCEPTED_B12_2_LIVE_WINDOWS_SCRIPT_MUTATION_PATH","limitation":"Disposable-workspace script-driven mutation burst only."},
    {"scenario_id":"B12-AUTOSTART-LINK-001","status":"VERIFIED","evidence_basis":"ACCEPTED_B12_3_LIVE_WINDOWS_SHORTCUT_PATTERN","limitation":"Disposable-workspace shortcut metadata only."},
    {"scenario_id":"B12-PROCESS-TREE-001","status":"VERIFIED","evidence_basis":"ACCEPTED_B12_4_LIVE_WINDOWS_PROCESS_TREE","limitation":"Bounded live ancestry pattern only."},
    {"scenario_id":"B7-PERSISTENCE-001","status":"PARTIAL","evidence_basis":"NO_REAL_PERSISTENCE_SURFACE_MUTATION","limitation":"Actual persistence execution remains unverified."},
    {"scenario_id":"B7-DEFENSE-EVASION-001","status":"PARTIAL","evidence_basis":"NO_ACCEPTED_SAFE_LIVE_POSITIVE_CONTROL","limitation":"No security-control impairment is performed."},
    {"scenario_id":"B7-C2-DNS-001","status":"PARTIAL","evidence_basis":"NO_ACCEPTED_NETWORK_CONTROL","limitation":"Core acceptance remains network-free."},
    {"scenario_id":"B7-CREDENTIAL-001","status":"PARTIAL","evidence_basis":"NO_ACCEPTED_SENSITIVE_ACCESS_CONTROL","limitation":"Credential access remains prohibited."},
)


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _valid_sha256(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(
        ch in "0123456789abcdef" for ch in value.lower()
    )


def validate_evidence(data: object) -> tuple[str, ...]:
    if not isinstance(data, dict):
        return ("b125:not_object",)
    failures: list[str] = []
    if set(data) != TOP_FIELDS:
        failures.append("b125:unexpected_or_missing_fields")
    if data.get("schema") != SCHEMA or data.get("source") != SOURCE:
        failures.append("b125:schema_or_source_invalid")
    if data.get("boundaries") != BOUNDARIES:
        failures.append("b125:boundary_invalid")

    process = data.get("process")
    if not isinstance(process, dict) or set(process) != PROCESS_FIELDS:
        failures.append("b125:process_fields_invalid")
    else:
        pid = process.get("pid")
        if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
            failures.append("b125:process_pid_invalid")
        if not _valid_sha256(process.get("image_sha256")):
            failures.append("b125:process_image_sha256_invalid")
        if not _valid_sha256(process.get("image_path_digest")):
            failures.append("b125:process_image_path_digest_invalid")

    failures.extend(f"b125:b9:{item}" for item in b93.validate_evidence(data.get("b9_evidence")))
    return tuple(dict.fromkeys(failures))


def _positive_observation(row: dict[str, Any]) -> tuple[ransomware_detector.FileActivityObservation, str]:
    material = {
        "control_id": row["control_id"],
        "write_event_count": row["write_event_count"],
        "rename_event_count": row["rename_event_count"],
        "entropy_delta": row["entropy_delta"],
        "extension_changed": row["extension_changed"],
        "canary_touched": row["canary_touched"],
        "started_at_utc": row["started_at_utc"],
        "completed_at_utc": row["completed_at_utc"],
    }
    evidence_id = "b125-live:" + _sha(material)[:24]
    return (
        ransomware_detector.FileActivityObservation(
            event_id="b125:" + row["control_id"],
            observed_at=1.0,
            logical_path="b125://" + row["control_id"],
            evidence_id=evidence_id,
            provenance={
                "source": "accepted-b9-live-temp-file-activity",
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
        ),
        evidence_id,
    )


def _build_graph(
    process_row: dict[str, Any],
    observation: ransomware_detector.FileActivityObservation,
    result: ransomware_detector.DetectionResult,
    evidence_id: str,
) -> tuple[security_graph.SecurityGraph, incident_correlation.CorrelationResult]:
    direct = {
        "source": "b125-live-process-attribution",
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
    process = builder.ingest_observation({
        "node_type": "PROCESS",
        "identity": {"pid": process_row["pid"], "image_sha256": process_row["image_sha256"]},
        "label": "Observed accepted B9 live-control process",
        "observed_at": 1.0,
        "provenance": direct,
        "evidence_ids": [evidence_id],
        "confidence": 1.0,
        "attributes": {
            "pid": process_row["pid"],
            "image_sha256": process_row["image_sha256"],
            "image_path_digest": process_row["image_path_digest"],
            "correlation_keys": [observation.correlation_key],
        },
    })
    evidence = builder.ingest_observation({
        "node_type": "EVIDENCE",
        "identity": {"evidence_id": evidence_id},
        "label": "Accepted B9 live ransomware-like aggregate",
        "observed_at": 1.0,
        "provenance": direct,
        "evidence_ids": [evidence_id],
        "confidence": 1.0,
        "attributes": {
            "write_event_count": observation.write_count_window,
            "rename_event_count": observation.rename_count_window,
            "entropy_delta": observation.entropy_delta,
            "extension_changed": observation.extension_changed,
            "canary_touched": observation.canary_touched,
            "correlation_keys": [observation.correlation_key],
        },
    })
    detection = builder.ingest_observation({
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
    })
    builder.link(
        edge_type="OBSERVED_WITH",
        source=process.node_id,
        target=evidence.node_id,
        observed_at=1.0,
        provenance=direct,
        evidence_ids=[evidence_id],
        confidence=1.0,
        reason="The exact acceptance-harness process is bound to the live B9 file-activity evidence produced by that run.",
    )
    builder.link(
        edge_type="SUPPORTED_BY",
        source=detection.node_id,
        target=evidence.node_id,
        observed_at=1.0,
        provenance=derived,
        evidence_ids=[evidence_id],
        confidence=1.0,
        reason="The process-attributed ransomware-like detector result is supported by the accepted live B9 evidence.",
    )
    graph = builder.build(
        graph_id="b125-ransomware:" + _sha({"evidence": evidence_id})[:20],
        incident_id="b125-ransomware:" + _sha({"scenario": TARGET_SCENARIO, "evidence": evidence_id})[:20],
        created_at=1.0,
        metadata={
            "milestone": "B12-5",
            "scenario_id": TARGET_SCENARIO,
            "reused_accepted_b9_live_harness": True,
            "new_file_mutation_harness_added": False,
            "real_malware": False,
        },
    )
    return graph, incident_correlation.IncidentCorrelator(max_time_delta=30.0).correlate(graph)


def summarize(data: object) -> dict[str, Any]:
    failures = validate_evidence(data)
    if failures:
        return {"passed": False, "failures": list(failures)}
    assert isinstance(data, dict)

    b9_report = b93.summarize(data["b9_evidence"])
    observation, evidence_id = _positive_observation(data["b9_evidence"]["controls"][0])
    detector_result = ransomware_detector.detect((observation,))
    graph, correlation = _build_graph(data["process"], observation, detector_result, evidence_id)

    binding_ok = (
        security_graph.validate_graph(graph.to_dict()).passed
        and incident_correlation.validate_result(correlation, graph).passed
        and len(graph.nodes_by_type("PROCESS")) == 1
        and len(graph.nodes_by_type("EVIDENCE")) == 1
        and len(graph.nodes_by_type("DETECTION")) == 1
        and len(correlation.incidents) == 1
        and any(edge.edge_type == "OBSERVED_WITH" for edge in graph.edges)
        and any(edge.edge_type == "SUPPORTED_BY" for edge in graph.edges)
    )
    controls_ok = (
        b9_report.get("passed") is True
        and b9_report.get("control_outcomes") == {
            "positive-ransomware-like": "DETECTED",
            "administrative-backup-like": "REVIEW_REQUIRED",
            "benign-save": "NO_MATCH",
        }
        and detector_result.outcome == ransomware_detector.OUTCOME_DETECTED
        and binding_ok
    )

    decisions = [dict(item) for item in BASELINE_DECISIONS]
    decisions.append({
        "scenario_id": TARGET_SCENARIO,
        "status": "VERIFIED" if controls_ok else "PARTIAL",
        "evidence_basis": (
            "ACCEPTED_B9_LIVE_CONTROLS_PLUS_EXACT_PROCESS_ATTRIBUTION"
            if controls_ok
            else "PROCESS_ATTRIBUTION_ACCEPTANCE_INCOMPLETE"
        ),
        "limitation": "Verified only for process attribution around the already accepted harmless B9 live ransomware-like control; no broad ransomware-family protection claim.",
    })
    coverage = {
        key: sum(1 for item in decisions if item["status"] == key)
        for key in ("PARTIAL", "GAP", "VERIFIED")
    }
    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "passed": bool(controls_ok),
        "failures": [] if controls_ok else ["b125:controls_or_binding_incomplete"],
        "target_scenario_id": TARGET_SCENARIO,
        "reused_b9_live_harness": True,
        "new_file_mutation_harness_added": False,
        "b9_control_outcomes": b9_report.get("control_outcomes"),
        "positive_score": detector_result.score,
        "positive_matched_signals": list(detector_result.matched_signals),
        "process_attribution_bound": bool(binding_ok),
        "detector_to_security_graph_bound": bool(binding_ok),
        "security_graph_to_incident_bound": bool(binding_ok),
        "graph_digest": graph.digest(),
        "correlation_digest": correlation.digest(),
        "coverage_summary": coverage,
        "coverage_decisions": decisions,
        "verified_scenarios": [item["scenario_id"] for item in decisions if item["status"] == "VERIFIED"],
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
        "reuses_accepted_b9_live_harness": True,
        "new_file_mutation_harness_added": False,
        "process_attribution_required": True,
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
            result = summarize(json.loads(args.evidence.read_text(encoding="utf-8-sig")))
        except (OSError, UnicodeError, ValueError):
            result = {"passed": False, "failures": ["b125:evidence_unreadable_or_invalid_json"]}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())

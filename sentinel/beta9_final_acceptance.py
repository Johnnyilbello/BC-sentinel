"""B9-4: final Beta9 Windows acceptance composition and freeze contract.

This module performs no Windows mutation and launches no processes. The acceptance
script supplies fresh local evidence from B9-0 through B9-3; this module validates
and composes those results, enforces privacy/authority boundaries, checks the
canonical coverage decision, and records bounded resource cost.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import time
import tracemalloc
from pathlib import Path
from typing import Any

from sentinel import (
    beta9_event_metadata,
    beta9_event_to_incident,
    beta9_ransomware_controls,
    beta9_telemetry_foundation,
)

SCHEMA = "bc-sentinel-beta9-final-acceptance-v1"
PROFILE = "v0.11.0-beta.9-b94-final-acceptance"
SOURCE_CHECKPOINT = "checkpoint/v011-beta9-b93-pass"
SOURCE_CHECKPOINT_COMMIT = "50bbe099ba146201864b8969c91149497df913fa"
EXPECTED_COVERAGE = {"PARTIAL": 5, "GAP": 0, "VERIFIED": 1}
MAX_LIVE_PIPELINE_SECONDS = 90.0
MAX_COMPOSITION_SECONDS = 20.0
MAX_COMPOSITION_PEAK_BYTES = 128 * 1024 * 1024


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _read_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _system_available(inventory: object) -> bool:
    if not isinstance(inventory, dict):
        return False
    rows = inventory.get("channels")
    if not isinstance(rows, list):
        return False
    for row in rows:
        if isinstance(row, dict) and row.get("channel") == "System":
            return row.get("state") == "AVAILABLE" and row.get("enabled") is True
    return False


def _only_ransomware_verified(decisions: object) -> bool:
    if not isinstance(decisions, list) or len(decisions) != 6:
        return False
    verified = [row.get("scenario_id") for row in decisions if isinstance(row, dict) and row.get("status") == "VERIFIED"]
    partial = [row for row in decisions if isinstance(row, dict) and row.get("status") == "PARTIAL"]
    return verified == ["B7-RANSOMWARE-001"] and len(partial) == 5


def _boundary_snapshot(
    b90: dict[str, Any],
    b91: dict[str, Any],
    b92: dict[str, Any],
    b93: dict[str, Any],
) -> dict[str, Any]:
    return {
        "local_only": (
            b91.get("boundaries", {}).get("local_only") is True
            and b92.get("boundaries", {}).get("local_only") is True
            and b93.get("boundaries", {}).get("local_only") is True
        ),
        "explicit_opt_in_required": (
            b91.get("boundaries", {}).get("explicit_opt_in_required") is True
            and b92.get("boundaries", {}).get("explicit_opt_in_required") is True
            and b93.get("boundaries", {}).get("explicit_opt_in_required") is True
        ),
        "event_payload_read": bool(
            b90.get("boundaries", {}).get("event_payload_read")
            or b91.get("boundaries", {}).get("event_payload_read")
            or b92.get("boundaries", {}).get("event_payload_read")
        ),
        "event_message_read": bool(
            b91.get("boundaries", {}).get("event_message_read")
            or b92.get("boundaries", {}).get("event_message_read")
        ),
        "event_properties_read": bool(b92.get("boundaries", {}).get("event_properties_read")),
        "personal_data_collected": bool(
            b90.get("boundaries", {}).get("personal_data_collected")
            or b91.get("boundaries", {}).get("personal_data_collected")
            or b92.get("boundaries", {}).get("personal_data_collected")
            or b93.get("boundaries", {}).get("personal_data_collected")
        ),
        "remote_access": bool(
            b91.get("boundaries", {}).get("remote_access")
            or b92.get("boundaries", {}).get("remote_access")
            or b93.get("boundaries", {}).get("remote_access")
        ),
        "logging_configuration_mutation": bool(
            b90.get("boundaries", {}).get("channel_configuration_mutation")
            or b91.get("boundaries", {}).get("logging_configuration_mutation")
            or b92.get("boundaries", {}).get("logging_configuration_mutation")
        ),
        "audit_policy_mutation": bool(b92.get("boundaries", {}).get("audit_policy_mutation")),
        "privileged_system_mutation": bool(b93.get("boundaries", {}).get("privileged_system_mutation")),
        "remediation_authority": bool(
            b90.get("boundaries", {}).get("remediation_authority")
            or b91.get("boundaries", {}).get("remediation_authority")
            or b92.get("boundaries", {}).get("remediation_authority")
            or b93.get("boundaries", {}).get("remediation_authority")
        ),
        "automatic_quarantine": bool(b93.get("boundaries", {}).get("automatic_quarantine")),
        "product_file_write_authority": bool(b93.get("boundaries", {}).get("product_file_write_authority")),
        "product_file_rename_authority": bool(b93.get("boundaries", {}).get("product_file_rename_authority")),
        "product_file_delete_authority": bool(b93.get("boundaries", {}).get("product_file_delete_authority")),
        "user_file_access": bool(b93.get("boundaries", {}).get("user_file_access")),
        "file_content_collected": bool(b93.get("boundaries", {}).get("file_content_collected")),
        "absolute_paths_exported": bool(b93.get("boundaries", {}).get("absolute_paths_exported")),
        "real_malware_executed": bool(b93.get("boundaries", {}).get("real_malware_executed")),
    }


def _core_snapshot(
    inventory: object,
    metadata: object,
    exercise: object,
    controls: object,
) -> tuple[dict[str, Any], list[str]]:
    failures: list[str] = []
    b90 = beta9_telemetry_foundation.summarize(inventory)
    b91 = beta9_event_metadata.summarize(metadata)
    b92 = beta9_event_to_incident.summarize(exercise)
    b93 = beta9_ransomware_controls.summarize(controls)

    if b90.get("passed") is not True or not _system_available(inventory):
        failures.append("final:b90_inventory_invalid")
    if b91.get("passed") is not True or b91.get("event_readability_tested") is not True or int(b91.get("readable_profile_count") or 0) < 1:
        failures.append("final:b91_metadata_readability_invalid")
    if (
        b92.get("passed") is not True
        or b92.get("live_event_bound") is not True
        or b92.get("event_to_acceptance_detector_bound") is not True
        or b92.get("detector_to_security_graph_bound") is not True
        or b92.get("security_graph_to_incident_bound") is not True
        or b92.get("threat_detector_verification_performed") is not False
        or b92.get("threat_classification_performed") is not False
    ):
        failures.append("final:b92_event_incident_invalid")
    if (
        b93.get("passed") is not True
        or b93.get("controlled_threat_detector_verification_performed") is not True
        or b93.get("synthetic_fallback_used") is not False
        or b93.get("broad_ransomware_protection_claimed") is not False
        or b93.get("coverage_summary") != EXPECTED_COVERAGE
        or not _only_ransomware_verified(b93.get("coverage_decisions"))
    ):
        failures.append("final:b93_coverage_decision_invalid")

    if b93.get("control_outcomes") != {
        "positive-ransomware-like": "DETECTED",
        "administrative-backup-like": "REVIEW_REQUIRED",
        "benign-save": "NO_MATCH",
    }:
        failures.append("final:b93_false_positive_controls_invalid")

    boundaries = _boundary_snapshot(b90, b91, b92, b93)
    required_true = ("local_only", "explicit_opt_in_required")
    required_false = tuple(key for key in boundaries if key not in required_true)
    if any(boundaries.get(key) is not True for key in required_true):
        failures.append("final:local_opt_in_boundary_invalid")
    if any(boundaries.get(key) is not False for key in required_false):
        failures.append("final:authority_or_privacy_boundary_expanded")

    core = {
        "telemetry_foundation": {
            "passed": b90.get("passed"),
            "system_available": _system_available(inventory),
            "event_readability_tested": b90.get("event_readability_tested"),
            "detector_verification_performed": b90.get("detector_verification_performed"),
        },
        "bounded_metadata": {
            "passed": b91.get("passed"),
            "event_readability_tested": b91.get("event_readability_tested"),
            "readable_profile_count": b91.get("readable_profile_count"),
            "detector_verification_performed": b91.get("detector_verification_performed"),
            "threat_classification_performed": b91.get("threat_classification_performed"),
        },
        "event_to_incident": {
            "passed": b92.get("passed"),
            "live_event_bound": b92.get("live_event_bound"),
            "event_to_acceptance_detector_bound": b92.get("event_to_acceptance_detector_bound"),
            "detector_to_security_graph_bound": b92.get("detector_to_security_graph_bound"),
            "security_graph_to_incident_bound": b92.get("security_graph_to_incident_bound"),
            "threat_detector_verification_performed": b92.get("threat_detector_verification_performed"),
        },
        "ransomware_controls": {
            "passed": b93.get("passed"),
            "control_outcomes": b93.get("control_outcomes"),
            "live_thresholds_met": b93.get("live_thresholds_met"),
            "controlled_threat_detector_verification_performed": b93.get("controlled_threat_detector_verification_performed"),
            "synthetic_fallback_used": b93.get("synthetic_fallback_used"),
            "broad_ransomware_protection_claimed": b93.get("broad_ransomware_protection_claimed"),
        },
        "coverage_summary": dict(EXPECTED_COVERAGE),
        "verified_scenario_id": "B7-RANSOMWARE-001",
        "partial_scenario_count": 5,
        "boundaries": boundaries,
    }
    return core, failures


def summarize(
    inventory: object,
    metadata: object,
    exercise: object,
    controls: object,
    live_elapsed_seconds: float,
) -> dict[str, Any]:
    if isinstance(live_elapsed_seconds, bool) or not isinstance(live_elapsed_seconds, (int, float)) or live_elapsed_seconds < 0:
        return {"passed": False, "failures": ["final:live_elapsed_invalid"]}

    tracemalloc.start()
    started = time.perf_counter()
    try:
        core, failures = _core_snapshot(inventory, metadata, exercise, controls)
        composition_elapsed = time.perf_counter() - started
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    if live_elapsed_seconds > MAX_LIVE_PIPELINE_SECONDS:
        failures.append("final:live_pipeline_budget_exceeded")
    if composition_elapsed > MAX_COMPOSITION_SECONDS:
        failures.append("final:composition_time_budget_exceeded")
    if peak > MAX_COMPOSITION_PEAK_BYTES:
        failures.append("final:composition_memory_budget_exceeded")

    second_core, second_failures = _core_snapshot(inventory, metadata, exercise, controls)
    deterministic = not second_failures and second_core == core
    if not deterministic:
        failures.append("final:core_not_deterministic")

    report = {
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "passed": not failures,
        "failures": failures,
        "core_digest": _sha(core),
        "deterministic_core": deterministic,
        "coverage_summary": dict(EXPECTED_COVERAGE),
        "verified_scenario_id": "B7-RANSOMWARE-001",
        "broad_protection_claimed": False,
        "resource_cost": {
            "live_pipeline_elapsed_seconds": float(live_elapsed_seconds),
            "max_live_pipeline_seconds": MAX_LIVE_PIPELINE_SECONDS,
            "composition_elapsed_seconds": float(composition_elapsed),
            "max_composition_seconds": MAX_COMPOSITION_SECONDS,
            "composition_peak_memory_bytes": int(peak),
            "max_composition_peak_memory_bytes": MAX_COMPOSITION_PEAK_BYTES,
        },
        "boundaries": core.get("boundaries", {}),
    }
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--exercise", type=Path, required=True)
    parser.add_argument("--controls", type=Path, required=True)
    parser.add_argument("--live-elapsed-seconds", type=float, required=True)
    args = parser.parse_args()
    try:
        result = summarize(
            _read_json(args.inventory),
            _read_json(args.metadata),
            _read_json(args.exercise),
            _read_json(args.controls),
            args.live_elapsed_seconds,
        )
    except (OSError, UnicodeError, ValueError):
        result = {"passed": False, "failures": ["final:input_unreadable_or_invalid_json"]}
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if result.get("passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())

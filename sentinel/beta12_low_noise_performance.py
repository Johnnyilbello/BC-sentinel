from __future__ import annotations

"""B12-7 Low-Noise Tuning & Performance.

Benchmarks accepted Beta12 detector/classifier paths with deterministic benign,
administrative and unknown-local-reputation controls. This milestone does not
promote coverage or change detector thresholds. It adds a fail-closed
performance/noise gate around the already accepted B12 behavior.
"""

import argparse
import json
import math
import time
from typing import Any, Callable, Final

import psutil

from sentinel import beta12_autostart_detection as b123
from sentinel import beta12_local_reputation as b126
from sentinel import beta12_process_file_correlation as b121
from sentinel import beta12_process_tree_intelligence as b124
from sentinel import beta12_script_abuse_controls as b122
from sentinel import ransomware_detector

SCHEMA: Final[str] = "bc-sentinel-beta12-low-noise-performance-v1"
PROFILE: Final[str] = "v0.12.0-beta.12-b127-low-noise-tuning-performance"
SOURCE_CHECKPOINT: Final[str] = "checkpoint/v012-beta12-b126-pass"
SOURCE_CHECKPOINT_COMMIT: Final[str] = "b1f55ea32564d72cae6056308f90f8b41137dc94"
CURRENT_COVERAGE: Final[dict[str, int]] = {"PARTIAL": 4, "GAP": 0, "VERIFIED": 7}

MIN_REPEATS: Final[int] = 10
MAX_REPEATS: Final[int] = 40
BUDGETS: Final[dict[str, float | int]] = {
    "p95_wall_ms": 250.0,
    "p95_cpu_ms": 250.0,
    "max_rss_delta_mib": 32.0,
    "max_false_positive_detections": 0,
    "max_outcome_drift": 0,
    "max_user_interruptions": 0,
}

EXPECTED_OUTCOMES: Final[dict[str, str]] = {
    "script_benign": "NO_MATCH",
    "script_admin": "REVIEW_REQUIRED",
    "autostart_benign": "NO_MATCH",
    "autostart_admin": "REVIEW_REQUIRED",
    "process_tree_benign": "NO_MATCH",
    "process_tree_admin": "REVIEW_REQUIRED",
    "ransomware_benign": "NO_MATCH",
    "ransomware_admin": "REVIEW_REQUIRED",
    "reputation_known_good": "TRUSTED_LOCAL",
    "reputation_signed_unknown": "UNKNOWN_SIGNED",
    "reputation_unsigned_unknown": "UNKNOWN_UNSIGNED",
}

BOUNDARIES: Final[dict[str, bool]] = {
    "local_only": True,
    "network_io": False,
    "cloud_required": False,
    "file_execution": False,
    "raw_path_exported": False,
    "command_line_exported": False,
    "file_content_exported": False,
    "trust_allowlist_mutation": False,
    "automatic_quarantine": False,
    "automatic_repair": False,
    "automatic_restore": False,
    "terminate_process_authority": False,
    "privileged_system_mutation": False,
}


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        raise ValueError("b127:percentile_requires_values")
    if not 0.0 < percentile <= 1.0:
        raise ValueError("b127:percentile_out_of_range")
    ordered = sorted(float(value) for value in values)
    index = max(0, math.ceil(percentile * len(ordered)) - 1)
    return ordered[index]


def _cpu_seconds(process: psutil.Process) -> float:
    cpu = process.cpu_times()
    return float(cpu.user) + float(cpu.system)


def _script_control(control_id: str, mutations: int, *, admin: bool) -> dict[str, Any]:
    observation = b121.sample_observation(with_parent=True)
    observation["observation_id"] = f"b127-{control_id}"
    observation["process"]["pid"] += mutations + (100 if admin else 0)
    observation["parent_process"]["pid"] += mutations + (100 if admin else 0)
    observation["process"]["parent_pid"] = observation["parent_process"]["pid"]
    observation["file"]["target_path_digest"] = ("%064x" % (11000 + mutations + (100 if admin else 0)))
    observation["file"]["sha256"] = ("%064x" % (12000 + mutations + (100 if admin else 0)))
    observation["evidence"] = {
        "process_evidence_id": f"ev-b127-{control_id}-process",
        "file_evidence_id": f"ev-b127-{control_id}-file",
        "relation_evidence_id": f"ev-b127-{control_id}-relation",
    }
    return {
        "control_id": control_id,
        "live_observation": True,
        "script_execution_observed": True,
        "script_sha256": "9" * 64,
        "script_path_digest": "8" * 64,
        "file_mutation_count": mutations,
        "duration_seconds": 2.0,
        "known_admin_automation": admin,
        "user_initiated_bulk_operation": admin,
        "cleanup_state": "EXITED",
        "correlation_observation": observation,
    }


def _autostart_control(*, admin: bool, benign: bool) -> dict[str, Any]:
    if benign:
        kind, signer, writable, arguments = "SIGNED_APPLICATION", "SIGNED_VERIFIED", False, False
    else:
        kind, signer, writable, arguments = "SCRIPT_HOST", "SIGNED_VERIFIED", False, True
    return {
        "target_kind": kind,
        "target_signer_state": signer,
        "target_user_writable": writable,
        "arguments_present": arguments,
        "known_admin_automation": admin,
        "user_initiated_configuration": admin,
    }


def _process(role: str, pid: int, parent_pid: int | None, kind: str, *, writable: bool) -> dict[str, Any]:
    return {
        "role": role,
        "pid": pid,
        "parent_pid": parent_pid,
        "image_sha256": ("%064x" % (30000 + pid)),
        "image_path_digest": ("%064x" % (40000 + pid)),
        "signer_state": "SIGNED_VERIFIED",
        "signer_subject_digest": "a" * 64,
        "image_kind": kind,
        "image_user_writable": writable,
    }


def _process_tree_control(*, admin: bool, benign: bool) -> dict[str, Any]:
    if benign:
        processes = [
            _process("ROOT", 5100, None, "SCRIPT_HOST", writable=False),
            _process("LEAF", 5101, 5100, "SHELL", writable=False),
        ]
    else:
        processes = [
            _process("ROOT", 5200, None, "SCRIPT_HOST", writable=False),
            _process("INTERMEDIATE", 5201, 5200, "SCRIPT_HOST", writable=False),
            _process("LEAF", 5202, 5201, "SHELL", writable=False),
        ]
    return {
        "processes": processes,
        "known_admin_automation": admin,
        "user_initiated_operation": admin,
    }


def _ransomware_observation(*, admin: bool, benign: bool) -> ransomware_detector.FileActivityObservation:
    return ransomware_detector.FileActivityObservation(
        event_id="b127-ransomware-benign" if benign else "b127-ransomware-admin",
        observed_at=1.0,
        logical_path="b127://ransomware-control",
        evidence_id="b127-ransomware-evidence-benign" if benign else "b127-ransomware-evidence-admin",
        provenance={
            "source": "b127-performance-fixture",
            "source_id": "b127-ransomware",
            "collector": "sentinel.beta12_low_noise_performance",
            "trust": "DIRECT",
        },
        write_count_window=2 if benign else 24,
        rename_count_window=0 if benign else 18,
        entropy_delta=0.0 if benign else 0.91,
        extension_changed=not benign,
        canary_touched=False,
        known_backup_workflow=admin,
        user_initiated_bulk_operation=admin,
        correlation_key="b127-ransomware",
    )


def _reputation_fixture() -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    allowlist = [{
        "entry_id": "b127-known-good",
        "sha256": "1" * 64,
        "signer_subject_digest": "2" * 64,
        "source": "EXPLICIT_EPHEMERAL_ACCEPTANCE_ALLOWLIST",
    }]
    rows = {
        "reputation_known_good": {
            "sha256": "1" * 64,
            "signer_state": "SIGNED_VERIFIED",
            "signer_subject_digest": "2" * 64,
        },
        "reputation_signed_unknown": {
            "sha256": "3" * 64,
            "signer_state": "SIGNED_VERIFIED",
            "signer_subject_digest": "4" * 64,
        },
        "reputation_unsigned_unknown": {
            "sha256": "5" * 64,
            "signer_state": "UNSIGNED",
            "signer_subject_digest": None,
        },
    }
    return allowlist, rows


def run_low_noise_cases() -> dict[str, str]:
    outcomes: dict[str, str] = {}

    outcomes["script_benign"] = b122.detect_control(
        _script_control("benign-powershell-script", 1, admin=False)
    )["outcome"]
    outcomes["script_admin"] = b122.detect_control(
        _script_control("administrative-script-mutation-burst", 6, admin=True)
    )["outcome"]

    outcomes["autostart_benign"] = b123.detect_control(
        _autostart_control(admin=False, benign=True)
    )["outcome"]
    outcomes["autostart_admin"] = b123.detect_control(
        _autostart_control(admin=True, benign=False)
    )["outcome"]

    outcomes["process_tree_benign"] = b124.detect_control(
        _process_tree_control(admin=False, benign=True)
    )["outcome"]
    outcomes["process_tree_admin"] = b124.detect_control(
        _process_tree_control(admin=True, benign=False)
    )["outcome"]

    outcomes["ransomware_benign"] = ransomware_detector.detect(
        (_ransomware_observation(admin=False, benign=True),)
    ).outcome
    outcomes["ransomware_admin"] = ransomware_detector.detect(
        (_ransomware_observation(admin=True, benign=False),)
    ).outcome

    allowlist, reputation_rows = _reputation_fixture()
    for key, row in reputation_rows.items():
        outcomes[key] = b126.classify(row, allowlist)["outcome"]

    return outcomes


def _noise_counts(outcomes: dict[str, str]) -> tuple[int, int]:
    false_positive = sum(
        1
        for key in ("script_benign", "autostart_benign", "process_tree_benign", "ransomware_benign")
        if outcomes.get(key) == "DETECTED"
    )
    drift = sum(1 for key, expected in EXPECTED_OUTCOMES.items() if outcomes.get(key) != expected)
    return false_positive, drift


def summarize_measurements(measurements: list[dict[str, Any]]) -> dict[str, Any]:
    failures: list[str] = []
    if len(measurements) < MIN_REPEATS:
        failures.append("measurement:insufficient_repeats")

    wall_values: list[float] = []
    cpu_values: list[float] = []
    rss_values: list[float] = []
    false_positive_values: list[int] = []
    drift_values: list[int] = []
    interruption_values: list[int] = []

    for index, row in enumerate(measurements):
        prefix = f"measurement[{index}]"
        if not isinstance(row, dict):
            failures.append(f"{prefix}:not_object")
            continue
        try:
            wall = float(row["wall_ms"])
            cpu = float(row["cpu_ms"])
            rss_delta = int(row["rss_delta_bytes"])
            false_positive = int(row["false_positive_detections"])
            drift = int(row["outcome_drift"])
            interruptions = int(row["user_interruptions"])
        except (KeyError, TypeError, ValueError):
            failures.append(f"{prefix}:metrics_invalid")
            continue
        if min(wall, cpu, rss_delta, false_positive, drift, interruptions) < 0:
            failures.append(f"{prefix}:metrics_negative")
            continue

        outcomes = row.get("outcomes")
        if outcomes != EXPECTED_OUTCOMES:
            failures.append(f"{prefix}:outcomes_invalid")

        wall_values.append(wall)
        cpu_values.append(cpu)
        rss_values.append(rss_delta / (1024.0 * 1024.0))
        false_positive_values.append(false_positive)
        drift_values.append(drift)
        interruption_values.append(interruptions)

    if wall_values:
        p95_wall = _percentile(wall_values, 0.95)
        p95_cpu = _percentile(cpu_values, 0.95)
        max_rss = max(rss_values)
        max_false_positive = max(false_positive_values)
        max_drift = max(drift_values)
        max_interruptions = max(interruption_values)
    else:
        p95_wall = p95_cpu = max_rss = float("inf")
        max_false_positive = max_drift = max_interruptions = 2**31 - 1

    if p95_wall > float(BUDGETS["p95_wall_ms"]):
        failures.append("budget:p95_wall_exceeded")
    if p95_cpu > float(BUDGETS["p95_cpu_ms"]):
        failures.append("budget:p95_cpu_exceeded")
    if max_rss > float(BUDGETS["max_rss_delta_mib"]):
        failures.append("budget:rss_delta_exceeded")
    if max_false_positive > int(BUDGETS["max_false_positive_detections"]):
        failures.append("budget:false_positive_exceeded")
    if max_drift > int(BUDGETS["max_outcome_drift"]):
        failures.append("budget:outcome_drift_exceeded")
    if max_interruptions > int(BUDGETS["max_user_interruptions"]):
        failures.append("budget:user_interruptions_exceeded")

    unique = list(dict.fromkeys(failures))
    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "passed": not unique,
        "failures": unique,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "coverage_summary": dict(CURRENT_COVERAGE),
        "coverage_promoted": False,
        "verified_count_preserved": CURRENT_COVERAGE["VERIFIED"],
        "operational_metrics": {
            "repeat_count": len(measurements),
            "p95_wall_ms": round(p95_wall, 6) if math.isfinite(p95_wall) else None,
            "p95_cpu_ms": round(p95_cpu, 6) if math.isfinite(p95_cpu) else None,
            "max_rss_delta_mib": round(max_rss, 6) if math.isfinite(max_rss) else None,
            "max_false_positive_detections": max_false_positive if max_false_positive < 2**31 - 1 else None,
            "max_outcome_drift": max_drift if max_drift < 2**31 - 1 else None,
            "max_user_interruptions": max_interruptions if max_interruptions < 2**31 - 1 else None,
        },
        "budgets": dict(BUDGETS),
        "expected_outcomes": dict(EXPECTED_OUTCOMES),
        "false_positive_gate_passed": "budget:false_positive_exceeded" not in unique,
        "outcome_stability_gate_passed": "budget:outcome_drift_exceeded" not in unique and not any(
            item.endswith(":outcomes_invalid") for item in unique
        ),
        "performance_gate_passed": not any(
            item in {"budget:p95_wall_exceeded", "budget:p95_cpu_exceeded", "budget:rss_delta_exceeded"}
            for item in unique
        ),
        "user_interruption_gate_passed": "budget:user_interruptions_exceeded" not in unique,
        "new_verified_scenario_earned": False,
        "authority_expanded": False,
        "network_required": False,
        "cloud_required": False,
        "boundaries": dict(BOUNDARIES),
    }


def measure(
    *,
    repeats: int = 15,
    process: psutil.Process | None = None,
    clock: Callable[[], float] | None = None,
) -> dict[str, Any]:
    if not isinstance(repeats, int) or isinstance(repeats, bool) or not MIN_REPEATS <= repeats <= MAX_REPEATS:
        raise ValueError("b127:repeat_count_out_of_range")

    proc = process or psutil.Process()
    now = clock or time.perf_counter
    measurements: list[dict[str, Any]] = []

    for iteration in range(1, repeats + 1):
        rss_before = int(proc.memory_info().rss)
        cpu_before = _cpu_seconds(proc)
        started = now()

        outcomes = run_low_noise_cases()

        ended = now()
        cpu_after = _cpu_seconds(proc)
        rss_after = int(proc.memory_info().rss)
        false_positive, drift = _noise_counts(outcomes)
        measurements.append({
            "iteration": iteration,
            "wall_ms": max(0.0, (ended - started) * 1000.0),
            "cpu_ms": max(0.0, (cpu_after - cpu_before) * 1000.0),
            "rss_delta_bytes": max(0, rss_after - rss_before),
            "false_positive_detections": false_positive,
            "outcome_drift": drift,
            "user_interruptions": 0,
            "outcomes": outcomes,
        })

    report = summarize_measurements(measurements)
    report["measurements"] = measurements
    return report


def self_check() -> dict[str, Any]:
    outcomes = run_low_noise_cases()
    false_positive, drift = _noise_counts(outcomes)
    contract = {
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "coverage": CURRENT_COVERAGE,
        "budgets": BUDGETS,
        "expected_outcomes": EXPECTED_OUTCOMES,
        "boundaries": BOUNDARIES,
    }
    import hashlib
    digest = hashlib.sha256(
        json.dumps(contract, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    passed = outcomes == EXPECTED_OUTCOMES and false_positive == 0 and drift == 0
    return {
        "passed": passed,
        "failures": [] if passed else ["b127:self_check_outcome_drift"],
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "contract_digest": digest,
        "coverage_summary": dict(CURRENT_COVERAGE),
        "expected_outcomes": dict(EXPECTED_OUTCOMES),
        "self_check_outcomes": outcomes,
        "false_positive_detections": false_positive,
        "outcome_drift": drift,
        "coverage_promoted_by_self_check": False,
        "new_verified_scenario_earned": False,
        "authority_expanded": False,
        "network_required": False,
        "cloud_required": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-check", action="store_true")
    parser.add_argument("--measure", action="store_true")
    parser.add_argument("--repeats", type=int, default=15)
    args = parser.parse_args()
    try:
        report = measure(repeats=args.repeats) if args.measure else self_check()
    except ValueError as exc:
        report = {"passed": False, "failures": [str(exc)]}
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report.get("passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())

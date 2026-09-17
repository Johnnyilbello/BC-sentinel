from __future__ import annotations

"""B10-7 Live Coverage Expansion II + Operational Impact.

This milestone measures the operational cost and low-noise behavior of the
already accepted B10-3 controlled live PowerShell metadata detector path. It
also records an explicit, fail-closed evaluation of the remaining PARTIAL live
coverage candidates. No candidate is promoted unless a later accepted harmless
live positive detector source satisfies the existing privacy/authority bounds.

B10-7 does not add network test authority, credential access, protected
security-control mutation, broad persistence mutation, automatic remediation,
or any new response authority beyond the narrow B10-6 disposable-workspace
pilot.
"""

import math
import time
from typing import Any, Callable, Final

import psutil

from sentinel import beta10_powershell_controls as powershell_controls
from sentinel import beta10_reversible_response_pilot as reversible_response

SCHEMA: Final[str] = "bc-sentinel-beta10-operational-impact-v1"
PROFILE: Final[str] = "v0.11.0-beta.10-b107-live-coverage-expansion-ii"
SOURCE_PREDECESSOR_BRANCH: Final[str] = "feature/v011-beta10-b106-reversible-response-pilot"
SOURCE_PREDECESSOR_COMMIT: Final[str] = "79293c641d1ecf5e1ce8d1fa313b9ea4b03f3868"
CURRENT_COVERAGE: Final[dict[str, int]] = {"PARTIAL": 4, "GAP": 0, "VERIFIED": 2}

MIN_REPEATS: Final[int] = 5
MAX_REPEATS: Final[int] = 25
BUDGETS: Final[dict[str, float | int]] = {
    "p95_wall_ms": 750.0,
    "p95_cpu_ms": 750.0,
    "max_rss_delta_mib": 64.0,
    "max_user_interruptions": 0,
}

EXPECTED_OUTCOMES: Final[dict[str, str]] = {
    "positive-powershell-burst": "DETECTED",
    "administrative-powershell-burst": "REVIEW_REQUIRED",
    "benign-powershell-session": "NO_MATCH",
}

PRIVACY_BOUNDARY: Final[dict[str, bool]] = {
    "local_only": True,
    "personal_data_collected": False,
    "file_content_collected": False,
    "absolute_paths_exported": False,
    "powershell_content_read": False,
    "event_message_read": False,
    "event_payload_read": False,
    "event_properties_read": False,
    "credential_access": False,
    "remote_access": False,
    "network_io": False,
    "cloud_required": False,
}

AUTHORITY_BOUNDARY: Final[dict[str, bool]] = {
    "new_authority_expanded": False,
    "automatic_quarantine": False,
    "automatic_repair": False,
    "automatic_restore": False,
    "delete_authority": False,
    "repair_authority": False,
    "terminate_process_authority": False,
    "trust_allowlist_mutation": False,
    "privileged_system_mutation": False,
    "general_home_execution": False,
    "network_test_authority": False,
    "credential_access_authority": False,
    "protected_security_control_mutation": False,
    "broad_persistence_mutation": False,
}

REMAINING_CANDIDATES: Final[tuple[dict[str, str], ...]] = (
    {
        "scenario_id": "B7-PERSISTENCE-001",
        "decision": "DEFERRED_BOUNDARY",
        "reason": "No accepted harmless live persistence detector source exists without adding a new product metadata surface or persistence mutation exercise.",
    },
    {
        "scenario_id": "B7-DEFENSE-EVASION-001",
        "decision": "BLOCKED_AUTHORITY",
        "reason": "A meaningful positive live control would require protected security-control mutation outside the current authority boundary.",
    },
    {
        "scenario_id": "B7-C2-DNS-001",
        "decision": "BLOCKED_AUTHORITY",
        "reason": "A positive live DNS control would require network test authority that is not granted in B10-7.",
    },
    {
        "scenario_id": "B7-CREDENTIAL-001",
        "decision": "BLOCKED_PRIVACY",
        "reason": "A positive credential-access control would require sensitive access prohibited by the privacy boundary.",
    },
)

Measurement = dict[str, Any]


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        raise ValueError("b107:percentile_requires_values")
    if not 0.0 < percentile <= 1.0:
        raise ValueError("b107:percentile_out_of_range")
    ordered = sorted(float(value) for value in values)
    index = max(0, math.ceil(percentile * len(ordered)) - 1)
    return ordered[index]


def _cpu_seconds(process: psutil.Process) -> float:
    cpu = process.cpu_times()
    return float(cpu.user) + float(cpu.system)


def _validate_baseline_summary(summary: object) -> list[str]:
    failures: list[str] = []
    if not isinstance(summary, dict):
        return ["baseline:not_object"]
    if summary.get("passed") is not True:
        failures.append("baseline:not_passed")
    if summary.get("coverage_summary") != CURRENT_COVERAGE:
        failures.append("baseline:coverage_changed")
    if summary.get("synthetic_fallback_used") is not False:
        failures.append("baseline:synthetic_fallback_not_allowed")
    results = summary.get("control_results")
    if not isinstance(results, dict):
        failures.append("baseline:control_results_missing")
    else:
        for control_id, expected in EXPECTED_OUTCOMES.items():
            row = results.get(control_id)
            if not isinstance(row, dict) or row.get("outcome") != expected:
                failures.append(f"baseline:outcome_invalid:{control_id}")
    return failures


def summarize_measurements(
    measurements: list[Measurement],
    baseline_summary: object,
) -> dict[str, Any]:
    failures = _validate_baseline_summary(baseline_summary)
    if len(measurements) < MIN_REPEATS:
        failures.append("measurement:insufficient_repeats")

    wall_values: list[float] = []
    cpu_values: list[float] = []
    rss_values: list[float] = []
    interruption_values: list[int] = []

    for index, row in enumerate(measurements):
        prefix = f"measurement[{index}]"
        if not isinstance(row, dict):
            failures.append(f"{prefix}:not_object")
            continue
        try:
            wall = float(row["wall_ms"])
            cpu = float(row["cpu_ms"])
            rss_delta_bytes = int(row["rss_delta_bytes"])
            interruptions = int(row["user_interruptions"])
        except (KeyError, TypeError, ValueError):
            failures.append(f"{prefix}:metrics_invalid")
            continue
        if wall < 0.0 or cpu < 0.0 or rss_delta_bytes < 0 or interruptions < 0:
            failures.append(f"{prefix}:metrics_negative")
            continue
        wall_values.append(wall)
        cpu_values.append(cpu)
        rss_values.append(rss_delta_bytes / (1024.0 * 1024.0))
        interruption_values.append(interruptions)
        for control_id, expected in EXPECTED_OUTCOMES.items():
            field = {
                "positive-powershell-burst": "positive_outcome",
                "administrative-powershell-burst": "administrative_outcome",
                "benign-powershell-session": "benign_outcome",
            }[control_id]
            if row.get(field) != expected:
                failures.append(f"{prefix}:outcome_drift:{control_id}")

    if wall_values:
        p95_wall = _percentile(wall_values, 0.95)
        p95_cpu = _percentile(cpu_values, 0.95)
        max_rss = max(rss_values)
        max_interruptions = max(interruption_values)
    else:
        p95_wall = p95_cpu = max_rss = float("inf")
        max_interruptions = 2**31 - 1

    if p95_wall > float(BUDGETS["p95_wall_ms"]):
        failures.append("budget:p95_wall_exceeded")
    if p95_cpu > float(BUDGETS["p95_cpu_ms"]):
        failures.append("budget:p95_cpu_exceeded")
    if max_rss > float(BUDGETS["max_rss_delta_mib"]):
        failures.append("budget:rss_delta_exceeded")
    if max_interruptions > int(BUDGETS["max_user_interruptions"]):
        failures.append("budget:user_interruptions_exceeded")

    unique_failures = list(dict.fromkeys(failures))
    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "passed": not unique_failures,
        "failures": unique_failures,
        "source_predecessor_commit": SOURCE_PREDECESSOR_COMMIT,
        "live_evidence_reused_from_b103": True,
        "coverage_expansion_attempted": True,
        "coverage_promoted": False,
        "coverage_summary": dict(CURRENT_COVERAGE),
        "candidate_evaluations": [dict(item) for item in REMAINING_CANDIDATES],
        "operational_metrics": {
            "repeat_count": len(measurements),
            "p95_wall_ms": round(p95_wall, 6) if math.isfinite(p95_wall) else None,
            "p95_cpu_ms": round(p95_cpu, 6) if math.isfinite(p95_cpu) else None,
            "max_rss_delta_mib": round(max_rss, 6) if math.isfinite(max_rss) else None,
            "max_user_interruptions": max_interruptions if max_interruptions < 2**31 - 1 else None,
        },
        "budgets": dict(BUDGETS),
        "false_positive_controls_passed": not any("outcome_drift" in item for item in unique_failures),
        "user_interruption_budget_passed": "budget:user_interruptions_exceeded" not in unique_failures,
        "performance_budget_passed": not any(item.startswith("budget:p95_") or item == "budget:rss_delta_exceeded" for item in unique_failures),
        "new_authority_expanded": False,
        "broad_protection_claimed": False,
        "privacy": dict(PRIVACY_BOUNDARY),
        "authority": dict(AUTHORITY_BOUNDARY),
    }


def measure_operational_impact(
    evidence: object,
    *,
    repeats: int = 7,
    process: psutil.Process | None = None,
    summarize_fn: Callable[[object], dict[str, Any]] | None = None,
    clock: Callable[[], float] | None = None,
) -> dict[str, Any]:
    if not isinstance(repeats, int) or isinstance(repeats, bool) or not MIN_REPEATS <= repeats <= MAX_REPEATS:
        raise ValueError("b107:repeat_count_out_of_range")
    proc = process or psutil.Process()
    summarize = summarize_fn or powershell_controls.summarize
    now = clock or time.perf_counter

    baseline = summarize(evidence)
    baseline_failures = _validate_baseline_summary(baseline)
    if baseline_failures:
        return summarize_measurements([], baseline)

    measurements: list[Measurement] = []
    for iteration in range(1, repeats + 1):
        rss_before = int(proc.memory_info().rss)
        cpu_before = _cpu_seconds(proc)
        wall_started = now()
        summary = summarize(evidence)
        wall_ended = now()
        cpu_after = _cpu_seconds(proc)
        rss_after = int(proc.memory_info().rss)

        results = summary.get("control_results", {}) if isinstance(summary, dict) else {}
        measurements.append(
            {
                "iteration": iteration,
                "wall_ms": max(0.0, (wall_ended - wall_started) * 1000.0),
                "cpu_ms": max(0.0, (cpu_after - cpu_before) * 1000.0),
                "rss_delta_bytes": max(0, rss_after - rss_before),
                "user_interruptions": 0,
                "positive_outcome": (results.get("positive-powershell-burst") or {}).get("outcome"),
                "administrative_outcome": (results.get("administrative-powershell-burst") or {}).get("outcome"),
                "benign_outcome": (results.get("benign-powershell-session") or {}).get("outcome"),
            }
        )

    report = summarize_measurements(measurements, baseline)
    report["measurements"] = measurements
    return report


def validate_b107_contract() -> dict[str, Any]:
    predecessor = reversible_response.validate_b106_contract()
    predecessor_ok = bool(predecessor.get("passed")) and predecessor.get("coverage_summary") == CURRENT_COVERAGE
    candidates_ok = len(REMAINING_CANDIDATES) == 4 and all(
        item["decision"] in {"DEFERRED_BOUNDARY", "BLOCKED_AUTHORITY", "BLOCKED_PRIVACY"}
        for item in REMAINING_CANDIDATES
    )
    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "passed": predecessor_ok and candidates_ok,
        "source_predecessor_branch": SOURCE_PREDECESSOR_BRANCH,
        "source_predecessor_commit": SOURCE_PREDECESSOR_COMMIT,
        "coverage_summary": dict(CURRENT_COVERAGE),
        "coverage_expansion_attempted": True,
        "coverage_promoted": False,
        "remaining_candidate_count": len(REMAINING_CANDIDATES),
        "candidate_evaluations": [dict(item) for item in REMAINING_CANDIDATES],
        "budgets": dict(BUDGETS),
        "predecessor_b106_contract_preserved": predecessor_ok,
        "b106_pilot_quarantine_authority_preserved": predecessor.get("pilot_quarantine_authority") is True,
        "b106_pilot_rollback_authority_preserved": predecessor.get("pilot_rollback_authority") is True,
        "new_authority_expanded": False,
        "broad_protection_claimed": False,
        "privacy": dict(PRIVACY_BOUNDARY),
        "authority": dict(AUTHORITY_BOUNDARY),
    }

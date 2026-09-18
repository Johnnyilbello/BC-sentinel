from __future__ import annotations

"""B12-0 Active Protection Foundation.

Beta12 returns development focus to protection quality: richer Windows telemetry
correlation, broader evidence-backed detection, lower noise, and additional
VERIFIED scenarios. This foundation is contract-only: it does not itself promote
coverage, add remediation authority, change installer behavior, or make broad
protection claims.
"""

import hashlib
import json
from typing import Any, Final

SCHEMA: Final[str] = "bc-sentinel-beta12-active-protection-foundation-v1"
PROFILE: Final[str] = "v0.12.0-beta.12-b120-active-protection-foundation"
SOURCE_CHECKPOINT: Final[str] = "checkpoint/v011-beta11-b119-pass"
SOURCE_CHECKPOINT_COMMIT: Final[str] = "3c5204ca949d41d3a740b8745ab9af06913b8555"

BASELINE_COVERAGE: Final[dict[str, int]] = {"PARTIAL": 4, "GAP": 0, "VERIFIED": 2}
BASELINE_VERIFIED_SCENARIOS: Final[tuple[str, ...]] = (
    "B7-POWERSHELL-001",
    "B7-RANSOMWARE-001",
)

PROTECTION_PILLARS: Final[tuple[dict[str, Any], ...]] = (
    {
        "pillar_id": "CORRELATED_TELEMETRY",
        "goal": "Correlate process, file, parent-child, signer and hash evidence into one bounded local incident graph.",
        "acceptance_signals": (
            "process-to-file evidence remains attributable to a concrete source",
            "missing correlation evidence stays explicit instead of inferred",
            "correlation does not require cloud connectivity",
        ),
    },
    {
        "pillar_id": "SCRIPT_ABUSE_DETECTION",
        "goal": "Expand evidence-backed PowerShell and script-abuse detection beyond the currently verified narrow lifecycle-burst scenario.",
        "acceptance_signals": (
            "harmless Windows fixtures exercise realistic script-abuse signals",
            "positive and negative controls are both required",
            "synthetic-only evidence cannot promote VERIFIED",
        ),
    },
    {
        "pillar_id": "PERSISTENCE_STARTUP_DETECTION",
        "goal": "Detect suspicious persistence and startup behaviors with explicit provenance and safe read-only evidence collection.",
        "acceptance_signals": (
            "persistence signals are tied to concrete local artifacts",
            "benign startup fixtures are used as false-positive controls",
            "no registry or startup mutation is performed by detection tests",
        ),
    },
    {
        "pillar_id": "PROCESS_TREE_INTELLIGENCE",
        "goal": "Identify suspicious process ancestry, launches and chains without inventing causality.",
        "acceptance_signals": (
            "parent-child relationships are evidence-backed",
            "unknown ancestry remains unknown",
            "process-tree scoring is deterministic for equivalent evidence",
        ),
    },
    {
        "pillar_id": "RANSOMWARE_RESILIENCE",
        "goal": "Broaden ransomware-like detection evidence while keeping all exercises harmless and disposable.",
        "acceptance_signals": (
            "controlled local ransomware-like fixtures remain non-destructive",
            "coverage expansion requires Windows evidence",
            "false-positive controls accompany positive controls",
        ),
    },
    {
        "pillar_id": "LOCAL_REPUTATION",
        "goal": "Use local hash, signer and known-good context to improve confidence without requiring a remote reputation service.",
        "acceptance_signals": (
            "local reputation inputs have explicit provenance",
            "unknown reputation remains unknown",
            "no network lookup is required for core acceptance",
        ),
    },
    {
        "pillar_id": "LOW_NOISE_PERFORMANCE",
        "goal": "Improve detection usefulness without unacceptable false positives, latency or resource regressions.",
        "acceptance_signals": (
            "positive controls are paired with benign controls",
            "latency and resource budgets are measurable",
            "performance regressions fail acceptance",
        ),
    },
)

BETA12_MILESTONES: Final[tuple[dict[str, Any], ...]] = (
    {"id": "B12-0", "name": "Active Protection Foundation", "primary_pillars": ("CORRELATED_TELEMETRY", "LOW_NOISE_PERFORMANCE")},
    {"id": "B12-1", "name": "Process/File Correlation 2.0", "primary_pillars": ("CORRELATED_TELEMETRY", "PROCESS_TREE_INTELLIGENCE")},
    {"id": "B12-2", "name": "PowerShell & Script Abuse Expansion", "primary_pillars": ("SCRIPT_ABUSE_DETECTION", "CORRELATED_TELEMETRY")},
    {"id": "B12-3", "name": "Persistence & Autostart Detection", "primary_pillars": ("PERSISTENCE_STARTUP_DETECTION", "CORRELATED_TELEMETRY")},
    {"id": "B12-4", "name": "Suspicious Process Tree Intelligence", "primary_pillars": ("PROCESS_TREE_INTELLIGENCE", "LOW_NOISE_PERFORMANCE")},
    {"id": "B12-5", "name": "Ransomware Protection Expansion", "primary_pillars": ("RANSOMWARE_RESILIENCE", "CORRELATED_TELEMETRY")},
    {"id": "B12-6", "name": "Local Reputation & Hash Intelligence", "primary_pillars": ("LOCAL_REPUTATION", "LOW_NOISE_PERFORMANCE")},
    {"id": "B12-7", "name": "Low-Noise Tuning & Performance", "primary_pillars": ("LOW_NOISE_PERFORMANCE", "CORRELATED_TELEMETRY")},
    {"id": "B12-8", "name": "Verified Coverage Expansion & Product Integration", "primary_pillars": tuple(p["pillar_id"] for p in PROTECTION_PILLARS)},
    {"id": "B12-9", "name": "Windows Active Protection Acceptance & Freeze", "primary_pillars": tuple(p["pillar_id"] for p in PROTECTION_PILLARS)},
)

FINAL_FREEZE_TARGETS: Final[dict[str, Any]] = {
    "minimum_total_verified_scenarios": 4,
    "minimum_new_verified_scenarios": 2,
    "required_gap_count": 0,
    "windows_evidence_required_for_new_verified": True,
    "synthetic_only_verified_promotion_forbidden": True,
    "positive_and_negative_controls_required": True,
    "performance_regression_gate_required": True,
    "broad_protection_claim_forbidden_without_evidence": True,
}

AUTHORITY_BOUNDARY: Final[dict[str, bool]] = {
    "automatic_quarantine": False,
    "automatic_repair": False,
    "automatic_restore": False,
    "general_home_execution": False,
    "delete_authority": False,
    "repair_authority": False,
    "terminate_process_authority": False,
    "trust_allowlist_mutation": False,
    "privileged_system_mutation": False,
    "remote_access": False,
}

INSTALLER_POLICY: Final[dict[str, bool]] = {
    "installer_work_deferred_until_after_beta12": True,
    "b120_changes_installer_behavior": False,
    "b120_signs_artifacts": False,
    "b120_publishes_release": False,
}


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def contract() -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "baseline_coverage": dict(BASELINE_COVERAGE),
        "baseline_verified_scenarios": list(BASELINE_VERIFIED_SCENARIOS),
        "protection_pillars": [
            {**pillar, "acceptance_signals": list(pillar["acceptance_signals"])}
            for pillar in PROTECTION_PILLARS
        ],
        "milestones": [
            {**milestone, "primary_pillars": list(milestone["primary_pillars"])}
            for milestone in BETA12_MILESTONES
        ],
        "final_freeze_targets": dict(FINAL_FREEZE_TARGETS),
        "authority_boundary": dict(AUTHORITY_BOUNDARY),
        "installer_policy": dict(INSTALLER_POLICY),
        "foundation_promotes_coverage": False,
        "foundation_adds_protection_claim": False,
        "foundation_adds_remediation_authority": False,
        "network_required": False,
        "cloud_required": False,
    }


def validate_contract(data: object) -> tuple[str, ...]:
    if not isinstance(data, dict):
        return ("b120:not_object",)

    failures: list[str] = []
    if data != contract():
        failures.append("b120:contract_changed")

    if data.get("source_checkpoint") != SOURCE_CHECKPOINT or data.get("source_checkpoint_commit") != SOURCE_CHECKPOINT_COMMIT:
        failures.append("b120:source_checkpoint_invalid")
    if data.get("baseline_coverage") != BASELINE_COVERAGE:
        failures.append("b120:baseline_coverage_invalid")
    if tuple(data.get("baseline_verified_scenarios", ())) != BASELINE_VERIFIED_SCENARIOS:
        failures.append("b120:baseline_verified_scenarios_invalid")

    pillars = data.get("protection_pillars")
    expected_pillar_ids = [p["pillar_id"] for p in PROTECTION_PILLARS]
    if not isinstance(pillars, list) or [p.get("pillar_id") for p in pillars if isinstance(p, dict)] != expected_pillar_ids:
        failures.append("b120:pillar_identity_invalid")

    milestones = data.get("milestones")
    expected_ids = [f"B12-{i}" for i in range(10)]
    if not isinstance(milestones, list) or [m.get("id") for m in milestones if isinstance(m, dict)] != expected_ids:
        failures.append("b120:milestone_order_invalid")

    targets = data.get("final_freeze_targets")
    if targets != FINAL_FREEZE_TARGETS:
        failures.append("b120:freeze_targets_invalid")
    elif targets["minimum_total_verified_scenarios"] < len(BASELINE_VERIFIED_SCENARIOS):
        failures.append("b120:verified_target_regressed")

    boundary = data.get("authority_boundary")
    if boundary != AUTHORITY_BOUNDARY or not isinstance(boundary, dict) or any(boundary.values()):
        failures.append("b120:authority_boundary_invalid")

    if data.get("installer_policy") != INSTALLER_POLICY:
        failures.append("b120:installer_policy_invalid")
    if data.get("foundation_promotes_coverage") is not False:
        failures.append("b120:foundation_coverage_promotion_forbidden")
    if data.get("foundation_adds_protection_claim") is not False:
        failures.append("b120:foundation_protection_claim_forbidden")
    if data.get("foundation_adds_remediation_authority") is not False:
        failures.append("b120:foundation_remediation_authority_forbidden")
    if data.get("network_required") is not False or data.get("cloud_required") is not False:
        failures.append("b120:local_first_boundary_invalid")

    return tuple(dict.fromkeys(failures))


def self_check() -> dict[str, Any]:
    first = contract()
    second = contract()
    failures = list(validate_contract(first))
    deterministic = first == second and _digest(first) == _digest(second)
    if not deterministic:
        failures.append("b120:contract_not_deterministic")

    return {
        "passed": not failures,
        "failures": failures,
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "baseline_coverage": dict(BASELINE_COVERAGE),
        "baseline_verified_scenarios": list(BASELINE_VERIFIED_SCENARIOS),
        "pillar_count": len(PROTECTION_PILLARS),
        "milestone_count": len(BETA12_MILESTONES),
        "minimum_total_verified_scenarios_for_freeze": FINAL_FREEZE_TARGETS["minimum_total_verified_scenarios"],
        "minimum_new_verified_scenarios_for_freeze": FINAL_FREEZE_TARGETS["minimum_new_verified_scenarios"],
        "contract_digest": _digest(first),
        "deterministic_contract": deterministic,
        "coverage_promoted": False,
        "protection_claim_expanded": False,
        "authority_expanded": any(AUTHORITY_BOUNDARY.values()),
        "installer_work_deferred": INSTALLER_POLICY["installer_work_deferred_until_after_beta12"],
        "network_required": False,
        "cloud_required": False,
    }


def main() -> int:
    result = self_check()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

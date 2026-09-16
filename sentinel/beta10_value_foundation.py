from __future__ import annotations

"""B10-0 product-value foundation and competitive engineering contract.

This milestone does not add protection, remediation, execution, or cloud authority.
It freezes the accepted Beta9 baseline and turns Beta10 product strategy into a
machine-checkable contract so later milestones can be judged on customer value,
evidence quality, operational impact, and safety rather than feature count.
"""

import hashlib
import json
from typing import Any, Final

SCHEMA: Final[str] = "bc-sentinel-beta10-value-foundation-v1"
PROFILE: Final[str] = "v0.11.0-beta.10-b100-value-foundation"
SOURCE_CHECKPOINT: Final[str] = "checkpoint/v011-beta9-b94-pass"
SOURCE_CHECKPOINT_COMMIT: Final[str] = "cc32c2c31ebb9b863624632a38175ec5825430e4"
BASELINE_COVERAGE: Final[dict[str, int]] = {"PARTIAL": 5, "GAP": 0, "VERIFIED": 1}
VERIFIED_SCENARIO: Final[str] = "B7-RANSOMWARE-001"

VALUE_PILLARS: Final[tuple[dict[str, Any], ...]] = (
    {
        "pillar_id": "PROTECTION_PROOF",
        "customer_value": "Show exactly which protections are proven on this Windows machine, when they were last proven, and what remains partial.",
        "success_metrics": (
            "scenario status is evidence-backed",
            "harmless local proof can be rerun on demand",
            "limitations are shown next to the claim",
            "synthetic evidence cannot promote VERIFIED",
        ),
        "market_role": "trust differentiator",
        "current_state": "foundation_only",
    },
    {
        "pillar_id": "ATTACK_STORY",
        "customer_value": "Turn correlated security evidence into an ordered, explainable incident story with entry point, stages, confidence, and supporting evidence.",
        "success_metrics": (
            "every story statement maps to accepted evidence",
            "unknown stages remain explicit",
            "plain-language and technical views share one evidence graph",
            "no generated explanation may invent entities or causality",
        ),
        "market_role": "enterprise-grade explainability with simpler UX",
        "current_state": "foundation_only",
    },
    {
        "pillar_id": "SAFE_RESPONSE",
        "customer_value": "Present a clear response plan before any action, including expected impact, approval boundary, and rollback path.",
        "success_metrics": (
            "response plan is deterministic from accepted evidence",
            "dry-run is available before authority expansion",
            "every future mutating action requires an explicit safety contract",
            "rollback or non-reversibility is declared before approval",
        ),
        "market_role": "confidence and recoverability",
        "current_state": "planning_only_no_execution_authority",
    },
    {
        "pillar_id": "RESCUE_CONTINUITY",
        "customer_value": "Preserve incident and evidence identity when moving from live Windows to portable or offline rescue workflows.",
        "success_metrics": (
            "incident identifiers survive handoff",
            "evidence provenance survives handoff",
            "offline findings can be reconciled without overwriting live evidence",
            "portable mode does not require cloud connectivity",
        ),
        "market_role": "field-recovery differentiator",
        "current_state": "foundation_only",
    },
    {
        "pillar_id": "LOW_NOISE_OPERATION",
        "customer_value": "Reduce security friction by measuring false positives, latency, resource use, and the number of user decisions required per incident.",
        "success_metrics": (
            "false-positive controls accompany positive controls",
            "latency and memory budgets are measured",
            "operator decision count is measurable",
            "performance regressions fail acceptance",
        ),
        "market_role": "operational-impact differentiator",
        "current_state": "foundation_only",
    },
    {
        "pillar_id": "LOCAL_FIRST_PRIVACY",
        "customer_value": "Keep sensitive analysis local by default and collect only the minimum telemetry required to support a security claim.",
        "success_metrics": (
            "personal data is excluded unless a later explicit contract requires it",
            "event payload collection is never implied by metadata availability",
            "remote access is not required for core proof workflows",
            "rejected input is not echoed when it may contain sensitive data",
        ),
        "market_role": "privacy differentiator",
        "current_state": "active_boundary",
    },
)

BETA10_MILESTONES: Final[tuple[dict[str, Any], ...]] = (
    {"id": "B10-0", "name": "Value Foundation + Competitive Contract", "primary_pillars": ("PROTECTION_PROOF", "LOW_NOISE_OPERATION", "LOCAL_FIRST_PRIVACY")},
    {"id": "B10-1", "name": "Sentinel Proof Mode", "primary_pillars": ("PROTECTION_PROOF", "LOCAL_FIRST_PRIVACY")},
    {"id": "B10-2", "name": "Attack Story 2.0", "primary_pillars": ("ATTACK_STORY", "PROTECTION_PROOF")},
    {"id": "B10-3", "name": "Live Coverage Expansion I", "primary_pillars": ("PROTECTION_PROOF", "LOW_NOISE_OPERATION")},
    {"id": "B10-4", "name": "Safe Response Plan Engine", "primary_pillars": ("SAFE_RESPONSE", "ATTACK_STORY")},
    {"id": "B10-5", "name": "Rescue Continuity", "primary_pillars": ("RESCUE_CONTINUITY", "PROTECTION_PROOF")},
    {"id": "B10-6", "name": "Reversible Response Pilot", "primary_pillars": ("SAFE_RESPONSE", "RESCUE_CONTINUITY")},
    {"id": "B10-7", "name": "Live Coverage Expansion II + Operational Impact", "primary_pillars": ("PROTECTION_PROOF", "LOW_NOISE_OPERATION")},
    {"id": "B10-8", "name": "Trust Center Product Integration", "primary_pillars": ("PROTECTION_PROOF", "ATTACK_STORY", "SAFE_RESPONSE", "RESCUE_CONTINUITY")},
    {"id": "B10-9", "name": "Beta10 Windows Competitive Acceptance & Freeze", "primary_pillars": tuple(p["pillar_id"] for p in VALUE_PILLARS)},
)

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
    "broad_protection_claimed": False,
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
        "verified_scenario_id": VERIFIED_SCENARIO,
        "value_pillars": [
            {
                **pillar,
                "success_metrics": list(pillar["success_metrics"]),
            }
            for pillar in VALUE_PILLARS
        ],
        "milestones": [
            {
                **milestone,
                "primary_pillars": list(milestone["primary_pillars"]),
            }
            for milestone in BETA10_MILESTONES
        ],
        "authority_boundary": dict(AUTHORITY_BOUNDARY),
        "beta10_adds_protection_claim_at_foundation": False,
        "beta10_adds_remediation_authority_at_foundation": False,
    }


def validate_contract(data: object) -> tuple[str, ...]:
    if not isinstance(data, dict):
        return ("b100:not_object",)
    failures: list[str] = []
    expected_keys = {
        "schema", "profile", "source_checkpoint", "source_checkpoint_commit",
        "baseline_coverage", "verified_scenario_id", "value_pillars", "milestones",
        "authority_boundary", "beta10_adds_protection_claim_at_foundation",
        "beta10_adds_remediation_authority_at_foundation",
    }
    if set(data) != expected_keys:
        failures.append("b100:unexpected_or_missing_fields")
    if data.get("schema") != SCHEMA or data.get("profile") != PROFILE:
        failures.append("b100:schema_or_profile_invalid")
    if data.get("source_checkpoint") != SOURCE_CHECKPOINT or data.get("source_checkpoint_commit") != SOURCE_CHECKPOINT_COMMIT:
        failures.append("b100:source_checkpoint_invalid")
    if data.get("baseline_coverage") != BASELINE_COVERAGE or data.get("verified_scenario_id") != VERIFIED_SCENARIO:
        failures.append("b100:baseline_invalid")
    if data.get("beta10_adds_protection_claim_at_foundation") is not False:
        failures.append("b100:foundation_protection_claim_forbidden")
    if data.get("beta10_adds_remediation_authority_at_foundation") is not False:
        failures.append("b100:foundation_remediation_authority_forbidden")

    boundary = data.get("authority_boundary")
    if boundary != AUTHORITY_BOUNDARY or not isinstance(boundary, dict):
        failures.append("b100:authority_boundary_invalid")
    elif any(boundary.values()):
        failures.append("b100:authority_expansion_forbidden")

    pillars = data.get("value_pillars")
    if not isinstance(pillars, list) or len(pillars) != len(VALUE_PILLARS):
        failures.append("b100:pillar_count_invalid")
    else:
        ids = [item.get("pillar_id") for item in pillars if isinstance(item, dict)]
        if ids != [item["pillar_id"] for item in VALUE_PILLARS] or len(set(ids)) != len(ids):
            failures.append("b100:pillar_identity_invalid")
        for item in pillars:
            if not isinstance(item, dict):
                failures.append("b100:pillar_not_object")
                continue
            metrics = item.get("success_metrics")
            if not isinstance(metrics, list) or len(metrics) < 3 or not all(isinstance(v, str) and v for v in metrics):
                failures.append("b100:pillar_metrics_invalid")
            if not isinstance(item.get("customer_value"), str) or not item.get("customer_value"):
                failures.append("b100:pillar_customer_value_invalid")

    milestones = data.get("milestones")
    expected_milestone_ids = [f"B10-{i}" for i in range(10)]
    if not isinstance(milestones, list) or [m.get("id") for m in milestones if isinstance(m, dict)] != expected_milestone_ids:
        failures.append("b100:milestone_order_invalid")
    else:
        pillar_ids = {p["pillar_id"] for p in VALUE_PILLARS}
        for milestone in milestones:
            if not isinstance(milestone.get("name"), str) or not milestone["name"]:
                failures.append("b100:milestone_name_invalid")
            primary = milestone.get("primary_pillars")
            if not isinstance(primary, list) or not primary or not set(primary).issubset(pillar_ids):
                failures.append("b100:milestone_pillars_invalid")
    return tuple(failures)


def self_check() -> dict[str, Any]:
    first = contract()
    second = contract()
    failures = list(validate_contract(first))
    deterministic = first == second and _digest(first) == _digest(second)
    if not deterministic:
        failures.append("b100:contract_not_deterministic")
    return {
        "passed": not failures,
        "failures": failures,
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "baseline_coverage": dict(BASELINE_COVERAGE),
        "verified_scenario_id": VERIFIED_SCENARIO,
        "pillar_count": len(VALUE_PILLARS),
        "milestone_count": len(BETA10_MILESTONES),
        "contract_digest": _digest(first),
        "deterministic_contract": deterministic,
        "authority_expanded": any(AUTHORITY_BOUNDARY.values()),
        "protection_claim_expanded": False,
    }


def main() -> int:
    result = self_check()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

"""B10-9 Windows Competitive Acceptance & Freeze composition contract.

B10-9 adds no protection or response authority. It composes the already accepted
Beta10 evidence into one fail-closed freeze decision: all six customer-value
pillars must be demonstrated, fresh operational-impact evidence must stay inside
budget, Trust Center claims must match accepted coverage, and the reversible
response exercise must finish rolled back.

"Competitive" here means conformance to the B10-0 competitive engineering
contract. It is not an external market-superiority claim.
"""

from copy import deepcopy
from typing import Any, Final

from sentinel import beta10_operational_impact as impact
from sentinel import beta10_rescue_continuity as rescue
from sentinel import beta10_reversible_response_pilot as reversible
from sentinel import beta10_trust_center as trust
from sentinel import beta10_value_foundation as value

SCHEMA: Final[str] = "bc-sentinel-beta10-final-acceptance-v1"
PROFILE: Final[str] = "v0.11.0-beta.10-b109-windows-competitive-acceptance-freeze"
SOURCE_PREDECESSOR_CHECKPOINT: Final[str] = "checkpoint/v011-beta10-b108-pass"
SOURCE_PREDECESSOR_COMMIT: Final[str] = "aa0c2b4e4b79381f9a20a5d69e99e972dee46971"
FINAL_COVERAGE: Final[dict[str, int]] = {"PARTIAL": 4, "GAP": 0, "VERIFIED": 2}
VERIFIED_SCENARIOS: Final[tuple[str, ...]] = (
    "B7-POWERSHELL-001",
    "B7-RANSOMWARE-001",
)

PILLAR_IDS: Final[tuple[str, ...]] = tuple(p["pillar_id"] for p in value.VALUE_PILLARS)


def _trust_report_failures(report: object) -> list[str]:
    if not isinstance(report, dict):
        return ["b109:trust_report_not_object"]
    failures: list[str] = []
    if report.get("passed") is not True:
        failures.append("b109:trust_report_not_passed")
    if report.get("profile") != trust.PROFILE:
        failures.append("b109:trust_profile_invalid")
    if report.get("coverage_summary") != FINAL_COVERAGE:
        failures.append("b109:trust_coverage_invalid")
    if tuple(report.get("verified_scenarios") or []) != VERIFIED_SCENARIOS:
        failures.append("b109:trust_verified_set_invalid")
    if report.get("scenario_count") != 6 or report.get("capability_count") != 6:
        failures.append("b109:trust_inventory_incomplete")
    if report.get("impact_status") != "MEASURED":
        failures.append("b109:impact_not_measured")
    if report.get("presentation_can_promote_coverage") is not False:
        failures.append("b109:presentation_can_promote_coverage")
    if report.get("general_response_execution_available") is not False:
        failures.append("b109:general_response_execution_enabled")
    if report.get("reversible_response_scope") != "DISPOSABLE_TEMP_WORKSPACE_ONLY":
        failures.append("b109:reversible_response_scope_changed")
    if report.get("new_authority_expanded") is not False:
        failures.append("b109:trust_new_authority_expanded")
    if report.get("broad_protection_claimed") is not False:
        failures.append("b109:broad_protection_claimed")

    metrics = report.get("impact_metrics")
    if not isinstance(metrics, dict):
        failures.append("b109:impact_metrics_missing")
    else:
        try:
            if int(metrics.get("repeat_count")) < impact.MIN_REPEATS:
                failures.append("b109:impact_repeat_count_too_low")
            if float(metrics.get("p95_wall_ms")) > float(impact.BUDGETS["p95_wall_ms"]):
                failures.append("b109:impact_wall_budget_failed")
            if float(metrics.get("p95_cpu_ms")) > float(impact.BUDGETS["p95_cpu_ms"]):
                failures.append("b109:impact_cpu_budget_failed")
            if float(metrics.get("max_rss_delta_mib")) > float(impact.BUDGETS["max_rss_delta_mib"]):
                failures.append("b109:impact_rss_budget_failed")
            if int(metrics.get("max_user_interruptions")) > int(impact.BUDGETS["max_user_interruptions"]):
                failures.append("b109:impact_interruption_budget_failed")
        except (TypeError, ValueError, KeyError):
            failures.append("b109:impact_metrics_invalid")

    smoke = report.get("ui_smoke")
    if not isinstance(smoke, dict) or smoke.get("passed") is not True:
        failures.append("b109:trust_ui_smoke_failed")
    else:
        if smoke.get("page_count") != 7 or smoke.get("trust_center_selected") is not True:
            failures.append("b109:trust_ui_surface_invalid")
        overflow = smoke.get("horizontal_overflow")
        if not isinstance(overflow, dict) or set(overflow) != {"560", "680", "960", "1440"}:
            failures.append("b109:trust_ui_width_inventory_invalid")
        elif any(int(value) != 0 for value in overflow.values()):
            failures.append("b109:trust_ui_horizontal_overflow")
    return failures


def _pilot_failures(result: object) -> list[str]:
    if not isinstance(result, dict):
        return ["b109:pilot_result_not_object"]
    failures: list[str] = []
    if result.get("passed") is not True or result.get("profile") != reversible.PROFILE:
        failures.append("b109:pilot_result_invalid")
    if result.get("quarantine_state") != "QUARANTINED":
        failures.append("b109:pilot_quarantine_not_observed")
    if result.get("final_state") != "ROLLED_BACK":
        failures.append("b109:pilot_not_rolled_back")
    if int(result.get("journal_record_count") or 0) < 1:
        failures.append("b109:pilot_journal_missing")
    for key in (
        "automatic_action",
        "broad_home_execution",
        "delete_authority",
        "repair_authority",
        "terminate_process_authority",
        "privileged_system_mutation",
        "broad_remediation_claimed",
    ):
        if result.get(key) is not False:
            failures.append(f"b109:pilot_boundary_changed:{key}")
    if result.get("pilot_quarantine_authority") is not True or result.get("pilot_rollback_authority") is not True:
        failures.append("b109:pilot_narrow_authority_missing")
    if result.get("authority_expanded") is not True:
        failures.append("b109:pilot_authority_identity_changed")
    if result.get("coverage_summary") != FINAL_COVERAGE:
        failures.append("b109:pilot_coverage_invalid")
    return failures


def _foundation_failures() -> list[str]:
    failures: list[str] = []
    v = value.self_check()
    b106 = reversible.validate_b106_contract()
    b107 = impact.validate_b107_contract()
    b108 = trust.validate_b108_contract()

    if v.get("passed") is not True or v.get("pillar_count") != 6 or v.get("milestone_count") != 10:
        failures.append("b109:value_contract_invalid")
    if v.get("deterministic_contract") is not True:
        failures.append("b109:value_contract_not_deterministic")
    if b106.get("passed") is not True:
        failures.append("b109:b106_contract_invalid")
    if b107.get("passed") is not True or b107.get("coverage_summary") != FINAL_COVERAGE:
        failures.append("b109:b107_contract_invalid")
    if b108.get("passed") is not True or b108.get("coverage_summary") != FINAL_COVERAGE:
        failures.append("b109:b108_contract_invalid")

    if rescue.CURRENT_COVERAGE != FINAL_COVERAGE:
        failures.append("b109:rescue_coverage_invalid")
    if rescue.CONTINUITY_STATE != "PORTABLE_CONTEXT_PREPARED_NOT_EXECUTABLE":
        failures.append("b109:rescue_continuity_state_invalid")
    if rescue.TARGET_BINDING_STATE != "REQUIRED":
        failures.append("b109:rescue_target_binding_invalid")
    if any(rescue.AUTHORITY_BOUNDARY.values()):
        failures.append("b109:rescue_authority_expanded")
    expected_privacy = {
        "local_only": True,
        "personal_data_collected": False,
        "file_content_collected": False,
        "absolute_paths_exported": False,
        "remote_access": False,
        "network_required": False,
        "cloud_required": False,
    }
    if rescue.PRIVACY_BOUNDARY != expected_privacy:
        failures.append("b109:rescue_privacy_boundary_invalid")
    return failures


def _pillar_evidence(trust_report: dict[str, Any], pilot_result: dict[str, Any]) -> list[dict[str, Any]]:
    metrics = deepcopy(trust_report["impact_metrics"])
    return [
        {
            "pillar_id": "PROTECTION_PROOF",
            "demonstrated": trust_report["coverage_summary"] == FINAL_COVERAGE
            and tuple(trust_report["verified_scenarios"]) == VERIFIED_SCENARIOS,
            "evidence": "accepted scenario ledger + Trust Center",
        },
        {
            "pillar_id": "ATTACK_STORY",
            "demonstrated": trust.validate_b108_contract().get("attack_story_requires_evidence") is True,
            "evidence": "evidence-only Attack Story contract with unknown stages preserved",
        },
        {
            "pillar_id": "SAFE_RESPONSE",
            "demonstrated": trust_report["general_response_execution_available"] is False
            and pilot_result["final_state"] == "ROLLED_BACK",
            "evidence": "planning-only general response + narrow reversible pilot",
        },
        {
            "pillar_id": "RESCUE_CONTINUITY",
            "demonstrated": rescue.CONTINUITY_STATE == "PORTABLE_CONTEXT_PREPARED_NOT_EXECUTABLE"
            and not any(rescue.AUTHORITY_BOUNDARY.values()),
            "evidence": "integrity-bound non-executing portable/rescue continuity",
        },
        {
            "pillar_id": "LOW_NOISE_OPERATION",
            "demonstrated": metrics["max_user_interruptions"] == 0
            and metrics["p95_wall_ms"] <= impact.BUDGETS["p95_wall_ms"]
            and metrics["p95_cpu_ms"] <= impact.BUDGETS["p95_cpu_ms"]
            and metrics["max_rss_delta_mib"] <= impact.BUDGETS["max_rss_delta_mib"],
            "evidence": "fresh operational-impact measurement inside accepted budgets",
        },
        {
            "pillar_id": "LOCAL_FIRST_PRIVACY",
            "demonstrated": trust.PRIVACY_BOUNDARY["local_only"] is True
            and all(
                trust.PRIVACY_BOUNDARY[key] is False
                for key in (
                    "personal_data_collected",
                    "file_content_collected",
                    "absolute_paths_exported",
                    "credential_access",
                    "remote_access",
                    "network_io",
                    "cloud_required",
                )
            ),
            "evidence": "local-first privacy boundary preserved through Trust Center",
        },
    ]


def build_final_report(trust_report: object, pilot_result: object) -> dict[str, Any]:
    failures = [*_foundation_failures(), *_trust_report_failures(trust_report), *_pilot_failures(pilot_result)]
    if failures:
        return {
            "schema": SCHEMA,
            "profile": PROFILE,
            "passed": False,
            "failures": list(dict.fromkeys(failures)),
            "freeze_eligible": False,
            "external_market_superiority_claimed": False,
        }

    assert isinstance(trust_report, dict)
    assert isinstance(pilot_result, dict)
    pillars = _pillar_evidence(trust_report, pilot_result)
    if [row["pillar_id"] for row in pillars] != list(PILLAR_IDS):
        failures.append("b109:pillar_identity_mismatch")
    if not all(row["demonstrated"] is True for row in pillars):
        failures.append("b109:value_pillar_not_demonstrated")

    report = {
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_predecessor_checkpoint": SOURCE_PREDECESSOR_CHECKPOINT,
        "source_predecessor_commit": SOURCE_PREDECESSOR_COMMIT,
        "passed": not failures,
        "failures": list(dict.fromkeys(failures)),
        "freeze_eligible": not failures,
        "freeze_state": "ELIGIBLE_AFTER_EXACT_CI_AND_LOCAL_ACCEPTANCE" if not failures else "BLOCKED",
        "competitive_contract_passed": not failures,
        "competitive_contract_scope": "BETA10_INTERNAL_VALUE_AND_SAFETY_CONTRACT",
        "external_market_superiority_claimed": False,
        "pillar_count": len(pillars),
        "milestone_count": len(value.BETA10_MILESTONES),
        "all_value_pillars_demonstrated": not failures and all(row["demonstrated"] for row in pillars),
        "pillar_evidence": pillars,
        "coverage_summary": dict(FINAL_COVERAGE),
        "verified_scenarios": list(VERIFIED_SCENARIOS),
        "scenario_count": 6,
        "trust_center_page_count": trust_report["ui_smoke"]["page_count"],
        "trust_center_no_horizontal_overflow": all(
            int(v) == 0 for v in trust_report["ui_smoke"]["horizontal_overflow"].values()
        ),
        "operational_metrics": deepcopy(trust_report["impact_metrics"]),
        "operational_budgets": dict(impact.BUDGETS),
        "false_positive_controls_required": True,
        "max_user_interruptions": int(trust_report["impact_metrics"]["max_user_interruptions"]),
        "rescue_continuity_non_executing": True,
        "general_response_execution_available": False,
        "reversible_response_scope": "DISPOSABLE_TEMP_WORKSPACE_ONLY",
        "reversible_response_final_state": pilot_result["final_state"],
        "reversible_response_journal_records": pilot_result["journal_record_count"],
        "new_authority_expanded_in_b109": False,
        "broad_protection_claimed": False,
        "presentation_can_promote_coverage": False,
        "local_first": True,
        "credential_access": False,
        "network_io": False,
        "cloud_required": False,
    }
    return report


def validate_b109_contract() -> dict[str, Any]:
    failures = _foundation_failures()
    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "passed": not failures,
        "failures": list(dict.fromkeys(failures)),
        "source_predecessor_checkpoint": SOURCE_PREDECESSOR_CHECKPOINT,
        "source_predecessor_commit": SOURCE_PREDECESSOR_COMMIT,
        "coverage_summary": dict(FINAL_COVERAGE),
        "verified_scenarios": list(VERIFIED_SCENARIOS),
        "pillar_count": len(PILLAR_IDS),
        "milestone_count": len(value.BETA10_MILESTONES),
        "competitive_contract_scope": "BETA10_INTERNAL_VALUE_AND_SAFETY_CONTRACT",
        "external_market_superiority_claimed": False,
        "general_response_execution_available": False,
        "reversible_response_scope": "DISPOSABLE_TEMP_WORKSPACE_ONLY",
        "rescue_continuity_non_executing": True,
        "new_authority_expanded_in_b109": False,
        "broad_protection_claimed": False,
        "presentation_can_promote_coverage": False,
    }

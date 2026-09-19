from __future__ import annotations

"""B12-9 Windows Active Protection Acceptance & Freeze.

Final Beta12 composition contract. It adds no detector, coverage promotion,
remediation authority, installer, signing, publication, network dependency or
cloud requirement. Freeze eligibility requires all accepted B12 predecessor
checkpoints, a fresh B12-7 low-noise measurement, a validated B12-8 product
snapshot and a read-only Trust Center UI smoke test on the same source commit.
"""

from copy import deepcopy
import hashlib
import json
from typing import Any, Final

from sentinel import beta12_low_noise_performance as b127
from sentinel import beta12_product_integration as b128

SCHEMA: Final[str] = "bc-sentinel-beta12-final-freeze-v1"
PROFILE: Final[str] = "v0.12.0-beta.12-b129-windows-active-protection-acceptance-freeze"
SOURCE_CHECKPOINT: Final[str] = "checkpoint/v012-beta12-b128-pass"
SOURCE_CHECKPOINT_COMMIT: Final[str] = "88a7f3df43ba329cb632252ef03928b069cbcc3d"

FINAL_COVERAGE: Final[dict[str, int]] = {"PARTIAL": 4, "GAP": 0, "VERIFIED": 7}
VERIFIED_SCENARIOS: Final[tuple[str, ...]] = (
    "B7-POWERSHELL-001",
    "B7-RANSOMWARE-001",
    "B12-SCRIPT-ABUSE-001",
    "B12-AUTOSTART-LINK-001",
    "B12-PROCESS-TREE-001",
    "B12-RANSOMWARE-PROCESS-001",
    "B12-LOCAL-REPUTATION-001",
)

ACCEPTED_BETA12_CHECKPOINTS: Final[tuple[tuple[str, str], ...]] = (
    ("checkpoint/v012-beta12-b120-pass", "0015feb80c550b9c67707f24f4042a45412e7af3"),
    ("checkpoint/v012-beta12-b121-pass", "cd8b3e89211afe29bf32a2646f4210c73179bc1f"),
    ("checkpoint/v012-beta12-b122-pass", "dedf78ae920b87f44636a0b9bd0c9708d2ae760b"),
    ("checkpoint/v012-beta12-b123-pass", "90776f9b0e3f1a9c034b79a5886b30df0db41e5c"),
    ("checkpoint/v012-beta12-b124-pass", "8e1cb119ef225efbf89471bddc645dc5416c8e01"),
    ("checkpoint/v012-beta12-b125-pass", "04dfef15f5cb5583fd49b878efc9de663e74cdcb"),
    ("checkpoint/v012-beta12-b126-pass", "b1f55ea32564d72cae6056308f90f8b41137dc94"),
    ("checkpoint/v012-beta12-b127-pass", "8e5614c919611a7b072dd0a4f462c56751ba331d"),
    ("checkpoint/v012-beta12-b128-pass", SOURCE_CHECKPOINT_COMMIT),
)

SOURCE_B127_CONTRACT_DIGEST: Final[str] = "81d9c55313fcd3720e40c53980150f6684844d35cf61e5e1794a8b7fbfc2c8c9"
SOURCE_B128_CONTRACT_DIGEST: Final[str] = "2e3029c2d222ad13488d5cbf10e9224eff8b1b8100fc2062ac1ba8009bf2618d"
SOURCE_B128_PRODUCT_EVIDENCE_DIGEST: Final[str] = "91d812eb9bd41cd00402c39f03c61e61a11081ba46e21d993bff258b92f60fa0"

FREEZE_POLICY: Final[dict[str, Any]] = {
    "all_beta12_checkpoints_must_match": True,
    "accepted_predecessor_source_immutable": True,
    "full_beta5_to_beta12_regression_required": True,
    "fresh_b127_measurement_required": True,
    "b127_false_positive_gate_required": True,
    "b127_outcome_stability_gate_required": True,
    "b127_performance_gate_required": True,
    "b128_product_snapshot_required": True,
    "b128_read_only_ui_smoke_required": True,
    "exact_ci_and_local_same_commit_required": True,
    "coverage_promotion_by_b129": False,
    "installer_execution_by_b129": False,
    "artifact_signing_by_b129": False,
    "release_publication_by_b129": False,
}

AUTHORITY_BOUNDARY: Final[dict[str, bool]] = {
    "automatic_quarantine": False,
    "automatic_repair": False,
    "automatic_restore": False,
    "terminate_process_authority": False,
    "trust_allowlist_mutation": False,
    "privileged_system_mutation": False,
    "general_home_execution": False,
    "installer_execution": False,
    "artifact_signing": False,
    "release_publication": False,
    "network_required": False,
    "cloud_required": False,
    "coverage_promoted": False,
    "new_authority_expanded": False,
}


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _product_evidence_digest(snapshot: dict[str, Any]) -> str:
    material = {
        "schema": snapshot["schema"],
        "profile": snapshot["profile"],
        "source_checkpoint": snapshot["source_checkpoint"],
        "source_checkpoint_commit": snapshot["source_checkpoint_commit"],
        "coverage_summary": snapshot["coverage_summary"],
        "verified_scenarios": snapshot["verified_scenarios"],
        "scenarios": snapshot["scenarios"],
        "capabilities": snapshot["capabilities"],
        "privacy": snapshot["privacy"],
        "authority": snapshot["authority"],
    }
    return _digest(material)


def contract() -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "final_coverage": dict(FINAL_COVERAGE),
        "verified_scenarios": list(VERIFIED_SCENARIOS),
        "accepted_beta12_checkpoints": [
            {"checkpoint": checkpoint, "commit": commit}
            for checkpoint, commit in ACCEPTED_BETA12_CHECKPOINTS
        ],
        "source_b127_contract_digest": SOURCE_B127_CONTRACT_DIGEST,
        "source_b128_contract_digest": SOURCE_B128_CONTRACT_DIGEST,
        "source_b128_product_evidence_digest": SOURCE_B128_PRODUCT_EVIDENCE_DIGEST,
        "freeze_policy": dict(FREEZE_POLICY),
        "authority_boundary": dict(AUTHORITY_BOUNDARY),
    }


def validate_contract(data: object) -> tuple[str, ...]:
    failures: list[str] = []
    if not isinstance(data, dict):
        return ("b129:not_object",)
    if data != contract():
        failures.append("b129:contract_changed")

    r127 = b127.self_check()
    if r127.get("passed") is not True:
        failures.append("b129:b127_self_check_failed")
    if r127.get("contract_digest") != SOURCE_B127_CONTRACT_DIGEST:
        failures.append("b129:b127_contract_digest_mismatch")
    if r127.get("coverage_summary") != FINAL_COVERAGE:
        failures.append("b129:b127_coverage_mismatch")

    r128 = b128.self_check()
    if r128.get("passed") is not True:
        failures.append("b129:b128_self_check_failed")
    if r128.get("contract_digest") != SOURCE_B128_CONTRACT_DIGEST:
        failures.append("b129:b128_contract_digest_mismatch")
    if r128.get("coverage_summary") != FINAL_COVERAGE:
        failures.append("b129:b128_coverage_mismatch")
    if tuple(r128.get("verified_scenarios") or ()) != VERIFIED_SCENARIOS:
        failures.append("b129:b128_verified_set_mismatch")

    if any(AUTHORITY_BOUNDARY.values()):
        failures.append("b129:authority_boundary_expanded")
    return tuple(dict.fromkeys(failures))


def _impact_failures(report: object) -> list[str]:
    if not isinstance(report, dict):
        return ["b129:impact_not_object"]
    failures: list[str] = []
    if report.get("schema") != b127.SCHEMA or report.get("profile") != b127.PROFILE:
        failures.append("b129:impact_identity_invalid")
    if report.get("passed") is not True:
        failures.append("b129:impact_not_passed")
    if report.get("coverage_summary") != FINAL_COVERAGE:
        failures.append("b129:impact_coverage_changed")
    if report.get("coverage_promoted") is not False:
        failures.append("b129:impact_coverage_promoted")
    for field in (
        "false_positive_gate_passed",
        "outcome_stability_gate_passed",
        "performance_gate_passed",
        "user_interruption_gate_passed",
    ):
        if report.get(field) is not True:
            failures.append(f"b129:impact_{field}_failed")
    metrics = report.get("operational_metrics")
    if not isinstance(metrics, dict):
        failures.append("b129:impact_metrics_missing")
        return failures
    try:
        if int(metrics["repeat_count"]) < b127.MIN_REPEATS:
            failures.append("b129:impact_repeat_count_low")
        if int(metrics["max_false_positive_detections"]) != 0:
            failures.append("b129:false_positive_regression")
        if int(metrics["max_outcome_drift"]) != 0:
            failures.append("b129:outcome_drift_regression")
        if int(metrics["max_user_interruptions"]) != 0:
            failures.append("b129:user_interruption_regression")
        if float(metrics["p95_wall_ms"]) > float(b127.BUDGETS["p95_wall_ms"]):
            failures.append("b129:wall_budget_failed")
        if float(metrics["p95_cpu_ms"]) > float(b127.BUDGETS["p95_cpu_ms"]):
            failures.append("b129:cpu_budget_failed")
        if float(metrics["max_rss_delta_mib"]) > float(b127.BUDGETS["max_rss_delta_mib"]):
            failures.append("b129:rss_budget_failed")
    except (KeyError, TypeError, ValueError):
        failures.append("b129:impact_metrics_invalid")
    return failures


def _snapshot_failures(snapshot: object) -> list[str]:
    if not isinstance(snapshot, dict):
        return ["b129:snapshot_not_object"]
    failures: list[str] = []
    validation = b128.validate_snapshot(snapshot)
    if validation.get("passed") is not True:
        failures.extend(f"b129:{item}" for item in validation.get("failures", []))
    if snapshot.get("passed") is not True:
        failures.append("b129:snapshot_not_passed")
    if snapshot.get("coverage_summary") != FINAL_COVERAGE:
        failures.append("b129:snapshot_coverage_changed")
    if tuple(snapshot.get("verified_scenarios") or ()) != VERIFIED_SCENARIOS:
        failures.append("b129:snapshot_verified_set_changed")
    if len(snapshot.get("scenarios") or []) != 11:
        failures.append("b129:snapshot_scenario_count_invalid")
    if len(snapshot.get("capabilities") or []) != 7:
        failures.append("b129:snapshot_capability_count_invalid")
    if snapshot.get("product_ui_read_only") is not True:
        failures.append("b129:snapshot_ui_not_read_only")
    if snapshot.get("coverage_promoted_by_presentation") is not False:
        failures.append("b129:snapshot_presentation_promoted_coverage")
    if snapshot.get("broad_protection_claimed") is not False:
        failures.append("b129:snapshot_broad_claim")
    if snapshot.get("automatic_remediation_claimed") is not False:
        failures.append("b129:snapshot_remediation_claim")
    if _product_evidence_digest(snapshot) != SOURCE_B128_PRODUCT_EVIDENCE_DIGEST:
        failures.append("b129:product_evidence_digest_mismatch")
    return failures


def _ui_failures(smoke: object) -> list[str]:
    if not isinstance(smoke, dict):
        return ["b129:ui_smoke_not_object"]
    failures: list[str] = []
    if smoke.get("passed") is not True:
        failures.append("b129:ui_smoke_failed")
    expected = {
        "page_count": 7,
        "scenario_card_count": 11,
        "capability_card_count": 7,
        "action_button_count": 0,
    }
    for field, value in expected.items():
        if smoke.get(field) != value:
            failures.append(f"b129:ui_{field}_invalid")
    if smoke.get("trust_center_selected") is not True:
        failures.append("b129:ui_trust_center_not_selected")
    if smoke.get("nav_enabled") is not True:
        failures.append("b129:ui_nav_disabled")
    overflow = smoke.get("horizontal_overflow")
    if not isinstance(overflow, dict) or set(overflow) != {"560", "680", "960", "1440"}:
        failures.append("b129:ui_width_inventory_invalid")
    elif any(int(value) != 0 for value in overflow.values()):
        failures.append("b129:ui_horizontal_overflow")
    return failures


def build_final_report(
    *,
    impact_report: object,
    product_snapshot: object,
    ui_smoke: object,
) -> dict[str, Any]:
    failures = [
        *validate_contract(contract()),
        *_impact_failures(impact_report),
        *_snapshot_failures(product_snapshot),
        *_ui_failures(ui_smoke),
    ]
    failures = list(dict.fromkeys(failures))

    metrics = (
        deepcopy(impact_report["operational_metrics"])
        if isinstance(impact_report, dict) and isinstance(impact_report.get("operational_metrics"), dict)
        else None
    )
    invariant_evidence = {
        "accepted_beta12_checkpoints": [
            {"checkpoint": checkpoint, "commit": commit}
            for checkpoint, commit in ACCEPTED_BETA12_CHECKPOINTS
        ],
        "coverage": FINAL_COVERAGE,
        "verified_scenarios": VERIFIED_SCENARIOS,
        "b127_contract_digest": SOURCE_B127_CONTRACT_DIGEST,
        "b128_contract_digest": SOURCE_B128_CONTRACT_DIGEST,
        "b128_product_evidence_digest": SOURCE_B128_PRODUCT_EVIDENCE_DIGEST,
        "impact_gates": {
            "false_positive": not any("false_positive" in item for item in failures),
            "outcome_stability": not any("outcome_drift" in item for item in failures),
            "performance": not any("budget_failed" in item for item in failures),
            "user_interruptions": not any("user_interruption" in item for item in failures),
        },
        "ui_inventory": {
            "page_count": 7,
            "scenario_card_count": 11,
            "capability_card_count": 7,
            "action_button_count": 0,
            "horizontal_overflow": {"560": 0, "680": 0, "960": 0, "1440": 0},
        },
        "authority_boundary": AUTHORITY_BOUNDARY,
    }

    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "passed": not failures,
        "failures": failures,
        "freeze_eligible": not failures,
        "freeze_state": "ELIGIBLE_AFTER_EXACT_CI_AND_LOCAL_ACCEPTANCE" if not failures else "BLOCKED",
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "accepted_checkpoint_count": len(ACCEPTED_BETA12_CHECKPOINTS),
        "coverage_summary": dict(FINAL_COVERAGE),
        "verified_scenarios": list(VERIFIED_SCENARIOS),
        "new_verified_scenario_earned": False,
        "operational_metrics": metrics,
        "scenario_count": 11,
        "capability_count": 7,
        "trust_center_page_count": 7,
        "trust_center_read_only": True,
        "trust_center_no_horizontal_overflow": not any(
            item == "b129:ui_horizontal_overflow" for item in failures
        ),
        "product_evidence_digest": SOURCE_B128_PRODUCT_EVIDENCE_DIGEST,
        "freeze_evidence_digest": _digest(invariant_evidence),
        "installer_execution_performed": False,
        "artifact_signing_performed": False,
        "release_publication_performed": False,
        "coverage_promoted": False,
        "authority_expanded": False,
        "network_required": False,
        "cloud_required": False,
    }


def self_check() -> dict[str, Any]:
    c = contract()
    failures = list(validate_contract(c))
    deterministic = c == contract() and _digest(c) == _digest(contract())
    if not deterministic:
        failures.append("b129:contract_not_deterministic")
    return {
        "passed": not failures,
        "failures": list(dict.fromkeys(failures)),
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "contract_digest": _digest(c),
        "deterministic_contract": deterministic,
        "accepted_checkpoint_count": len(ACCEPTED_BETA12_CHECKPOINTS),
        "coverage_summary": dict(FINAL_COVERAGE),
        "verified_scenarios": list(VERIFIED_SCENARIOS),
        "source_b127_contract_digest": SOURCE_B127_CONTRACT_DIGEST,
        "source_b128_contract_digest": SOURCE_B128_CONTRACT_DIGEST,
        "source_b128_product_evidence_digest": SOURCE_B128_PRODUCT_EVIDENCE_DIGEST,
        "new_verified_scenario_earned": False,
        "installer_execution_available": False,
        "artifact_signing_available": False,
        "release_publication_available": False,
        "coverage_promoted": False,
        "authority_expanded": False,
        "network_required": False,
        "cloud_required": False,
    }


def main() -> int:
    report = self_check()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

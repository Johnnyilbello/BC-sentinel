from __future__ import annotations

"""B14-4 Lab Test Orchestrator T0-T5.

This module plans and validates BC Sentinel lab campaigns. It does not execute,
store, transfer, unpack, download, or reconstruct malware. Real-sample tiers are
external-lab-only and their results must return through the accepted B14-3
sanitized evidence importer.

The orchestrator deliberately separates:
T0 harmless feature checks,
T1 safe adversary emulation,
T2 static authorized real-sample exposure without execution,
T3 dynamic authorized real-sample execution in an isolated disposable lab,
T4 benign/false-positive corpus,
T5 performance and resilience.
"""

import hashlib
import json
import re
from typing import Any, Final, Mapping

SCHEMA: Final[str] = "bc-sentinel-beta14-lab-test-orchestrator-v1"
PROFILE: Final[str] = "v0.14.0-b144-lab-test-orchestrator"
SOURCE_CHECKPOINT: Final[str] = "checkpoint/v014-b143-pass"
SOURCE_CHECKPOINT_COMMIT: Final[str] = "b807797b35e40dc34235c569e4f56b099824bca5"
SOURCE_COVERAGE: Final[dict[str, int]] = {"PARTIAL": 4, "GAP": 0, "VERIFIED": 7}

T0: Final[str] = "T0_HARMLESS_FEATURE_CHECKS"
T1: Final[str] = "T1_SAFE_ADVERSARY_EMULATION"
T2: Final[str] = "T2_STATIC_AUTHORIZED_REAL_SAMPLE"
T3: Final[str] = "T3_DYNAMIC_AUTHORIZED_REAL_SAMPLE"
T4: Final[str] = "T4_BENIGN_FALSE_POSITIVE_CORPUS"
T5: Final[str] = "T5_PERFORMANCE_RESILIENCE"

EXEC_SAFE_EXISTING: Final[str] = "EXTERNAL_EXISTING_SAFE_HARNESS"
EXEC_STATIC_LAB: Final[str] = "EXTERNAL_STATIC_QUARANTINE_LAB"
EXEC_DYNAMIC_LAB: Final[str] = "EXTERNAL_ISOLATED_DISPOSABLE_LAB"
EXEC_BENIGN: Final[str] = "EXTERNAL_BENIGN_CORPUS_HARNESS"
EXEC_PERF: Final[str] = "EXTERNAL_PERFORMANCE_HARNESS"

NETWORK_NONE: Final[str] = "NONE"
NETWORK_FAKE: Final[str] = "FAKE_SERVICES"
NETWORK_INETSIM: Final[str] = "INETSIM"

_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,160}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")

TIERS: Final[tuple[dict[str, Any], ...]] = (
    {
        "tier": T0,
        "description": "Harmless feature checks and standard non-malicious test artifacts.",
        "execution_mode": EXEC_SAFE_EXISTING,
        "real_sample": False,
        "real_sample_execution": False,
        "allowed_network_modes": (NETWORK_NONE,),
        "requires_isolated_disposable_lab": False,
        "requires_sample_authorization": False,
        "evidence_importer_required": True,
        "metrics": (
            "download_or_access_detection",
            "archive_handling",
            "pua_or_feature_check_behavior",
            "alerting",
            "quarantine_restore_if_supported",
        ),
    },
    {
        "tier": T1,
        "description": "Accepted safe adversary emulation using inert metadata and disposable safe fixtures.",
        "execution_mode": EXEC_SAFE_EXISTING,
        "real_sample": False,
        "real_sample_execution": False,
        "allowed_network_modes": (NETWORK_NONE,),
        "requires_isolated_disposable_lab": False,
        "requires_sample_authorization": False,
        "evidence_importer_required": True,
        "metrics": (
            "emulation_alert_rate",
            "administrative_review_rate",
            "benign_no_alert_rate",
            "detector_binding_coverage",
        ),
    },
    {
        "tier": T2,
        "description": "Authorized real malicious/PUA files exposed only to static/on-access/on-demand scanning; never executed.",
        "execution_mode": EXEC_STATIC_LAB,
        "real_sample": True,
        "real_sample_execution": False,
        "allowed_network_modes": (NETWORK_NONE,),
        "requires_isolated_disposable_lab": True,
        "requires_sample_authorization": True,
        "evidence_importer_required": True,
        "metrics": (
            "true_positive_rate_static",
            "false_negative_rate_static",
            "scan_latency",
            "archive_container_detection",
            "engine_stability",
        ),
    },
    {
        "tier": T3,
        "description": "Authorized real-sample dynamic execution only inside a separately isolated disposable lab.",
        "execution_mode": EXEC_DYNAMIC_LAB,
        "real_sample": True,
        "real_sample_execution": True,
        "allowed_network_modes": (NETWORK_NONE, NETWORK_FAKE, NETWORK_INETSIM),
        "requires_isolated_disposable_lab": True,
        "requires_sample_authorization": True,
        "evidence_importer_required": True,
        "metrics": (
            "prevention_rate",
            "behavior_detection_rate",
            "detection_latency",
            "process_file_correlation",
            "response_outcome",
            "cleanup_revert_success",
        ),
    },
    {
        "tier": T4,
        "description": "Large benign corpus and legitimate software workflow testing for false positives and usability.",
        "execution_mode": EXEC_BENIGN,
        "real_sample": False,
        "real_sample_execution": False,
        "allowed_network_modes": (NETWORK_NONE,),
        "requires_isolated_disposable_lab": False,
        "requires_sample_authorization": False,
        "evidence_importer_required": True,
        "metrics": (
            "false_positive_rate",
            "signed_software_false_positive_rate",
            "installer_compatibility",
            "application_usability",
        ),
    },
    {
        "tier": T5,
        "description": "Performance and resilience workloads with benign/synthetic inputs only.",
        "execution_mode": EXEC_PERF,
        "real_sample": False,
        "real_sample_execution": False,
        "allowed_network_modes": (NETWORK_NONE,),
        "requires_isolated_disposable_lab": False,
        "requires_sample_authorization": False,
        "evidence_importer_required": True,
        "metrics": (
            "cpu_impact",
            "memory_impact",
            "scan_throughput",
            "file_copy_impact",
            "application_launch_impact",
            "event_storm_resilience",
            "malformed_file_resilience",
            "nested_archive_resilience",
        ),
    },
)

TIER_BY_ID: Final[dict[str, dict[str, Any]]] = {str(item["tier"]): dict(item) for item in TIERS}

SAFETY_BOUNDARIES: Final[dict[str, bool]] = {
    "orchestrator_executes_samples": False,
    "orchestrator_downloads_samples": False,
    "orchestrator_stores_samples": False,
    "orchestrator_transfers_samples": False,
    "orchestrator_unpacks_samples": False,
    "orchestrator_opens_network_connections": False,
    "direct_internet_dynamic_lab_allowed": False,
    "coverage_promoted": False,
    "authority_expanded": False,
}


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _valid_id(value: object) -> bool:
    return isinstance(value, str) and bool(_ID_RE.fullmatch(value))


def _valid_commit(value: object) -> bool:
    return isinstance(value, str) and bool(_COMMIT_RE.fullmatch(value.lower()))


def tier_contract() -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "source_coverage": dict(SOURCE_COVERAGE),
        "tiers": [
            {
                **dict(item),
                "allowed_network_modes": list(item["allowed_network_modes"]),
                "metrics": list(item["metrics"]),
            }
            for item in TIERS
        ],
        "safety_boundaries": dict(SAFETY_BOUNDARIES),
    }


def make_plan(
    *,
    campaign_id: str,
    tier: str,
    engine_commit: str,
    engine_checkpoint: str,
    rule_version: str,
    network_mode: str,
    lab_profile: str,
    sample_authorized: bool = False,
    isolated_disposable_lab: bool = False,
) -> dict[str, Any]:
    spec = TIER_BY_ID[tier]
    material = {
        "campaign_id": campaign_id,
        "tier": tier,
        "engine_commit": engine_commit,
        "engine_checkpoint": engine_checkpoint,
        "rule_version": rule_version,
        "network_mode": network_mode,
        "lab_profile": lab_profile,
        "sample_authorized": bool(sample_authorized),
        "isolated_disposable_lab": bool(isolated_disposable_lab),
    }
    return {
        "schema": "bc-sentinel-beta14-lab-campaign-plan-v1",
        **material,
        "execution_mode": spec["execution_mode"],
        "real_sample": spec["real_sample"],
        "real_sample_execution": spec["real_sample_execution"],
        "evidence_importer_required": True,
        "coverage_promotion_allowed": False,
        "orchestrator_executes_workload": False,
        "plan_id": "b144:" + _digest(material)[:24],
    }


def validate_plan(plan: object) -> tuple[str, ...]:
    if not isinstance(plan, dict):
        return ("b144:plan_not_object",)

    required = {
        "schema",
        "campaign_id",
        "tier",
        "engine_commit",
        "engine_checkpoint",
        "rule_version",
        "network_mode",
        "lab_profile",
        "sample_authorized",
        "isolated_disposable_lab",
        "execution_mode",
        "real_sample",
        "real_sample_execution",
        "evidence_importer_required",
        "coverage_promotion_allowed",
        "orchestrator_executes_workload",
        "plan_id",
    }
    failures: list[str] = []
    if set(plan) != required:
        failures.append("b144:plan_fields_invalid")
    if plan.get("schema") != "bc-sentinel-beta14-lab-campaign-plan-v1":
        failures.append("b144:plan_schema_invalid")
    if not _valid_id(plan.get("campaign_id")):
        failures.append("b144:campaign_id_invalid")
    if not _valid_commit(plan.get("engine_commit")):
        failures.append("b144:engine_commit_invalid")
    if not isinstance(plan.get("engine_checkpoint"), str) or not plan["engine_checkpoint"].startswith("checkpoint/"):
        failures.append("b144:engine_checkpoint_invalid")
    if not _valid_id(plan.get("rule_version")):
        failures.append("b144:rule_version_invalid")
    if not _valid_id(plan.get("lab_profile")):
        failures.append("b144:lab_profile_invalid")
    if not isinstance(plan.get("sample_authorized"), bool):
        failures.append("b144:sample_authorized_invalid")
    if not isinstance(plan.get("isolated_disposable_lab"), bool):
        failures.append("b144:isolated_lab_flag_invalid")
    if plan.get("evidence_importer_required") is not True:
        failures.append("b144:evidence_importer_required")
    if plan.get("coverage_promotion_allowed") is not False:
        failures.append("b144:coverage_promotion_forbidden")
    if plan.get("orchestrator_executes_workload") is not False:
        failures.append("b144:orchestrator_execution_forbidden")
    if not isinstance(plan.get("plan_id"), str) or not str(plan["plan_id"]).startswith("b144:"):
        failures.append("b144:plan_id_invalid")

    tier = plan.get("tier")
    if tier not in TIER_BY_ID:
        return tuple(dict.fromkeys(failures + ["b144:tier_invalid"]))
    spec = TIER_BY_ID[str(tier)]

    if plan.get("execution_mode") != spec["execution_mode"]:
        failures.append("b144:execution_mode_invalid")
    if plan.get("real_sample") is not spec["real_sample"]:
        failures.append("b144:real_sample_flag_invalid")
    if plan.get("real_sample_execution") is not spec["real_sample_execution"]:
        failures.append("b144:real_sample_execution_flag_invalid")
    if plan.get("network_mode") not in spec["allowed_network_modes"]:
        failures.append("b144:network_mode_invalid")
    if spec["requires_sample_authorization"] and plan.get("sample_authorized") is not True:
        failures.append("b144:sample_authorization_required")
    if spec["requires_isolated_disposable_lab"] and plan.get("isolated_disposable_lab") is not True:
        failures.append("b144:isolated_disposable_lab_required")

    if tier == T3 and plan.get("network_mode") not in {NETWORK_NONE, NETWORK_FAKE, NETWORK_INETSIM}:
        failures.append("b144:dynamic_direct_internet_forbidden")
    if tier != T3 and plan.get("network_mode") != NETWORK_NONE:
        failures.append("b144:non_dynamic_network_forbidden")

    return tuple(dict.fromkeys(failures))


def campaign_summary(plan: Mapping[str, Any]) -> dict[str, Any]:
    failures = validate_plan(dict(plan))
    if failures:
        return {"passed": False, "failures": list(failures)}

    spec = TIER_BY_ID[str(plan["tier"])]
    return {
        "passed": True,
        "failures": [],
        "plan_id": plan["plan_id"],
        "campaign_id": plan["campaign_id"],
        "tier": plan["tier"],
        "execution_mode": plan["execution_mode"],
        "lab_profile": plan["lab_profile"],
        "network_mode": plan["network_mode"],
        "real_sample": plan["real_sample"],
        "real_sample_execution": plan["real_sample_execution"],
        "metrics": list(spec["metrics"]),
        "evidence_importer_required": True,
        "orchestrator_executes_workload": False,
        "coverage_promoted": False,
        "authority_expanded": False,
        "plan_digest": _digest(dict(plan)),
    }


def full_validation_campaign(
    *,
    engine_commit: str = SOURCE_CHECKPOINT_COMMIT,
    engine_checkpoint: str = SOURCE_CHECKPOINT,
    rule_version: str = "rules-b144-baseline",
) -> dict[str, Any]:
    plans = (
        make_plan(
            campaign_id="t0-safe-features",
            tier=T0,
            engine_commit=engine_commit,
            engine_checkpoint=engine_checkpoint,
            rule_version=rule_version,
            network_mode=NETWORK_NONE,
            lab_profile="safe-feature-lab",
        ),
        make_plan(
            campaign_id="t1-safe-emulation",
            tier=T1,
            engine_commit=engine_commit,
            engine_checkpoint=engine_checkpoint,
            rule_version=rule_version,
            network_mode=NETWORK_NONE,
            lab_profile="safe-emulation-lab",
        ),
        make_plan(
            campaign_id="t2-static-real-samples",
            tier=T2,
            engine_commit=engine_commit,
            engine_checkpoint=engine_checkpoint,
            rule_version=rule_version,
            network_mode=NETWORK_NONE,
            lab_profile="isolated-static-lab",
            sample_authorized=True,
            isolated_disposable_lab=True,
        ),
        make_plan(
            campaign_id="t3-dynamic-real-samples",
            tier=T3,
            engine_commit=engine_commit,
            engine_checkpoint=engine_checkpoint,
            rule_version=rule_version,
            network_mode=NETWORK_INETSIM,
            lab_profile="isolated-dynamic-lab",
            sample_authorized=True,
            isolated_disposable_lab=True,
        ),
        make_plan(
            campaign_id="t4-benign-corpus",
            tier=T4,
            engine_commit=engine_commit,
            engine_checkpoint=engine_checkpoint,
            rule_version=rule_version,
            network_mode=NETWORK_NONE,
            lab_profile="benign-corpus-lab",
        ),
        make_plan(
            campaign_id="t5-performance-resilience",
            tier=T5,
            engine_commit=engine_commit,
            engine_checkpoint=engine_checkpoint,
            rule_version=rule_version,
            network_mode=NETWORK_NONE,
            lab_profile="performance-lab",
        ),
    )

    summaries = [campaign_summary(plan) for plan in plans]
    failures = [
        f"plan[{index}]"
        for index, summary in enumerate(summaries)
        if summary.get("passed") is not True
    ]
    return {
        "schema": "bc-sentinel-beta14-full-validation-campaign-v1",
        "profile": PROFILE,
        "passed": not failures,
        "failures": failures,
        "plan_count": len(plans),
        "tier_count": len({plan["tier"] for plan in plans}),
        "plans": plans,
        "summaries": summaries,
        "real_sample_tiers": [T2, T3],
        "dynamic_real_sample_tiers": [T3],
        "evidence_importer_required_for_all": all(
            plan["evidence_importer_required"] for plan in plans
        ),
        "orchestrator_executes_workload": False,
        "coverage_promoted": False,
        "authority_expanded": False,
        "campaign_digest": _digest(plans),
    }


def self_check() -> dict[str, Any]:
    failures: list[str] = []
    campaign = full_validation_campaign()

    if campaign["passed"] is not True:
        failures.append("b144:baseline_campaign_failed")
    if campaign["plan_count"] != 6 or campaign["tier_count"] != 6:
        failures.append("b144:tier_inventory_invalid")
    if campaign["evidence_importer_required_for_all"] is not True:
        failures.append("b144:evidence_importer_not_required")

    unsafe = make_plan(
        campaign_id="unsafe-dynamic",
        tier=T3,
        engine_commit=SOURCE_CHECKPOINT_COMMIT,
        engine_checkpoint=SOURCE_CHECKPOINT,
        rule_version="rules-b144-baseline",
        network_mode=NETWORK_INETSIM,
        lab_profile="isolated-dynamic-lab",
        sample_authorized=True,
        isolated_disposable_lab=True,
    )
    unsafe["network_mode"] = "DIRECT_INTERNET"
    unsafe_failures = validate_plan(unsafe)
    if "b144:network_mode_invalid" not in unsafe_failures:
        failures.append("b144:direct_internet_not_rejected")

    unauthorized = make_plan(
        campaign_id="unauthorized-static",
        tier=T2,
        engine_commit=SOURCE_CHECKPOINT_COMMIT,
        engine_checkpoint=SOURCE_CHECKPOINT,
        rule_version="rules-b144-baseline",
        network_mode=NETWORK_NONE,
        lab_profile="isolated-static-lab",
        sample_authorized=False,
        isolated_disposable_lab=True,
    )
    if "b144:sample_authorization_required" not in validate_plan(unauthorized):
        failures.append("b144:unauthorized_real_sample_not_rejected")

    nonisolated = make_plan(
        campaign_id="nonisolated-dynamic",
        tier=T3,
        engine_commit=SOURCE_CHECKPOINT_COMMIT,
        engine_checkpoint=SOURCE_CHECKPOINT,
        rule_version="rules-b144-baseline",
        network_mode=NETWORK_NONE,
        lab_profile="isolated-dynamic-lab",
        sample_authorized=True,
        isolated_disposable_lab=False,
    )
    if "b144:isolated_disposable_lab_required" not in validate_plan(nonisolated):
        failures.append("b144:nonisolated_dynamic_not_rejected")

    contract_digest = _digest(tier_contract())
    deterministic = contract_digest == _digest(tier_contract())
    if not deterministic:
        failures.append("b144:contract_not_deterministic")

    return {
        "passed": not failures,
        "failures": list(dict.fromkeys(failures)),
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "source_coverage": dict(SOURCE_COVERAGE),
        "tier_count": 6,
        "plan_count": campaign["plan_count"],
        "real_sample_tiers": campaign["real_sample_tiers"],
        "dynamic_real_sample_tiers": campaign["dynamic_real_sample_tiers"],
        "direct_internet_rejected": True,
        "unauthorized_real_sample_rejected": True,
        "nonisolated_dynamic_rejected": True,
        "evidence_importer_required_for_all": True,
        "orchestrator_executes_samples": False,
        "orchestrator_downloads_samples": False,
        "orchestrator_stores_samples": False,
        "orchestrator_transfers_samples": False,
        "orchestrator_unpacks_samples": False,
        "orchestrator_opens_network_connections": False,
        "coverage_promoted": False,
        "authority_expanded": False,
        "contract_digest": contract_digest,
        "deterministic_contract": deterministic,
    }


def main() -> int:
    result = self_check()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

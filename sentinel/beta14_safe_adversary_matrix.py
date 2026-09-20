from __future__ import annotations

"""B14-1 Safe Adversary Emulation Matrix.

The matrix models multi-stage adversary-like behavior as inert metadata traces.
It never executes attack commands, mutates real persistence surfaces, touches
credentials, disables security controls, encrypts user data, propagates, or
performs network/C2 activity.

B14-1 is an emulation-quality milestone only. Synthetic/emulated evidence cannot
promote canonical detection coverage to VERIFIED.
"""

import hashlib
import json
from typing import Any, Final, Iterable, Mapping

SCHEMA: Final[str] = "bc-sentinel-beta14-safe-adversary-matrix-v1"
PROFILE: Final[str] = "v0.14.0-b141-safe-adversary-emulation-matrix"
SOURCE_CHECKPOINT: Final[str] = "checkpoint/v014-b140-pass"
SOURCE_CHECKPOINT_COMMIT: Final[str] = "a29de186a95d006b83fcb4e1c17992068b216255"
SOURCE_COVERAGE: Final[dict[str, int]] = {"PARTIAL": 4, "GAP": 0, "VERIFIED": 7}

OUTCOME_ALERT: Final[str] = "EMULATION_ALERT"
OUTCOME_REVIEW: Final[str] = "EMULATION_REVIEW"
OUTCOME_BENIGN: Final[str] = "EMULATION_BENIGN"

SAFETY_BOUNDARIES: Final[dict[str, bool]] = {
    "metadata_only": True,
    "harmless_fixtures_only": True,
    "disposable_workspace_model_only": True,
    "real_malware_execution": False,
    "real_data_encryption": False,
    "credential_access": False,
    "credential_material_collected": False,
    "network_io": False,
    "c2_activity": False,
    "propagation": False,
    "security_control_disabling": False,
    "real_registry_persistence": False,
    "real_startup_persistence": False,
    "scheduled_task_mutation": False,
    "service_driver_mutation": False,
    "privileged_system_mutation": False,
    "automatic_quarantine": False,
    "automatic_repair": False,
    "automatic_restore": False,
    "terminate_process_authority": False,
    "trust_allowlist_mutation": False,
    "coverage_promoted": False,
    "independent_certification_claimed": False,
}

SCENARIOS: Final[tuple[dict[str, Any], ...]] = (
    {
        "scenario_id": "B14-EMU-SCRIPT-CHAIN-001",
        "family": "SCRIPT_FILE_CHAIN",
        "label": "Script-like process to short file-mutation burst",
        "required_signals": (
            "SCRIPT_INTERPRETER_OBSERVED",
            "CHILD_PROCESS_OBSERVED",
            "FILE_MUTATION_BURST",
        ),
        "supporting_signals": ("UNKNOWN_LOCAL_REPUTATION",),
        "alert_threshold": 3,
    },
    {
        "scenario_id": "B14-EMU-PROCESS-TREE-001",
        "family": "PROCESS_ANCESTRY",
        "label": "Suspicious multi-stage process ancestry",
        "required_signals": (
            "PARENT_CHILD_CHAIN",
            "MULTI_STAGE_ANCESTRY",
            "UNCOMMON_CHILD_ROLE",
        ),
        "supporting_signals": ("UNKNOWN_LOCAL_REPUTATION",),
        "alert_threshold": 3,
    },
    {
        "scenario_id": "B14-EMU-PERSISTENCE-META-001",
        "family": "PERSISTENCE_METADATA",
        "label": "Persistence-like metadata without real persistence mutation",
        "required_signals": (
            "PERSISTENCE_LIKE_ARTIFACT",
            "USER_WRITABLE_TARGET",
            "AUTOSTART_INTENT_METADATA",
        ),
        "supporting_signals": ("ARGUMENT_METADATA_PRESENT",),
        "alert_threshold": 3,
    },
    {
        "scenario_id": "B14-EMU-RANSOMWARE-CHAIN-001",
        "family": "RANSOMWARE_LIKE_WORKSPACE",
        "label": "Disposable-workspace ransomware-like aggregate",
        "required_signals": (
            "RAPID_WRITE_BURST",
            "RENAME_BURST",
            "ENTROPY_CHANGE_SIMULATED",
        ),
        "supporting_signals": (
            "EXTENSION_CHANGE_SIMULATED",
            "CANARY_TOUCH_SIMULATED",
        ),
        "alert_threshold": 4,
    },
    {
        "scenario_id": "B14-EMU-REPUTATION-EDGE-001",
        "family": "LOCAL_REPUTATION",
        "label": "Unknown reputation plus suspicious behavior edge case",
        "required_signals": (
            "UNKNOWN_LOCAL_REPUTATION",
            "UNSIGNED_METADATA",
            "BEHAVIOR_SIGNAL_PRESENT",
        ),
        "supporting_signals": (),
        "alert_threshold": 3,
    },
    {
        "scenario_id": "B14-EMU-ARCHIVE-CHAIN-001",
        "family": "ARCHIVE_METADATA",
        "label": "Nested archive metadata leading to inert staged artifact",
        "required_signals": (
            "NESTED_ARCHIVE_DEPTH",
            "STAGED_ARTIFACT_METADATA",
            "UNKNOWN_LOCAL_REPUTATION",
        ),
        "supporting_signals": ("SCRIPT_LIKE_EXTENSION_METADATA",),
        "alert_threshold": 3,
    },
)

SCENARIO_BY_ID: Final[dict[str, dict[str, Any]]] = {
    str(item["scenario_id"]): dict(item) for item in SCENARIOS
}


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def matrix_contract() -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "source_coverage": dict(SOURCE_COVERAGE),
        "scenario_count": len(SCENARIOS),
        "scenarios": [
            {
                **dict(item),
                "required_signals": list(item["required_signals"]),
                "supporting_signals": list(item["supporting_signals"]),
            }
            for item in SCENARIOS
        ],
        "safety_boundaries": dict(SAFETY_BOUNDARIES),
    }


def make_trace(
    *,
    scenario_id: str,
    signals: Iterable[str],
    known_admin_or_user_workflow: bool = False,
    disposable_workspace: bool = True,
) -> dict[str, Any]:
    signal_list = sorted({str(item) for item in signals})
    material = {
        "scenario_id": scenario_id,
        "signals": signal_list,
        "known_admin_or_user_workflow": bool(known_admin_or_user_workflow),
        "disposable_workspace": bool(disposable_workspace),
    }
    return {
        "schema": "bc-sentinel-beta14-inert-trace-v1",
        **material,
        "trace_id": "b141:" + _digest(material)[:24],
        "real_execution": False,
        "real_network_activity": False,
        "real_persistence_mutation": False,
        "real_credential_access": False,
        "real_data_encryption": False,
    }


def validate_trace(trace: object) -> tuple[str, ...]:
    if not isinstance(trace, dict):
        return ("b141:trace_not_object",)

    expected_fields = {
        "schema",
        "scenario_id",
        "signals",
        "known_admin_or_user_workflow",
        "disposable_workspace",
        "trace_id",
        "real_execution",
        "real_network_activity",
        "real_persistence_mutation",
        "real_credential_access",
        "real_data_encryption",
    }
    failures: list[str] = []
    if set(trace) != expected_fields:
        failures.append("b141:trace_fields_invalid")
    if trace.get("schema") != "bc-sentinel-beta14-inert-trace-v1":
        failures.append("b141:trace_schema_invalid")
    scenario_id = trace.get("scenario_id")
    if scenario_id not in SCENARIO_BY_ID:
        failures.append("b141:scenario_unknown")
    signals = trace.get("signals")
    if (
        not isinstance(signals, list)
        or not all(isinstance(item, str) and item for item in signals)
        or signals != sorted(set(signals))
    ):
        failures.append("b141:signals_invalid")
    if not isinstance(trace.get("known_admin_or_user_workflow"), bool):
        failures.append("b141:suppressor_invalid")
    if trace.get("disposable_workspace") is not True:
        failures.append("b141:disposable_workspace_required")
    if not isinstance(trace.get("trace_id"), str) or not str(trace["trace_id"]).startswith("b141:"):
        failures.append("b141:trace_id_invalid")

    for field in (
        "real_execution",
        "real_network_activity",
        "real_persistence_mutation",
        "real_credential_access",
        "real_data_encryption",
    ):
        if trace.get(field) is not False:
            failures.append(f"b141:{field}_forbidden")

    return tuple(dict.fromkeys(failures))


def evaluate_trace(trace: Mapping[str, Any]) -> dict[str, Any]:
    failures = validate_trace(dict(trace))
    if failures:
        return {"passed": False, "failures": list(failures)}

    scenario = SCENARIO_BY_ID[str(trace["scenario_id"])]
    observed = set(str(item) for item in trace["signals"])
    required = set(str(item) for item in scenario["required_signals"])
    supporting = set(str(item) for item in scenario["supporting_signals"])

    required_hits = sorted(required & observed)
    supporting_hits = sorted(supporting & observed)
    missing_required = sorted(required - observed)
    score = len(required_hits) + len(supporting_hits)

    suppressor = bool(trace["known_admin_or_user_workflow"])
    threshold = int(scenario["alert_threshold"])
    if not missing_required and score >= threshold:
        outcome = OUTCOME_REVIEW if suppressor else OUTCOME_ALERT
    else:
        outcome = OUTCOME_BENIGN

    return {
        "passed": True,
        "failures": [],
        "trace_id": trace["trace_id"],
        "scenario_id": trace["scenario_id"],
        "family": scenario["family"],
        "outcome": outcome,
        "score": score,
        "threshold": threshold,
        "required_hits": required_hits,
        "supporting_hits": supporting_hits,
        "missing_required": missing_required,
        "suppressor": suppressor,
        "real_execution": False,
        "coverage_promoted": False,
    }


def acceptance_matrix() -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for scenario in SCENARIOS:
        required = list(scenario["required_signals"])
        supporting = list(scenario["supporting_signals"])

        positive = make_trace(
            scenario_id=str(scenario["scenario_id"]),
            signals=required + supporting,
        )
        administrative = make_trace(
            scenario_id=str(scenario["scenario_id"]),
            signals=required + supporting,
            known_admin_or_user_workflow=True,
        )
        benign = make_trace(
            scenario_id=str(scenario["scenario_id"]),
            signals=required[:-1],
        )

        rows.append({
            "scenario_id": scenario["scenario_id"],
            "positive": evaluate_trace(positive),
            "administrative": evaluate_trace(administrative),
            "benign": evaluate_trace(benign),
        })

    return {
        "schema": "bc-sentinel-beta14-safe-adversary-acceptance-v1",
        "profile": PROFILE,
        "scenario_count": len(rows),
        "rows": rows,
        "safety_boundaries": dict(SAFETY_BOUNDARIES),
        "source_coverage": dict(SOURCE_COVERAGE),
        "coverage_promoted": False,
    }


def self_check() -> dict[str, Any]:
    failures: list[str] = []
    contract = matrix_contract()
    matrix = acceptance_matrix()

    if contract["source_checkpoint"] != SOURCE_CHECKPOINT:
        failures.append("b141:source_checkpoint_invalid")
    if contract["source_checkpoint_commit"] != SOURCE_CHECKPOINT_COMMIT:
        failures.append("b141:source_commit_invalid")
    if contract["source_coverage"] != SOURCE_COVERAGE:
        failures.append("b141:coverage_changed")
    if contract["scenario_count"] != 6:
        failures.append("b141:scenario_count_invalid")

    if SAFETY_BOUNDARIES["metadata_only"] is not True:
        failures.append("b141:metadata_only_required")
    if SAFETY_BOUNDARIES["harmless_fixtures_only"] is not True:
        failures.append("b141:harmless_fixture_required")
    for key, value in SAFETY_BOUNDARIES.items():
        if key in {"metadata_only", "harmless_fixtures_only", "disposable_workspace_model_only"}:
            if value is not True:
                failures.append(f"b141:{key}_invalid")
        elif value is not False:
            failures.append(f"b141:{key}_unexpectedly_enabled")

    for row in matrix["rows"]:
        if row["positive"]["outcome"] != OUTCOME_ALERT:
            failures.append(f"b141:{row['scenario_id']}:positive_outcome")
        if row["administrative"]["outcome"] != OUTCOME_REVIEW:
            failures.append(f"b141:{row['scenario_id']}:administrative_outcome")
        if row["benign"]["outcome"] != OUTCOME_BENIGN:
            failures.append(f"b141:{row['scenario_id']}:benign_outcome")

    first_digest = _digest(contract)
    second_digest = _digest(matrix_contract())
    deterministic = first_digest == second_digest
    if not deterministic:
        failures.append("b141:contract_not_deterministic")

    return {
        "passed": not failures,
        "failures": list(dict.fromkeys(failures)),
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "source_coverage": dict(SOURCE_COVERAGE),
        "scenario_count": len(SCENARIOS),
        "control_count": len(SCENARIOS) * 3,
        "positive_alerts": sum(
            1 for row in matrix["rows"] if row["positive"]["outcome"] == OUTCOME_ALERT
        ),
        "administrative_reviews": sum(
            1 for row in matrix["rows"] if row["administrative"]["outcome"] == OUTCOME_REVIEW
        ),
        "benign_no_alerts": sum(
            1 for row in matrix["rows"] if row["benign"]["outcome"] == OUTCOME_BENIGN
        ),
        "real_malware_executed": False,
        "network_io": False,
        "credential_access": False,
        "real_persistence_mutation": False,
        "real_data_encryption": False,
        "coverage_promoted": False,
        "authority_expanded": False,
        "contract_digest": first_digest,
        "deterministic_contract": deterministic,
    }


def main() -> int:
    result = self_check()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

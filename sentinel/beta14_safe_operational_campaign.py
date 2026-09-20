from __future__ import annotations

"""B14-5 Safe Operational Campaign Evidence Bridge.

Consumes privacy-minimal summaries produced by already accepted harmless live
Windows controls and binds them into the B14-3 lab-evidence schema.

No malware is executed or handled. This milestone proves that the T0/T1
campaign can run end-to-end on Windows and return evidence through the same
import path that later isolated-lab tiers will use.
"""

import hashlib
import json
import re
from typing import Any, Final, Iterable, Mapping

from sentinel import beta14_lab_evidence_importer as b143

SCHEMA: Final[str] = "bc-sentinel-beta14-safe-operational-campaign-v1"
PROFILE: Final[str] = "v0.14.0-b145-safe-operational-campaign"
SOURCE_CHECKPOINT: Final[str] = "checkpoint/v014-b144-pass"
SOURCE_CHECKPOINT_COMMIT: Final[str] = "bbaec9bfbe52c43483054185501239351781d29a"
SOURCE_COVERAGE: Final[dict[str, int]] = {"PARTIAL": 4, "GAP": 0, "VERIFIED": 7}

T0: Final[str] = "T0_HARMLESS_FEATURE_CHECKS"
T1: Final[str] = "T1_SAFE_ADVERSARY_EMULATION"

CONTROL_SPECS: Final[tuple[dict[str, Any], ...]] = (
    {
        "control_id": "b145-script-abuse-live",
        "tier": T1,
        "scenario_id": "B12-SCRIPT-ABUSE-001",
        "source_module": "sentinel.beta12_script_abuse_controls",
        "detection_layer": "BEHAVIOR",
    },
    {
        "control_id": "b145-autostart-live",
        "tier": T1,
        "scenario_id": "B12-AUTOSTART-LINK-001",
        "source_module": "sentinel.beta12_autostart_detection",
        "detection_layer": "BEHAVIOR",
    },
    {
        "control_id": "b145-process-tree-live",
        "tier": T1,
        "scenario_id": "B12-PROCESS-TREE-001",
        "source_module": "sentinel.beta12_process_tree_intelligence",
        "detection_layer": "PROCESS_CORRELATION",
    },
    {
        "control_id": "b145-local-reputation-live",
        "tier": T0,
        "scenario_id": "B12-LOCAL-REPUTATION-001",
        "source_module": "sentinel.beta12_local_reputation",
        "detection_layer": "STATIC",
    },
    {
        "control_id": "b145-ransomware-like-live",
        "tier": T1,
        "scenario_id": "B7-RANSOMWARE-001",
        "source_module": "sentinel.beta9_ransomware_controls",
        "detection_layer": "RANSOMWARE_SHIELD",
    },
)

SPEC_BY_ID: Final[dict[str, dict[str, Any]]] = {
    str(item["control_id"]): dict(item) for item in CONTROL_SPECS
}

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_ALLOWED_TOP_FIELDS: Final[set[str]] = {
    "schema",
    "profile",
    "source_checkpoint",
    "source_checkpoint_commit",
    "controls",
    "boundaries",
}

BOUNDARIES: Final[dict[str, bool]] = {
    "harmless_live_controls_only": True,
    "disposable_temp_workspaces_only": True,
    "real_malware_executed": False,
    "real_sample_bytes_present": False,
    "network_io": False,
    "credential_access": False,
    "real_persistence_mutation": False,
    "security_control_impairment": False,
    "user_file_access": False,
    "coverage_promoted": False,
    "authority_expanded": False,
}


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _valid_sha256(value: object) -> bool:
    return isinstance(value, str) and bool(_SHA256_RE.fullmatch(value.lower()))


def campaign_contract() -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "controls": [dict(item) for item in CONTROL_SPECS],
        "boundaries": dict(BOUNDARIES),
    }


def make_control_result(
    *,
    control_id: str,
    evidence_digest: str,
    source_summary_digest: str,
    source_summary_passed: bool,
    cleanup_confirmed: bool,
) -> dict[str, Any]:
    spec = SPEC_BY_ID[control_id]
    return {
        "control_id": control_id,
        "tier": spec["tier"],
        "scenario_id": spec["scenario_id"],
        "source_module": spec["source_module"],
        "detection_layer": spec["detection_layer"],
        "evidence_digest": evidence_digest,
        "source_summary_digest": source_summary_digest,
        "source_summary_passed": bool(source_summary_passed),
        "live_windows_observation": True,
        "cleanup_confirmed": bool(cleanup_confirmed),
        "real_malware_executed": False,
        "network_io": False,
        "credential_access": False,
        "real_persistence_mutation": False,
        "security_control_impairment": False,
        "user_file_access": False,
    }


def validate_control_result(row: object) -> tuple[str, ...]:
    if not isinstance(row, dict):
        return ("b145:control_not_object",)
    expected = {
        "control_id",
        "tier",
        "scenario_id",
        "source_module",
        "detection_layer",
        "evidence_digest",
        "source_summary_digest",
        "source_summary_passed",
        "live_windows_observation",
        "cleanup_confirmed",
        "real_malware_executed",
        "network_io",
        "credential_access",
        "real_persistence_mutation",
        "security_control_impairment",
        "user_file_access",
    }
    failures: list[str] = []
    if set(row) != expected:
        failures.append("b145:control_fields_invalid")

    control_id = row.get("control_id")
    if control_id not in SPEC_BY_ID:
        return tuple(dict.fromkeys(failures + ["b145:control_unknown"]))
    spec = SPEC_BY_ID[str(control_id)]
    for key in ("tier", "scenario_id", "source_module", "detection_layer"):
        if row.get(key) != spec[key]:
            failures.append(f"b145:{control_id}:{key}_invalid")
    for field in ("evidence_digest", "source_summary_digest"):
        if not _valid_sha256(row.get(field)):
            failures.append(f"b145:{control_id}:{field}_invalid")
    if row.get("source_summary_passed") is not True:
        failures.append(f"b145:{control_id}:source_summary_failed")
    if row.get("live_windows_observation") is not True:
        failures.append(f"b145:{control_id}:live_observation_required")
    if row.get("cleanup_confirmed") is not True:
        failures.append(f"b145:{control_id}:cleanup_required")
    for field in (
        "real_malware_executed",
        "network_io",
        "credential_access",
        "real_persistence_mutation",
        "security_control_impairment",
        "user_file_access",
    ):
        if row.get(field) is not False:
            failures.append(f"b145:{control_id}:{field}_forbidden")
    return tuple(dict.fromkeys(failures))


def validate_campaign(data: object) -> tuple[str, ...]:
    if not isinstance(data, dict):
        return ("b145:not_object",)
    failures: list[str] = []
    if set(data) != _ALLOWED_TOP_FIELDS:
        failures.append("b145:top_fields_invalid")
    if data.get("schema") != SCHEMA:
        failures.append("b145:schema_invalid")
    if data.get("profile") != PROFILE:
        failures.append("b145:profile_invalid")
    if data.get("source_checkpoint") != SOURCE_CHECKPOINT:
        failures.append("b145:source_checkpoint_invalid")
    if data.get("source_checkpoint_commit") != SOURCE_CHECKPOINT_COMMIT:
        failures.append("b145:source_commit_invalid")
    if data.get("boundaries") != BOUNDARIES:
        failures.append("b145:boundaries_invalid")

    rows = data.get("controls")
    if not isinstance(rows, list) or len(rows) != len(CONTROL_SPECS):
        return tuple(dict.fromkeys(failures + ["b145:control_count_invalid"]))

    seen: set[str] = set()
    for index, row in enumerate(rows):
        row_failures = validate_control_result(row)
        failures.extend(f"control[{index}]:{item}" for item in row_failures)
        if isinstance(row, dict):
            control_id = str(row.get("control_id") or "")
            if control_id in seen:
                failures.append(f"control[{index}]:b145:duplicate_control")
            seen.add(control_id)
    if seen != set(SPEC_BY_ID):
        failures.append("b145:control_inventory_invalid")
    return tuple(dict.fromkeys(failures))


def build_import_records(data: Mapping[str, Any]) -> tuple[dict[str, Any], ...]:
    failures = validate_campaign(dict(data))
    if failures:
        raise ValueError("b145:invalid_campaign:" + ",".join(failures))

    records: list[dict[str, Any]] = []
    for row in data["controls"]:
        result = b143.RESULT_DETECTED
        record = {
            "schema": b143.SCHEMA,
            "run_id": str(row["control_id"]),
            "sample_id": "safe-live:" + str(row["scenario_id"]).lower(),
            "sample_sha256": str(row["evidence_digest"]),
            "sample_kind": b143.SAMPLE_TEST,
            "authorization_class": b143.AUTH_INTERNAL_SAFE,
            "sample_authorized": True,
            "environment_classification": b143.ENVIRONMENT_STATIC,
            "victim_snapshot_id": "safe-live-windows-host",
            "network_mode": b143.NETWORK_NONE,
            "engine_commit": SOURCE_CHECKPOINT_COMMIT,
            "engine_checkpoint": SOURCE_CHECKPOINT,
            "rule_version": "rules-b145-safe-operational",
            "pre_state_digest": str(row["source_summary_digest"]),
            "post_state_digest": _digest({
                "control_id": row["control_id"],
                "cleanup_confirmed": row["cleanup_confirmed"],
                "evidence_digest": row["evidence_digest"],
            }),
            "result": result,
            "detection_layer": str(row["detection_layer"]),
            "detection_latency_ms": 0.0,
            "evidence_ids": [
                "b145:" + str(row["control_id"]) + ":live",
                "b145:" + str(row["control_id"]) + ":summary",
            ],
            "quarantine_state": "NOT_APPLICABLE",
            "restore_state": "NOT_APPLICABLE",
            "cleanup_revert_confirmed": True,
            "real_sample_executed": False,
            "raw_sample_bytes_included": False,
            "raw_paths_included": False,
            "command_lines_included": False,
            "usernames_included": False,
            "credentials_included": False,
            "file_contents_included": False,
        }
        record_failures = b143.validate_record(record)
        if record_failures:
            raise ValueError(
                "b145:import_record_invalid:"
                + str(row["control_id"])
                + ":"
                + ",".join(record_failures)
            )
        records.append(record)
    return tuple(records)


def summarize(data: object) -> dict[str, Any]:
    failures = validate_campaign(data)
    if failures:
        return {"passed": False, "failures": list(failures)}
    assert isinstance(data, dict)

    records = build_import_records(data)
    imported = b143.import_batch(records)
    controls = data["controls"]
    t0_count = sum(1 for row in controls if row["tier"] == T0)
    t1_count = sum(1 for row in controls if row["tier"] == T1)

    passed = (
        imported["passed"] is True
        and imported["accepted_count"] == len(CONTROL_SPECS)
        and imported["authoritative_count"] == len(CONTROL_SPECS)
        and t0_count == 1
        and t1_count == 4
    )
    return {
        "passed": bool(passed),
        "failures": [] if passed else ["b145:operational_campaign_incomplete"],
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "source_coverage": dict(SOURCE_COVERAGE),
        "live_control_count": len(controls),
        "t0_control_count": t0_count,
        "t1_control_count": t1_count,
        "scenario_ids": [str(row["scenario_id"]) for row in controls],
        "b143_import_passed": imported["passed"],
        "b143_import_accepted_count": imported["accepted_count"],
        "b143_import_authoritative_count": imported["authoritative_count"],
        "campaign_digest": _digest(data),
        "import_batch_digest": imported["batch_digest"],
        "real_malware_executed": False,
        "network_io": False,
        "credential_access": False,
        "real_persistence_mutation": False,
        "security_control_impairment": False,
        "user_file_access": False,
        "coverage_promoted": False,
        "authority_expanded": False,
    }


def self_check() -> dict[str, Any]:
    controls = [
        make_control_result(
            control_id=str(spec["control_id"]),
            evidence_digest=_digest({"control": spec["control_id"], "evidence": True}),
            source_summary_digest=_digest({"control": spec["control_id"], "summary": True}),
            source_summary_passed=True,
            cleanup_confirmed=True,
        )
        for spec in CONTROL_SPECS
    ]
    fixture = {
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "controls": controls,
        "boundaries": dict(BOUNDARIES),
    }
    report = summarize(fixture)
    contract_digest = _digest(campaign_contract())
    deterministic = contract_digest == _digest(campaign_contract())
    failures = list(report.get("failures") or [])
    if not deterministic:
        failures.append("b145:contract_not_deterministic")
    return {
        **report,
        "passed": report.get("passed") is True and deterministic,
        "failures": failures,
        "contract_digest": contract_digest,
        "deterministic_contract": deterministic,
    }


def main() -> int:
    result = self_check()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

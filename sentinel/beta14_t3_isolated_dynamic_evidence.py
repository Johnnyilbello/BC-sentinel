from __future__ import annotations

"""B14-8 T3 Isolated Dynamic Evidence.

Consumes metadata-only evidence produced after an authorized real sample was
executed in the separately provisioned B14-6 disposable lab. This module does
not execute, download, store, transfer, unpack, reconstruct, or route samples.

Accepted T3 evidence must prove:
- isolated disposable lab execution,
- no direct Internet,
- one sample per clean snapshot/revert cycle,
- no escape or propagation beyond the guest,
- no real user data or host credentials exposed,
- no successful security-control impairment,
- sanitized evidence only,
- exact engine/rule/snapshot binding.

B14-8 measures dynamic protection quality but does not promote canonical
VERIFIED coverage or claim independent certification.
"""

import hashlib
import json
import re
from typing import Any, Final, Iterable, Mapping

from sentinel import beta14_lab_evidence_importer as b143

SCHEMA: Final[str] = "bc-sentinel-beta14-t3-isolated-dynamic-evidence-v1"
PROFILE: Final[str] = "v0.14.0-b148-t3-isolated-dynamic-evidence"
SOURCE_CHECKPOINT: Final[str] = "checkpoint/v014-b147-pass"
SOURCE_CHECKPOINT_COMMIT: Final[str] = "4b4bcb4d11ee1ac6847f1dba3a353f6976c959b2"
SOURCE_COVERAGE: Final[dict[str, int]] = {"PARTIAL": 4, "GAP": 0, "VERIFIED": 7}

RESULT_BLOCKED: Final[str] = "BLOCKED"
RESULT_DETECTED: Final[str] = "DETECTED"
RESULT_REVIEW: Final[str] = "REVIEW_REQUIRED"
RESULT_MISSED: Final[str] = "MISSED"
RESULT_ERROR: Final[str] = "ERROR"
ALLOWED_RESULTS: Final[set[str]] = {
    RESULT_BLOCKED,
    RESULT_DETECTED,
    RESULT_REVIEW,
    RESULT_MISSED,
    RESULT_ERROR,
}

ALLOWED_NETWORK_MODES: Final[set[str]] = {
    b143.NETWORK_NONE,
    b143.NETWORK_FAKE_SERVICES,
    b143.NETWORK_INETSIM,
}

ALLOWED_PRIMARY_LAYERS: Final[set[str]] = {
    "BEHAVIOR",
    "PROCESS_CORRELATION",
    "RANSOMWARE_SHIELD",
    "NETWORK_OBSERVATION",
    "RESPONSE",
    "ON_ACCESS",
    "STATIC",
    "NONE",
}

BEHAVIOR_PROCESS_TREE: Final[str] = "PROCESS_TREE"
BEHAVIOR_SCRIPT_ABUSE: Final[str] = "SCRIPT_ABUSE"
BEHAVIOR_FILE_MUTATION: Final[str] = "FILE_MUTATION"
BEHAVIOR_RANSOMWARE: Final[str] = "RANSOMWARE_LIKE"
BEHAVIOR_PERSISTENCE: Final[str] = "PERSISTENCE_ATTEMPT"
BEHAVIOR_NETWORK: Final[str] = "NETWORK_ATTEMPT"
BEHAVIOR_DEFENSE_EVASION: Final[str] = "DEFENSE_EVASION_ATTEMPT"
BEHAVIOR_MEMORY: Final[str] = "MEMORY_ACTIVITY"
BEHAVIOR_CREDENTIAL_ATTEMPT: Final[str] = "CREDENTIAL_ACCESS_ATTEMPT"
ALLOWED_BEHAVIORS: Final[set[str]] = {
    BEHAVIOR_PROCESS_TREE,
    BEHAVIOR_SCRIPT_ABUSE,
    BEHAVIOR_FILE_MUTATION,
    BEHAVIOR_RANSOMWARE,
    BEHAVIOR_PERSISTENCE,
    BEHAVIOR_NETWORK,
    BEHAVIOR_DEFENSE_EVASION,
    BEHAVIOR_MEMORY,
    BEHAVIOR_CREDENTIAL_ATTEMPT,
}

CATEGORY_RANSOMWARE: Final[str] = "RANSOMWARE"
CATEGORY_TROJAN: Final[str] = "TROJAN"
CATEGORY_INFOSTEALER: Final[str] = "INFOSTEALER"
CATEGORY_DOWNLOADER: Final[str] = "DOWNLOADER"
CATEGORY_BACKDOOR: Final[str] = "BACKDOOR"
CATEGORY_WORM: Final[str] = "WORM"
CATEGORY_FILE_INFECTOR: Final[str] = "FILE_INFECTOR"
CATEGORY_SCRIPT_MACRO: Final[str] = "SCRIPT_OR_MACRO"
CATEGORY_OTHER: Final[str] = "OTHER_MALWARE"
ALLOWED_CATEGORIES: Final[set[str]] = {
    CATEGORY_RANSOMWARE,
    CATEGORY_TROJAN,
    CATEGORY_INFOSTEALER,
    CATEGORY_DOWNLOADER,
    CATEGORY_BACKDOOR,
    CATEGORY_WORM,
    CATEGORY_FILE_INFECTOR,
    CATEGORY_SCRIPT_MACRO,
    CATEGORY_OTHER,
}

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,160}$")

_REQUIRED_FIELDS: Final[set[str]] = {
    "schema",
    "run_id",
    "sample_id",
    "sample_sha256",
    "malware_category",
    "authorization_class",
    "sample_authorized",
    "environment_classification",
    "isolated_lab_profile_id",
    "network_mode",
    "direct_internet_observed",
    "engine_commit",
    "engine_checkpoint",
    "rule_version",
    "victim_snapshot_id",
    "snapshot_revert_confirmed",
    "one_sample_cycle_confirmed",
    "result",
    "primary_detection_layer",
    "supporting_detection_layers",
    "detection_latency_ms",
    "execution_duration_ms",
    "observed_behaviors",
    "evidence_ids",
    "quarantine_state",
    "cleanup_revert_confirmed",
    "real_sample_executed",
    "propagation_beyond_guest",
    "host_escape_observed",
    "real_user_data_touched",
    "host_credentials_exposed",
    "credential_material_exported",
    "security_control_impairment_succeeded",
    "raw_sample_bytes_exported",
    "raw_paths_exported",
    "command_lines_exported",
    "usernames_exported",
    "credentials_exported",
    "file_contents_exported",
}

SAFETY_BOUNDARIES: Final[dict[str, bool]] = {
    "sample_execution_capability_in_module": False,
    "sample_download_capability_in_module": False,
    "sample_storage_capability_in_module": False,
    "sample_transfer_capability_in_module": False,
    "sample_unpack_capability_in_module": False,
    "network_route_creation_capability_in_module": False,
    "direct_internet_evidence_accepted": False,
    "host_escape_accepted": False,
    "propagation_beyond_guest_accepted": False,
    "real_user_data_touch_accepted": False,
    "credential_material_export_accepted": False,
    "security_control_impairment_success_accepted": False,
    "raw_sample_bytes_export_accepted": False,
    "coverage_promoted": False,
    "authority_expanded": False,
    "independent_certification_claimed": False,
}


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _valid_id(value: object) -> bool:
    return isinstance(value, str) and bool(_ID_RE.fullmatch(value))


def _valid_sha256(value: object) -> bool:
    return isinstance(value, str) and bool(_SHA256_RE.fullmatch(value.lower()))


def _valid_commit(value: object) -> bool:
    return isinstance(value, str) and bool(_COMMIT_RE.fullmatch(value.lower()))


def _valid_nonnegative_number(value: object) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and float(value) >= 0.0
    )


def validate_record(record: object) -> tuple[str, ...]:
    if not isinstance(record, dict):
        return ("b148:not_object",)

    failures: list[str] = []
    if set(record) != _REQUIRED_FIELDS:
        failures.append("b148:fields_invalid")
    if record.get("schema") != SCHEMA:
        failures.append("b148:schema_invalid")

    for field in (
        "run_id",
        "sample_id",
        "isolated_lab_profile_id",
        "rule_version",
        "victim_snapshot_id",
    ):
        if not _valid_id(record.get(field)):
            failures.append(f"b148:{field}_invalid")

    if not _valid_sha256(record.get("sample_sha256")):
        failures.append("b148:sample_sha256_invalid")
    if not _valid_commit(record.get("engine_commit")):
        failures.append("b148:engine_commit_invalid")
    if not isinstance(record.get("engine_checkpoint"), str) or not record["engine_checkpoint"].startswith("checkpoint/"):
        failures.append("b148:engine_checkpoint_invalid")

    if record.get("malware_category") not in ALLOWED_CATEGORIES:
        failures.append("b148:malware_category_invalid")
    if record.get("authorization_class") not in {
        b143.AUTH_APPROVED_RESEARCH,
        b143.AUTH_VENDOR_TEST,
    }:
        failures.append("b148:authorization_class_invalid")
    if record.get("sample_authorized") is not True:
        failures.append("b148:sample_authorization_required")
    if record.get("environment_classification") != b143.ENVIRONMENT_ISOLATED:
        failures.append("b148:isolated_environment_required")
    if record.get("network_mode") not in ALLOWED_NETWORK_MODES:
        failures.append("b148:network_mode_invalid")
    if record.get("direct_internet_observed") is not False:
        failures.append("b148:direct_internet_forbidden")
    if record.get("snapshot_revert_confirmed") is not True:
        failures.append("b148:snapshot_revert_required")
    if record.get("one_sample_cycle_confirmed") is not True:
        failures.append("b148:one_sample_cycle_required")
    if record.get("cleanup_revert_confirmed") is not True:
        failures.append("b148:cleanup_revert_required")
    if record.get("real_sample_executed") is not True:
        failures.append("b148:real_sample_execution_required")

    if record.get("result") not in ALLOWED_RESULTS:
        failures.append("b148:result_invalid")
    if record.get("primary_detection_layer") not in ALLOWED_PRIMARY_LAYERS:
        failures.append("b148:primary_detection_layer_invalid")

    supporting = record.get("supporting_detection_layers")
    if (
        not isinstance(supporting, list)
        or len(supporting) > 16
        or len(supporting) != len(set(supporting))
        or not all(item in ALLOWED_PRIMARY_LAYERS - {"NONE"} for item in supporting)
    ):
        failures.append("b148:supporting_detection_layers_invalid")

    behaviors = record.get("observed_behaviors")
    if (
        not isinstance(behaviors, list)
        or not behaviors
        or len(behaviors) > 32
        or len(behaviors) != len(set(behaviors))
        or not all(item in ALLOWED_BEHAVIORS for item in behaviors)
    ):
        failures.append("b148:observed_behaviors_invalid")

    if not _valid_nonnegative_number(record.get("detection_latency_ms")):
        failures.append("b148:detection_latency_invalid")
    if not _valid_nonnegative_number(record.get("execution_duration_ms")):
        failures.append("b148:execution_duration_invalid")

    evidence_ids = record.get("evidence_ids")
    if (
        not isinstance(evidence_ids, list)
        or not evidence_ids
        or len(evidence_ids) > 128
        or len(evidence_ids) != len(set(evidence_ids))
        or not all(_valid_id(item) for item in evidence_ids)
    ):
        failures.append("b148:evidence_ids_invalid")

    if record.get("quarantine_state") not in b143.QUARANTINE_STATES:
        failures.append("b148:quarantine_state_invalid")

    forbidden_true = (
        "propagation_beyond_guest",
        "host_escape_observed",
        "real_user_data_touched",
        "host_credentials_exposed",
        "credential_material_exported",
        "security_control_impairment_succeeded",
        "raw_sample_bytes_exported",
        "raw_paths_exported",
        "command_lines_exported",
        "usernames_exported",
        "credentials_exported",
        "file_contents_exported",
    )
    for field in forbidden_true:
        if record.get(field) is not False:
            failures.append(f"b148:{field}_forbidden")

    result = record.get("result")
    layer = record.get("primary_detection_layer")
    if result in {RESULT_BLOCKED, RESULT_DETECTED, RESULT_REVIEW} and layer == "NONE":
        failures.append("b148:detection_layer_required")
    if result in {RESULT_MISSED, RESULT_ERROR} and layer != "NONE":
        failures.append("b148:non_detection_layer_must_be_none")

    if record.get("quarantine_state") == "SUCCEEDED" and result not in {
        RESULT_BLOCKED,
        RESULT_DETECTED,
        RESULT_REVIEW,
    }:
        failures.append("b148:quarantine_without_detection")

    return tuple(dict.fromkeys(failures))


def to_b143_record(record: Mapping[str, Any]) -> dict[str, Any]:
    failures = validate_record(dict(record))
    if failures:
        raise ValueError("b148:invalid_record:" + ",".join(failures))

    result_map = {
        RESULT_BLOCKED: b143.RESULT_BLOCKED,
        RESULT_DETECTED: b143.RESULT_DETECTED,
        RESULT_REVIEW: b143.RESULT_REVIEW,
        RESULT_MISSED: b143.RESULT_MISSED,
        RESULT_ERROR: b143.RESULT_ERROR,
    }
    converted = {
        "schema": b143.SCHEMA,
        "run_id": record["run_id"],
        "sample_id": record["sample_id"],
        "sample_sha256": record["sample_sha256"],
        "sample_kind": b143.SAMPLE_MALWARE,
        "authorization_class": record["authorization_class"],
        "sample_authorized": True,
        "environment_classification": b143.ENVIRONMENT_ISOLATED,
        "victim_snapshot_id": record["victim_snapshot_id"],
        "network_mode": record["network_mode"],
        "engine_commit": record["engine_commit"],
        "engine_checkpoint": record["engine_checkpoint"],
        "rule_version": record["rule_version"],
        "pre_state_digest": _digest({
            "sample_sha256": record["sample_sha256"],
            "snapshot": record["victim_snapshot_id"],
            "network_mode": record["network_mode"],
        }),
        "post_state_digest": _digest({
            "run_id": record["run_id"],
            "result": record["result"],
            "cleanup_revert_confirmed": True,
            "behaviors": record["observed_behaviors"],
        }),
        "result": result_map[str(record["result"])],
        "detection_layer": record["primary_detection_layer"],
        "detection_latency_ms": float(record["detection_latency_ms"]),
        "evidence_ids": list(record["evidence_ids"]),
        "quarantine_state": record["quarantine_state"],
        "restore_state": "NOT_REQUESTED",
        "cleanup_revert_confirmed": True,
        "real_sample_executed": True,
        "raw_sample_bytes_included": False,
        "raw_paths_included": False,
        "command_lines_included": False,
        "usernames_included": False,
        "credentials_included": False,
        "file_contents_included": False,
    }
    b143_failures = b143.validate_record(converted)
    if b143_failures:
        raise ValueError("b148:b143_bridge_invalid:" + ",".join(b143_failures))
    return converted


def summarize_batch(records: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    items = [dict(item) for item in records]
    failures: list[str] = []
    accepted: list[dict[str, Any]] = []
    seen_runs: set[str] = set()
    seen_hashes: set[str] = set()

    if not items:
        failures.append("b148:batch_empty")

    for index, record in enumerate(items):
        record_failures = validate_record(record)
        if record_failures:
            failures.extend(f"record[{index}]:{item}" for item in record_failures)
            continue
        run_id = str(record["run_id"])
        sample_sha = str(record["sample_sha256"]).lower()
        if run_id in seen_runs:
            failures.append(f"record[{index}]:b148:duplicate_run_id")
            continue
        if sample_sha in seen_hashes:
            failures.append(f"record[{index}]:b148:duplicate_sample_sha256")
            continue
        seen_runs.add(run_id)
        seen_hashes.add(sample_sha)
        accepted.append(record)

    bridged_records: list[dict[str, Any]] = []
    if not failures:
        for record in accepted:
            try:
                bridged_records.append(to_b143_record(record))
            except ValueError as exc:
                failures.append(str(exc))

    bridged = b143.import_batch(bridged_records) if bridged_records else {
        "passed": False,
        "accepted_count": 0,
        "authoritative_count": 0,
        "batch_digest": _digest([]),
    }

    result_counts = {result: 0 for result in sorted(ALLOWED_RESULTS)}
    category_counts = {category: 0 for category in sorted(ALLOWED_CATEGORIES)}
    behavior_counts = {behavior: 0 for behavior in sorted(ALLOWED_BEHAVIORS)}
    network_counts = {mode: 0 for mode in sorted(ALLOWED_NETWORK_MODES)}
    latencies: list[float] = []
    durations: list[float] = []

    for record in accepted:
        result_counts[str(record["result"])] += 1
        category_counts[str(record["malware_category"])] += 1
        network_counts[str(record["network_mode"])] += 1
        for behavior in record["observed_behaviors"]:
            behavior_counts[str(behavior)] += 1
        latencies.append(float(record["detection_latency_ms"]))
        durations.append(float(record["execution_duration_ms"]))

    protected = result_counts[RESULT_BLOCKED] + result_counts[RESULT_DETECTED]
    missed = result_counts[RESULT_MISSED]
    denominator = protected + missed
    dynamic_protection_rate = (protected / denominator) if denominator else None
    review_rate = (
        result_counts[RESULT_REVIEW] / len(accepted)
        if accepted
        else None
    )
    mean_latency = (sum(latencies) / len(latencies)) if latencies else None
    mean_duration = (sum(durations) / len(durations)) if durations else None

    passed = (
        not failures
        and bridged.get("passed") is True
        and bridged.get("accepted_count") == len(accepted)
        and bridged.get("authoritative_count") == len(accepted)
    )

    return {
        "schema": "bc-sentinel-beta14-t3-dynamic-batch-v1",
        "profile": PROFILE,
        "passed": bool(passed),
        "failures": list(dict.fromkeys(failures)),
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "source_coverage": dict(SOURCE_COVERAGE),
        "sample_count": len(items),
        "accepted_count": len(accepted),
        "unique_sample_count": len(seen_hashes),
        "result_counts": result_counts,
        "category_counts": category_counts,
        "behavior_counts": behavior_counts,
        "network_mode_counts": network_counts,
        "dynamic_protection_rate": dynamic_protection_rate,
        "review_rate": review_rate,
        "mean_detection_latency_ms": mean_latency,
        "mean_execution_duration_ms": mean_duration,
        "b143_import_passed": bridged.get("passed") is True,
        "b143_import_accepted_count": int(bridged.get("accepted_count", 0)),
        "b143_import_authoritative_count": int(bridged.get("authoritative_count", 0)),
        "b143_batch_digest": bridged.get("batch_digest"),
        "direct_internet_observed": False,
        "propagation_beyond_guest": False,
        "host_escape_observed": False,
        "real_user_data_touched": False,
        "credential_material_exported": False,
        "security_control_impairment_succeeded": False,
        "raw_sample_bytes_imported": False,
        "coverage_promoted": False,
        "authority_expanded": False,
        "independent_certification_claimed": False,
        "batch_digest": _digest(accepted),
    }


def contract() -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "source_coverage": dict(SOURCE_COVERAGE),
        "allowed_results": sorted(ALLOWED_RESULTS),
        "allowed_network_modes": sorted(ALLOWED_NETWORK_MODES),
        "allowed_primary_layers": sorted(ALLOWED_PRIMARY_LAYERS),
        "allowed_behaviors": sorted(ALLOWED_BEHAVIORS),
        "allowed_categories": sorted(ALLOWED_CATEGORIES),
        "safety_boundaries": dict(SAFETY_BOUNDARIES),
    }


def _fixture(
    index: int,
    *,
    result: str,
    category: str,
    network_mode: str = b143.NETWORK_INETSIM,
) -> dict[str, Any]:
    if result == RESULT_BLOCKED:
        layer = "RANSOMWARE_SHIELD"
        behaviors = [BEHAVIOR_FILE_MUTATION, BEHAVIOR_RANSOMWARE]
    elif result == RESULT_DETECTED:
        layer = "BEHAVIOR"
        behaviors = [BEHAVIOR_PROCESS_TREE, BEHAVIOR_SCRIPT_ABUSE]
    elif result == RESULT_REVIEW:
        layer = "PROCESS_CORRELATION"
        behaviors = [BEHAVIOR_PROCESS_TREE, BEHAVIOR_PERSISTENCE]
    else:
        layer = "NONE"
        behaviors = [BEHAVIOR_PROCESS_TREE]

    return {
        "schema": SCHEMA,
        "run_id": f"b148-fixture-{index}",
        "sample_id": f"authorized-dynamic-malware-{index}",
        "sample_sha256": hashlib.sha256(f"b148-fixture-{index}".encode()).hexdigest(),
        "malware_category": category,
        "authorization_class": b143.AUTH_APPROVED_RESEARCH,
        "sample_authorized": True,
        "environment_classification": b143.ENVIRONMENT_ISOLATED,
        "isolated_lab_profile_id": "bc-sentinel-lab-b146",
        "network_mode": network_mode,
        "direct_internet_observed": False,
        "engine_commit": SOURCE_CHECKPOINT_COMMIT,
        "engine_checkpoint": SOURCE_CHECKPOINT,
        "rule_version": "rules-b148-fixture",
        "victim_snapshot_id": "win11-clean-b146",
        "snapshot_revert_confirmed": True,
        "one_sample_cycle_confirmed": True,
        "result": result,
        "primary_detection_layer": layer,
        "supporting_detection_layers": [] if layer == "NONE" else ["ON_ACCESS"],
        "detection_latency_ms": float(index * 10),
        "execution_duration_ms": float(index * 1000),
        "observed_behaviors": behaviors,
        "evidence_ids": [f"b148:evidence:{index}"],
        "quarantine_state": "NOT_REQUESTED",
        "cleanup_revert_confirmed": True,
        "real_sample_executed": True,
        "propagation_beyond_guest": False,
        "host_escape_observed": False,
        "real_user_data_touched": False,
        "host_credentials_exposed": False,
        "credential_material_exported": False,
        "security_control_impairment_succeeded": False,
        "raw_sample_bytes_exported": False,
        "raw_paths_exported": False,
        "command_lines_exported": False,
        "usernames_exported": False,
        "credentials_exported": False,
        "file_contents_exported": False,
    }


def self_check() -> dict[str, Any]:
    fixtures = (
        _fixture(1, result=RESULT_BLOCKED, category=CATEGORY_RANSOMWARE),
        _fixture(2, result=RESULT_DETECTED, category=CATEGORY_TROJAN),
        _fixture(3, result=RESULT_REVIEW, category=CATEGORY_BACKDOOR),
        _fixture(4, result=RESULT_MISSED, category=CATEGORY_INFOSTEALER),
        _fixture(5, result=RESULT_ERROR, category=CATEGORY_SCRIPT_MACRO),
    )
    report = summarize_batch(fixtures)
    failures = list(report.get("failures") or [])

    direct = dict(fixtures[0])
    direct["direct_internet_observed"] = True
    if "b148:direct_internet_forbidden" not in validate_record(direct):
        failures.append("b148:direct_internet_not_rejected")

    escape = dict(fixtures[0])
    escape["host_escape_observed"] = True
    if "b148:host_escape_observed_forbidden" not in validate_record(escape):
        failures.append("b148:host_escape_not_rejected")

    propagation = dict(fixtures[0])
    propagation["propagation_beyond_guest"] = True
    if "b148:propagation_beyond_guest_forbidden" not in validate_record(propagation):
        failures.append("b148:propagation_not_rejected")

    no_revert = dict(fixtures[0])
    no_revert["snapshot_revert_confirmed"] = False
    if "b148:snapshot_revert_required" not in validate_record(no_revert):
        failures.append("b148:no_revert_not_rejected")

    raw = dict(fixtures[0])
    raw["raw_sample_bytes_exported"] = True
    if "b148:raw_sample_bytes_exported_forbidden" not in validate_record(raw):
        failures.append("b148:raw_sample_not_rejected")

    contract_digest = _digest(contract())
    deterministic = contract_digest == _digest(contract())
    if not deterministic:
        failures.append("b148:contract_not_deterministic")

    return {
        **report,
        "passed": report.get("passed") is True and not failures,
        "failures": list(dict.fromkeys(failures)),
        "fixture_sample_count": len(fixtures),
        "direct_internet_rejected": True,
        "host_escape_rejected": True,
        "propagation_rejected": True,
        "missing_revert_rejected": True,
        "raw_sample_export_rejected": True,
        "sample_execution_capability_in_module": False,
        "sample_download_capability_in_module": False,
        "sample_storage_capability_in_module": False,
        "sample_transfer_capability_in_module": False,
        "sample_unpack_capability_in_module": False,
        "network_route_creation_capability_in_module": False,
        "contract_digest": contract_digest,
        "deterministic_contract": deterministic,
    }


def main() -> int:
    result = self_check()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())

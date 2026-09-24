from __future__ import annotations

"""B14-7 T2 Static Real-Sample Evidence Campaign.

Validates sanitized evidence from authorized real malicious samples that were
exposed to BC Sentinel only through static/on-demand/on-access scanning in the
isolated T2 laboratory. No sample may be executed.

This module never downloads, opens, stores, transfers, unpacks or reconstructs
sample bytes. It consumes metadata-only evidence packages emitted by the lab and
routes them through the already accepted B14-3 evidence policy.

B14-7 measures static detection quality. It does not promote canonical VERIFIED
coverage by itself and does not claim independent certification.
"""

import hashlib
import json
import math
import re
from typing import Any, Final, Iterable, Mapping

from sentinel import beta14_lab_evidence_importer as b143

SCHEMA: Final[str] = "bc-sentinel-beta14-t2-static-real-sample-evidence-v1"
PROFILE: Final[str] = "v0.14.0-b147-t2-static-real-sample-evidence"
SOURCE_CHECKPOINT: Final[str] = "checkpoint/v014-b146-pass"
SOURCE_CHECKPOINT_COMMIT: Final[str] = "98a702e178e8ef07da2c25751efcf5d1a7c2006f"
SOURCE_COVERAGE: Final[dict[str, int]] = {"PARTIAL": 4, "GAP": 0, "VERIFIED": 7}

RESULT_DETECTED: Final[str] = "DETECTED"
RESULT_MISSED: Final[str] = "MISSED"
RESULT_ERROR: Final[str] = "ERROR"
ALLOWED_RESULTS: Final[set[str]] = {RESULT_DETECTED, RESULT_MISSED, RESULT_ERROR}

MODE_STATIC: Final[str] = "STATIC"
MODE_ON_DEMAND: Final[str] = "ON_DEMAND"
MODE_ON_ACCESS: Final[str] = "ON_ACCESS"
ALLOWED_SCAN_MODES: Final[set[str]] = {MODE_STATIC, MODE_ON_DEMAND, MODE_ON_ACCESS}

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
    "engine_commit",
    "engine_checkpoint",
    "rule_version",
    "victim_snapshot_id",
    "scan_mode",
    "result",
    "detection_layer",
    "detection_latency_ms",
    "evidence_ids",
    "cleanup_revert_confirmed",
    "real_sample_executed",
    "raw_sample_bytes_exported",
    "raw_paths_exported",
    "command_lines_exported",
    "usernames_exported",
    "credentials_exported",
    "file_contents_exported",
}

SAFETY_BOUNDARIES: Final[dict[str, bool]] = {
    "sample_execution_allowed": False,
    "sample_download_capability": False,
    "sample_storage_capability": False,
    "sample_transfer_capability": False,
    "sample_unpack_capability": False,
    "network_io_allowed": False,
    "raw_sample_bytes_export_allowed": False,
    "sensitive_export_allowed": False,
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
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return False
    try:
        numeric = float(value)
    except (OverflowError, TypeError, ValueError):
        return False
    return math.isfinite(numeric) and numeric >= 0.0


def _valid_allowed_string(value: object, allowed: set[str]) -> bool:
    return isinstance(value, str) and value in allowed


def _valid_checkpoint(value: object) -> bool:
    return (
        isinstance(value, str)
        and value.startswith("checkpoint/")
        and 1 <= len(value) <= 200
        and "\x00" not in value
        and "\r" not in value
        and "\n" not in value
    )


def validate_record(record: object) -> tuple[str, ...]:
    if not isinstance(record, dict):
        return ("b147:not_object",)

    failures: list[str] = []
    if set(record) != _REQUIRED_FIELDS:
        failures.append("b147:fields_invalid")
    if record.get("schema") != SCHEMA:
        failures.append("b147:schema_invalid")

    for field in ("run_id", "sample_id", "isolated_lab_profile_id", "rule_version", "victim_snapshot_id"):
        if not _valid_id(record.get(field)):
            failures.append(f"b147:{field}_invalid")

    if not _valid_sha256(record.get("sample_sha256")):
        failures.append("b147:sample_sha256_invalid")
    if not _valid_commit(record.get("engine_commit")):
        failures.append("b147:engine_commit_invalid")
    if not _valid_checkpoint(record.get("engine_checkpoint")):
        failures.append("b147:engine_checkpoint_invalid")

    if not _valid_allowed_string(record.get("malware_category"), ALLOWED_CATEGORIES):
        failures.append("b147:malware_category_invalid")
    if not _valid_allowed_string(
        record.get("authorization_class"),
        {b143.AUTH_APPROVED_RESEARCH, b143.AUTH_VENDOR_TEST},
    ):
        failures.append("b147:authorization_class_invalid")
    if record.get("sample_authorized") is not True:
        failures.append("b147:sample_authorization_required")
    if record.get("environment_classification") != b143.ENVIRONMENT_STATIC:
        failures.append("b147:static_environment_required")
    if record.get("network_mode") != b143.NETWORK_NONE:
        failures.append("b147:network_must_be_none")
    if not _valid_allowed_string(record.get("scan_mode"), ALLOWED_SCAN_MODES):
        failures.append("b147:scan_mode_invalid")
    if not _valid_allowed_string(record.get("result"), ALLOWED_RESULTS):
        failures.append("b147:result_invalid")
    if not _valid_allowed_string(
        record.get("detection_layer"),
        {"STATIC", "ON_DEMAND", "ON_ACCESS", "NONE"},
    ):
        failures.append("b147:detection_layer_invalid")
    if not _valid_nonnegative_number(record.get("detection_latency_ms")):
        failures.append("b147:detection_latency_invalid")

    evidence_ids = record.get("evidence_ids")
    if (
        not isinstance(evidence_ids, list)
        or not evidence_ids
        or len(evidence_ids) > 64
        or not all(_valid_id(item) for item in evidence_ids)
        or len(evidence_ids) != len(set(evidence_ids))
    ):
        failures.append("b147:evidence_ids_invalid")

    if record.get("cleanup_revert_confirmed") is not True:
        failures.append("b147:cleanup_revert_required")
    if record.get("real_sample_executed") is not False:
        failures.append("b147:sample_execution_forbidden")

    for field in (
        "raw_sample_bytes_exported",
        "raw_paths_exported",
        "command_lines_exported",
        "usernames_exported",
        "credentials_exported",
        "file_contents_exported",
    ):
        if record.get(field) is not False:
            failures.append(f"b147:{field}_forbidden")

    result = record.get("result")
    detection_layer = record.get("detection_layer")
    if result == RESULT_DETECTED and detection_layer == "NONE":
        failures.append("b147:detection_layer_required")
    if (
        isinstance(result, str)
        and result in {RESULT_MISSED, RESULT_ERROR}
        and detection_layer != "NONE"
    ):
        failures.append("b147:non_detection_layer_must_be_none")

    return tuple(dict.fromkeys(failures))


def to_b143_record(record: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(record, Mapping):
        raise ValueError("b147:invalid_record:b147:not_object")
    try:
        material = dict(record)
    except (TypeError, ValueError):
        raise ValueError("b147:invalid_record:b147:not_object")
    failures = validate_record(material)
    if failures:
        raise ValueError("b147:invalid_record:" + ",".join(failures))

    result_map = {
        RESULT_DETECTED: b143.RESULT_DETECTED,
        RESULT_MISSED: b143.RESULT_MISSED,
        RESULT_ERROR: b143.RESULT_ERROR,
    }
    record = material
    detection_layer = str(record["detection_layer"])
    mapped_layer = detection_layer if detection_layer in b143.DETECTION_LAYERS else "STATIC"

    converted = {
        "schema": b143.SCHEMA,
        "run_id": record["run_id"],
        "sample_id": record["sample_id"],
        "sample_sha256": record["sample_sha256"],
        "sample_kind": b143.SAMPLE_MALWARE,
        "authorization_class": record["authorization_class"],
        "sample_authorized": True,
        "environment_classification": b143.ENVIRONMENT_STATIC,
        "victim_snapshot_id": record["victim_snapshot_id"],
        "network_mode": b143.NETWORK_NONE,
        "engine_commit": record["engine_commit"],
        "engine_checkpoint": record["engine_checkpoint"],
        "rule_version": record["rule_version"],
        "pre_state_digest": _digest({
            "sample_sha256": record["sample_sha256"],
            "snapshot": record["victim_snapshot_id"],
        }),
        "post_state_digest": _digest({
            "run_id": record["run_id"],
            "result": record["result"],
            "cleanup_revert_confirmed": True,
        }),
        "result": result_map[str(record["result"])],
        "detection_layer": mapped_layer,
        "detection_latency_ms": float(record["detection_latency_ms"]),
        "evidence_ids": list(record["evidence_ids"]),
        "quarantine_state": "NOT_REQUESTED",
        "restore_state": "NOT_REQUESTED",
        "cleanup_revert_confirmed": True,
        "real_sample_executed": False,
        "raw_sample_bytes_included": False,
        "raw_paths_included": False,
        "command_lines_included": False,
        "usernames_included": False,
        "credentials_included": False,
        "file_contents_included": False,
    }
    b143_failures = b143.validate_record(converted)
    if b143_failures:
        raise ValueError("b147:b143_bridge_invalid:" + ",".join(b143_failures))
    return converted


def summarize_batch(records: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    failures: list[str] = []
    parsed_items: list[tuple[int, dict[str, Any]]] = []
    try:
        raw_items = list(records)
    except (TypeError, ValueError, RuntimeError):
        raw_items = []
        failures.append("b147:batch_iterable_invalid")

    for index, item in enumerate(raw_items):
        if not isinstance(item, Mapping):
            failures.append(f"record[{index}]:b147:not_object")
            continue
        try:
            parsed_items.append((index, dict(item)))
        except (TypeError, ValueError):
            failures.append(f"record[{index}]:b147:not_object")
    accepted: list[dict[str, Any]] = []
    seen_hashes: set[str] = set()
    seen_run_ids: set[str] = set()

    if not raw_items:
        failures.append("b147:batch_empty")

    for index, record in parsed_items:
        record_failures = validate_record(record)
        if record_failures:
            failures.extend(f"record[{index}]:{item}" for item in record_failures)
            continue

        run_id = str(record["run_id"])
        sha = str(record["sample_sha256"]).lower()
        if run_id in seen_run_ids:
            failures.append(f"record[{index}]:b147:duplicate_run_id")
            continue
        if sha in seen_hashes:
            failures.append(f"record[{index}]:b147:duplicate_sample_sha256")
            continue
        seen_run_ids.add(run_id)
        seen_hashes.add(sha)
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

    counts = {result: 0 for result in sorted(ALLOWED_RESULTS)}
    category_counts = {category: 0 for category in sorted(ALLOWED_CATEGORIES)}
    latencies: list[float] = []
    for record in accepted:
        counts[str(record["result"])] += 1
        category_counts[str(record["malware_category"])] += 1
        latencies.append(float(record["detection_latency_ms"]))

    detected = counts[RESULT_DETECTED]
    missed = counts[RESULT_MISSED]
    denominator = detected + missed
    detection_rate = (detected / denominator) if denominator else None
    mean_latency = (sum(latencies) / len(latencies)) if latencies else None

    passed = (
        not failures
        and bridged.get("passed") is True
        and bridged.get("accepted_count") == len(accepted)
        and bridged.get("authoritative_count") == len(accepted)
    )

    return {
        "schema": "bc-sentinel-beta14-t2-static-batch-v1",
        "profile": PROFILE,
        "passed": bool(passed),
        "failures": list(dict.fromkeys(failures)),
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "source_coverage": dict(SOURCE_COVERAGE),
        "sample_count": len(raw_items),
        "accepted_count": len(accepted),
        "unique_sample_count": len(seen_hashes),
        "result_counts": counts,
        "category_counts": category_counts,
        "static_detection_rate": detection_rate,
        "mean_detection_latency_ms": mean_latency,
        "b143_import_passed": bridged.get("passed") is True,
        "b143_import_accepted_count": int(bridged.get("accepted_count", 0)),
        "b143_import_authoritative_count": int(bridged.get("authoritative_count", 0)),
        "b143_batch_digest": bridged.get("batch_digest"),
        "real_sample_executed": False,
        "network_io": False,
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
        "allowed_scan_modes": sorted(ALLOWED_SCAN_MODES),
        "allowed_results": sorted(ALLOWED_RESULTS),
        "allowed_categories": sorted(ALLOWED_CATEGORIES),
        "safety_boundaries": dict(SAFETY_BOUNDARIES),
    }


def _fixture(index: int, *, result: str, category: str) -> dict[str, Any]:
    layer = "STATIC" if result == RESULT_DETECTED else "NONE"
    return {
        "schema": SCHEMA,
        "run_id": f"b147-fixture-{index}",
        "sample_id": f"authorized-malware-{index}",
        "sample_sha256": hashlib.sha256(f"fixture-{index}".encode()).hexdigest(),
        "malware_category": category,
        "authorization_class": b143.AUTH_APPROVED_RESEARCH,
        "sample_authorized": True,
        "environment_classification": b143.ENVIRONMENT_STATIC,
        "isolated_lab_profile_id": "bc-sentinel-lab-b146",
        "network_mode": b143.NETWORK_NONE,
        "engine_commit": SOURCE_CHECKPOINT_COMMIT,
        "engine_checkpoint": SOURCE_CHECKPOINT,
        "rule_version": "rules-b147-fixture",
        "victim_snapshot_id": "win11-clean-b146",
        "scan_mode": MODE_STATIC,
        "result": result,
        "detection_layer": layer,
        "detection_latency_ms": float(index + 1),
        "evidence_ids": [f"b147:evidence:{index}"],
        "cleanup_revert_confirmed": True,
        "real_sample_executed": False,
        "raw_sample_bytes_exported": False,
        "raw_paths_exported": False,
        "command_lines_exported": False,
        "usernames_exported": False,
        "credentials_exported": False,
        "file_contents_exported": False,
    }


def self_check() -> dict[str, Any]:
    fixtures = (
        _fixture(1, result=RESULT_DETECTED, category=CATEGORY_RANSOMWARE),
        _fixture(2, result=RESULT_DETECTED, category=CATEGORY_TROJAN),
        _fixture(3, result=RESULT_MISSED, category=CATEGORY_INFOSTEALER),
        _fixture(4, result=RESULT_ERROR, category=CATEGORY_SCRIPT_MACRO),
    )
    report = summarize_batch(fixtures)
    failures = list(report.get("failures") or [])

    unsafe = dict(fixtures[0])
    unsafe["real_sample_executed"] = True
    if "b147:sample_execution_forbidden" not in validate_record(unsafe):
        failures.append("b147:execution_not_rejected")

    networked = dict(fixtures[0])
    networked["network_mode"] = b143.NETWORK_INETSIM
    if "b147:network_must_be_none" not in validate_record(networked):
        failures.append("b147:network_not_rejected")

    raw = dict(fixtures[0])
    raw["raw_sample_bytes_exported"] = True
    if "b147:raw_sample_bytes_exported_forbidden" not in validate_record(raw):
        failures.append("b147:raw_sample_not_rejected")

    contract_digest = _digest(contract())
    deterministic = contract_digest == _digest(contract())
    if not deterministic:
        failures.append("b147:contract_not_deterministic")

    return {
        **report,
        "passed": report.get("passed") is True and not failures,
        "failures": list(dict.fromkeys(failures)),
        "fixture_sample_count": len(fixtures),
        "sample_execution_rejected": True,
        "network_rejected": True,
        "raw_sample_export_rejected": True,
        "sample_download_capability": False,
        "sample_storage_capability": False,
        "sample_transfer_capability": False,
        "sample_unpack_capability": False,
        "contract_digest": contract_digest,
        "deterministic_contract": deterministic,
    }


def main() -> int:
    result = self_check()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())

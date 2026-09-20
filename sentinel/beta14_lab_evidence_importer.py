from __future__ import annotations

"""B14-3 Isolated Lab Evidence Importer.

Accepts sanitized evidence emitted by a separately authorized isolated malware
lab. This module never executes, stores, transfers, unpacks or reconstructs a
sample. It validates run provenance and produces privacy-minimal summaries.

Real-malware evidence is authoritative only when it is bound to:
- an isolated disposable lab environment,
- an approved sample authorization class,
- a non-Internet network mode,
- an immutable victim snapshot,
- exact engine/rule identities,
- pre/post state digests, and
- confirmed cleanup/revert.

B14-3 does not promote canonical detection coverage by itself.
"""

import hashlib
import json
import re
from typing import Any, Final, Iterable, Mapping

SCHEMA: Final[str] = "bc-sentinel-beta14-isolated-lab-evidence-v1"
BATCH_SCHEMA: Final[str] = "bc-sentinel-beta14-isolated-lab-batch-v1"
PROFILE: Final[str] = "v0.14.0-b143-isolated-lab-evidence-importer"
SOURCE_CHECKPOINT: Final[str] = "checkpoint/v014-b142-pass"
SOURCE_CHECKPOINT_COMMIT: Final[str] = "346f3d2ffb61db09437d82c3762991b3c25c45b7"
SOURCE_COVERAGE: Final[dict[str, int]] = {"PARTIAL": 4, "GAP": 0, "VERIFIED": 7}

ENVIRONMENT_ISOLATED: Final[str] = "ISOLATED_DISPOSABLE_LAB"
ENVIRONMENT_STATIC: Final[str] = "STATIC_QUARANTINE_ONLY"
ALLOWED_ENVIRONMENTS: Final[set[str]] = {ENVIRONMENT_ISOLATED, ENVIRONMENT_STATIC}

NETWORK_NONE: Final[str] = "NONE"
NETWORK_FAKE_SERVICES: Final[str] = "FAKE_SERVICES"
NETWORK_INETSIM: Final[str] = "INETSIM"
ALLOWED_NETWORK_MODES: Final[set[str]] = {
    NETWORK_NONE,
    NETWORK_FAKE_SERVICES,
    NETWORK_INETSIM,
}

SAMPLE_MALWARE: Final[str] = "MALWARE"
SAMPLE_PUA: Final[str] = "PUA"
SAMPLE_BENIGN: Final[str] = "BENIGN"
SAMPLE_TEST: Final[str] = "TEST_ARTIFACT"
ALLOWED_SAMPLE_KINDS: Final[set[str]] = {
    SAMPLE_MALWARE,
    SAMPLE_PUA,
    SAMPLE_BENIGN,
    SAMPLE_TEST,
}

AUTH_APPROVED_RESEARCH: Final[str] = "APPROVED_RESEARCH"
AUTH_VENDOR_TEST: Final[str] = "VENDOR_OR_LAB_TEST"
AUTH_INTERNAL_SAFE: Final[str] = "INTERNAL_SAFE_ARTIFACT"
ALLOWED_AUTHORIZATION_CLASSES: Final[set[str]] = {
    AUTH_APPROVED_RESEARCH,
    AUTH_VENDOR_TEST,
    AUTH_INTERNAL_SAFE,
}

RESULT_BLOCKED: Final[str] = "BLOCKED"
RESULT_DETECTED: Final[str] = "DETECTED"
RESULT_REVIEW: Final[str] = "REVIEW_REQUIRED"
RESULT_MISSED: Final[str] = "MISSED"
RESULT_ERROR: Final[str] = "ERROR"
RESULT_CLEAN: Final[str] = "CLEAN"
ALLOWED_RESULTS: Final[set[str]] = {
    RESULT_BLOCKED,
    RESULT_DETECTED,
    RESULT_REVIEW,
    RESULT_MISSED,
    RESULT_ERROR,
    RESULT_CLEAN,
}

DETECTION_LAYERS: Final[set[str]] = {
    "STATIC",
    "ON_ACCESS",
    "ON_DEMAND",
    "BEHAVIOR",
    "PROCESS_CORRELATION",
    "RANSOMWARE_SHIELD",
    "NETWORK_OBSERVATION",
    "RESPONSE",
    "NONE",
}

QUARANTINE_STATES: Final[set[str]] = {
    "NOT_REQUESTED",
    "NOT_APPLICABLE",
    "SUCCEEDED",
    "FAILED",
}
RESTORE_STATES: Final[set[str]] = {
    "NOT_REQUESTED",
    "NOT_APPLICABLE",
    "SUCCEEDED",
    "FAILED",
}

_REQUIRED_FIELDS: Final[set[str]] = {
    "schema",
    "run_id",
    "sample_id",
    "sample_sha256",
    "sample_kind",
    "authorization_class",
    "sample_authorized",
    "environment_classification",
    "victim_snapshot_id",
    "network_mode",
    "engine_commit",
    "engine_checkpoint",
    "rule_version",
    "pre_state_digest",
    "post_state_digest",
    "result",
    "detection_layer",
    "detection_latency_ms",
    "evidence_ids",
    "quarantine_state",
    "restore_state",
    "cleanup_revert_confirmed",
    "real_sample_executed",
    "raw_sample_bytes_included",
    "raw_paths_included",
    "command_lines_included",
    "usernames_included",
    "credentials_included",
    "file_contents_included",
}

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,160}$")

SAFETY_BOUNDARIES: Final[dict[str, bool]] = {
    "sample_execution_capability_in_importer": False,
    "sample_storage_capability_in_importer": False,
    "sample_transfer_capability_in_importer": False,
    "sample_unpack_capability_in_importer": False,
    "direct_internet_lab_mode_accepted": False,
    "raw_sample_bytes_accepted": False,
    "raw_paths_accepted": False,
    "command_lines_accepted": False,
    "usernames_accepted": False,
    "credentials_accepted": False,
    "file_contents_accepted": False,
    "coverage_promoted": False,
    "authority_expanded": False,
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
        return ("b143:not_object",)

    failures: list[str] = []
    if set(record) != _REQUIRED_FIELDS:
        failures.append("b143:fields_invalid")
    if record.get("schema") != SCHEMA:
        failures.append("b143:schema_invalid")

    for field in ("run_id", "sample_id", "victim_snapshot_id", "rule_version"):
        if not _valid_id(record.get(field)):
            failures.append(f"b143:{field}_invalid")

    if not _valid_sha256(record.get("sample_sha256")):
        failures.append("b143:sample_sha256_invalid")
    if not _valid_sha256(record.get("pre_state_digest")):
        failures.append("b143:pre_state_digest_invalid")
    if not _valid_sha256(record.get("post_state_digest")):
        failures.append("b143:post_state_digest_invalid")
    if not _valid_commit(record.get("engine_commit")):
        failures.append("b143:engine_commit_invalid")

    if not isinstance(record.get("engine_checkpoint"), str) or not record["engine_checkpoint"].startswith("checkpoint/"):
        failures.append("b143:engine_checkpoint_invalid")
    if record.get("sample_kind") not in ALLOWED_SAMPLE_KINDS:
        failures.append("b143:sample_kind_invalid")
    if record.get("authorization_class") not in ALLOWED_AUTHORIZATION_CLASSES:
        failures.append("b143:authorization_class_invalid")
    if record.get("environment_classification") not in ALLOWED_ENVIRONMENTS:
        failures.append("b143:environment_invalid")
    if record.get("network_mode") not in ALLOWED_NETWORK_MODES:
        failures.append("b143:network_mode_invalid")
    if record.get("result") not in ALLOWED_RESULTS:
        failures.append("b143:result_invalid")
    if record.get("detection_layer") not in DETECTION_LAYERS:
        failures.append("b143:detection_layer_invalid")
    if record.get("quarantine_state") not in QUARANTINE_STATES:
        failures.append("b143:quarantine_state_invalid")
    if record.get("restore_state") not in RESTORE_STATES:
        failures.append("b143:restore_state_invalid")
    if not _valid_nonnegative_number(record.get("detection_latency_ms")):
        failures.append("b143:detection_latency_invalid")

    evidence_ids = record.get("evidence_ids")
    if (
        not isinstance(evidence_ids, list)
        or not evidence_ids
        or len(evidence_ids) > 128
        or not all(_valid_id(item) for item in evidence_ids)
        or len(evidence_ids) != len(set(evidence_ids))
    ):
        failures.append("b143:evidence_ids_invalid")

    if record.get("sample_authorized") is not True:
        failures.append("b143:sample_authorization_required")
    if record.get("cleanup_revert_confirmed") is not True:
        failures.append("b143:cleanup_revert_required")

    privacy_false = (
        "raw_sample_bytes_included",
        "raw_paths_included",
        "command_lines_included",
        "usernames_included",
        "credentials_included",
        "file_contents_included",
    )
    for field in privacy_false:
        if record.get(field) is not False:
            failures.append(f"b143:{field}_forbidden")

    real_sample = bool(record.get("real_sample_executed"))
    sample_kind = record.get("sample_kind")
    environment = record.get("environment_classification")

    if real_sample:
        if sample_kind not in {SAMPLE_MALWARE, SAMPLE_PUA}:
            failures.append("b143:real_sample_kind_invalid")
        if environment != ENVIRONMENT_ISOLATED:
            failures.append("b143:real_sample_requires_isolated_lab")
        if record.get("authorization_class") not in {
            AUTH_APPROVED_RESEARCH,
            AUTH_VENDOR_TEST,
        }:
            failures.append("b143:real_sample_authorization_class_invalid")
    elif environment == ENVIRONMENT_STATIC and record.get("result") == RESULT_CLEAN and sample_kind == SAMPLE_MALWARE:
        # Static analysis may legitimately miss a malicious sample, but CLEAN is
        # too ambiguous for the importer. Require MISSED instead.
        failures.append("b143:malware_static_clean_must_be_missed")

    if record.get("result") in {RESULT_BLOCKED, RESULT_DETECTED, RESULT_REVIEW} and record.get("detection_layer") == "NONE":
        failures.append("b143:detection_layer_required")
    if record.get("result") in {RESULT_MISSED, RESULT_CLEAN} and record.get("detection_layer") != "NONE":
        failures.append("b143:non_detection_layer_must_be_none")

    if record.get("quarantine_state") == "SUCCEEDED" and record.get("result") not in {
        RESULT_BLOCKED,
        RESULT_DETECTED,
        RESULT_REVIEW,
    }:
        failures.append("b143:quarantine_without_detection")

    return tuple(dict.fromkeys(failures))


def evidence_digest(record: Mapping[str, Any]) -> str:
    failures = validate_record(dict(record))
    if failures:
        raise ValueError("b143:invalid_record:" + ",".join(failures))
    return _digest(dict(record))


def authoritative_for_internal_lab(record: Mapping[str, Any]) -> bool:
    failures = validate_record(dict(record))
    if failures:
        return False
    if record["sample_kind"] in {SAMPLE_MALWARE, SAMPLE_PUA}:
        if record["environment_classification"] == ENVIRONMENT_ISOLATED:
            return True
        if record["environment_classification"] == ENVIRONMENT_STATIC and record["real_sample_executed"] is False:
            return True
        return False
    return True


def sanitized_summary(record: Mapping[str, Any]) -> dict[str, Any]:
    failures = validate_record(dict(record))
    if failures:
        return {"passed": False, "failures": list(failures)}

    return {
        "passed": True,
        "failures": [],
        "run_id": record["run_id"],
        "sample_id": record["sample_id"],
        "sample_sha256": record["sample_sha256"],
        "sample_kind": record["sample_kind"],
        "authorization_class": record["authorization_class"],
        "environment_classification": record["environment_classification"],
        "network_mode": record["network_mode"],
        "engine_commit": record["engine_commit"],
        "engine_checkpoint": record["engine_checkpoint"],
        "rule_version": record["rule_version"],
        "victim_snapshot_id": record["victim_snapshot_id"],
        "result": record["result"],
        "detection_layer": record["detection_layer"],
        "detection_latency_ms": float(record["detection_latency_ms"]),
        "evidence_count": len(record["evidence_ids"]),
        "quarantine_state": record["quarantine_state"],
        "restore_state": record["restore_state"],
        "cleanup_revert_confirmed": True,
        "real_sample_executed": bool(record["real_sample_executed"]),
        "authoritative_internal_lab_evidence": authoritative_for_internal_lab(record),
        "evidence_digest": evidence_digest(record),
        "privacy_minimal": True,
        "coverage_promoted": False,
        "authority_expanded": False,
    }


def import_batch(records: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    items = [dict(item) for item in records]
    failures: list[str] = []
    summaries: list[dict[str, Any]] = []
    seen_run_ids: set[str] = set()

    if not items:
        failures.append("b143:batch_empty")

    for index, record in enumerate(items):
        record_failures = validate_record(record)
        if record_failures:
            failures.extend(f"record[{index}]:{item}" for item in record_failures)
            continue
        run_id = str(record["run_id"])
        if run_id in seen_run_ids:
            failures.append(f"record[{index}]:b143:duplicate_run_id")
            continue
        seen_run_ids.add(run_id)
        summary = sanitized_summary(record)
        if summary.get("passed") is not True:
            failures.append(f"record[{index}]:b143:summary_failed")
            continue
        summaries.append(summary)

    counts = {result: 0 for result in sorted(ALLOWED_RESULTS)}
    for summary in summaries:
        counts[str(summary["result"])] += 1

    return {
        "schema": BATCH_SCHEMA,
        "profile": PROFILE,
        "passed": not failures,
        "failures": list(dict.fromkeys(failures)),
        "record_count": len(items),
        "accepted_count": len(summaries),
        "authoritative_count": sum(
            1 for item in summaries if item["authoritative_internal_lab_evidence"]
        ),
        "result_counts": counts,
        "summaries": summaries,
        "coverage_promoted": False,
        "authority_expanded": False,
        "sample_bytes_imported": False,
        "batch_digest": _digest(summaries),
    }


def contract() -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "source_coverage": dict(SOURCE_COVERAGE),
        "allowed_environments": sorted(ALLOWED_ENVIRONMENTS),
        "allowed_network_modes": sorted(ALLOWED_NETWORK_MODES),
        "allowed_sample_kinds": sorted(ALLOWED_SAMPLE_KINDS),
        "allowed_authorization_classes": sorted(ALLOWED_AUTHORIZATION_CLASSES),
        "allowed_results": sorted(ALLOWED_RESULTS),
        "detection_layers": sorted(DETECTION_LAYERS),
        "safety_boundaries": dict(SAFETY_BOUNDARIES),
    }


def _fixture(
    *,
    run_id: str,
    sample_id: str,
    sample_sha256: str,
    sample_kind: str,
    environment: str,
    result: str,
    layer: str,
    real_sample_executed: bool,
    authorization_class: str,
) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "run_id": run_id,
        "sample_id": sample_id,
        "sample_sha256": sample_sha256,
        "sample_kind": sample_kind,
        "authorization_class": authorization_class,
        "sample_authorized": True,
        "environment_classification": environment,
        "victim_snapshot_id": "snapshot-clean-v1",
        "network_mode": NETWORK_INETSIM if real_sample_executed else NETWORK_NONE,
        "engine_commit": SOURCE_CHECKPOINT_COMMIT,
        "engine_checkpoint": SOURCE_CHECKPOINT,
        "rule_version": "rules-b143-fixture",
        "pre_state_digest": "a" * 64,
        "post_state_digest": "b" * 64,
        "result": result,
        "detection_layer": layer,
        "detection_latency_ms": 12.5,
        "evidence_ids": [f"evidence:{run_id}:1"],
        "quarantine_state": "NOT_REQUESTED",
        "restore_state": "NOT_REQUESTED",
        "cleanup_revert_confirmed": True,
        "real_sample_executed": real_sample_executed,
        "raw_sample_bytes_included": False,
        "raw_paths_included": False,
        "command_lines_included": False,
        "usernames_included": False,
        "credentials_included": False,
        "file_contents_included": False,
    }


def self_check() -> dict[str, Any]:
    failures: list[str] = []

    benign = _fixture(
        run_id="b143-benign",
        sample_id="benign-fixture",
        sample_sha256="1" * 64,
        sample_kind=SAMPLE_BENIGN,
        environment=ENVIRONMENT_STATIC,
        result=RESULT_CLEAN,
        layer="NONE",
        real_sample_executed=False,
        authorization_class=AUTH_INTERNAL_SAFE,
    )
    static_malware = _fixture(
        run_id="b143-static-malware",
        sample_id="malware-static-fixture",
        sample_sha256="2" * 64,
        sample_kind=SAMPLE_MALWARE,
        environment=ENVIRONMENT_STATIC,
        result=RESULT_DETECTED,
        layer="STATIC",
        real_sample_executed=False,
        authorization_class=AUTH_APPROVED_RESEARCH,
    )
    dynamic_malware = _fixture(
        run_id="b143-dynamic-malware",
        sample_id="malware-dynamic-fixture",
        sample_sha256="3" * 64,
        sample_kind=SAMPLE_MALWARE,
        environment=ENVIRONMENT_ISOLATED,
        result=RESULT_DETECTED,
        layer="BEHAVIOR",
        real_sample_executed=True,
        authorization_class=AUTH_APPROVED_RESEARCH,
    )

    for label, record in (
        ("benign", benign),
        ("static", static_malware),
        ("dynamic", dynamic_malware),
    ):
        record_failures = validate_record(record)
        if record_failures:
            failures.extend(f"b143:{label}:{item}" for item in record_failures)

    batch = import_batch((benign, static_malware, dynamic_malware))
    if batch["passed"] is not True:
        failures.append("b143:fixture_batch_failed")
    if batch["accepted_count"] != 3:
        failures.append("b143:fixture_batch_count_invalid")
    if batch["authoritative_count"] != 3:
        failures.append("b143:fixture_authority_invalid")

    unsafe = dict(dynamic_malware)
    unsafe["network_mode"] = "DIRECT_INTERNET"
    if "b143:network_mode_invalid" not in validate_record(unsafe):
        failures.append("b143:direct_internet_not_rejected")

    no_revert = dict(dynamic_malware)
    no_revert["cleanup_revert_confirmed"] = False
    if "b143:cleanup_revert_required" not in validate_record(no_revert):
        failures.append("b143:no_revert_not_rejected")

    raw_sample = dict(dynamic_malware)
    raw_sample["raw_sample_bytes_included"] = True
    if "b143:raw_sample_bytes_included_forbidden" not in validate_record(raw_sample):
        failures.append("b143:raw_sample_not_rejected")

    contract_digest = _digest(contract())
    deterministic = contract_digest == _digest(contract())
    if not deterministic:
        failures.append("b143:contract_not_deterministic")

    return {
        "passed": not failures,
        "failures": list(dict.fromkeys(failures)),
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "source_coverage": dict(SOURCE_COVERAGE),
        "fixture_record_count": 3,
        "fixture_authoritative_count": batch["authoritative_count"],
        "direct_internet_rejected": True,
        "missing_revert_rejected": True,
        "raw_sample_bytes_rejected": True,
        "sample_execution_capability_in_importer": False,
        "sample_storage_capability_in_importer": False,
        "sample_transfer_capability_in_importer": False,
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

from __future__ import annotations

"""B11-6 deterministic upgrade / rollback / configuration-migration contract.

B11-6 remains non-executing on the host. It turns the accepted B11-5 persistent
storage model into an explicit, fail-closed migration plan that a later clean-PC
lifecycle milestone may execute. The planner never creates directories, copies
or deletes files, changes ACLs, switches an installed version, elevates
privileges, restores quarantine content, or mutates configuration.

Legacy B6 quarantine data is deliberately typed. Untrusted quarantine and
rollback payloads remain payload data; journal and restart-safe recovery records
remain metadata. Migration is copy/verify/keep-source by contract. Source data
is never silently moved or deleted, and rollback never depends on destructive
cleanup.
"""

import hashlib
import json
from typing import Any, Final, Iterable

from sentinel import beta11_persistent_data_model as persistent

SCHEMA: Final[str] = "bc-sentinel-beta11-upgrade-migration-contract-v1"
PROFILE: Final[str] = "v0.11.0-beta.11-b116-upgrade-rollback-config-migration"
SOURCE_CHECKPOINT: Final[str] = "checkpoint/v011-beta11-b115-pass"
SOURCE_CHECKPOINT_COMMIT: Final[str] = "19e40b9b41f4d87b3f081bb7e8bfb5b155db4660"
SOURCE_COVERAGE: Final[dict[str, int]] = {"PARTIAL": 4, "GAP": 0, "VERIFIED": 2}
VERIFIED_SCENARIOS: Final[tuple[str, ...]] = (
    "B7-POWERSHELL-001",
    "B7-RANSOMWARE-001",
)

MACHINE_DATA_ROOT: Final[str] = persistent.MACHINE_DATA_ROOT
LEGACY_ROOT: Final[str] = persistent.LEGACY_HOME_QUARANTINE_ROOT
MIGRATION_MODE: Final[str] = "COPY_VERIFY_SWITCH_KEEP_SOURCE"
ROLLBACK_MODE: Final[str] = "POINTER_ROLLBACK_KEEP_BOTH_DATASETS"
CONFIG_POLICY: Final[str] = "KNOWN_SCHEMA_ONLY_PRESERVE_SOURCE_ON_FAILURE"
ACTIVE_CONFIG_SCHEMA: Final[str] = "bc-sentinel-config-state-v1"
BASELINE_CONFIG_SCHEMA: Final[str] = "bc-sentinel-config-state-v1"

LEGACY_MAPPINGS: Final[tuple[dict[str, Any], ...]] = (
    {
        "mapping_id": "B656_QUARANTINE_PAYLOADS",
        "source_token": LEGACY_ROOT + r"\quarantine",
        "destination_class": "QUARANTINE_PAYLOADS",
        "destination_token": MACHINE_DATA_ROOT + r"\quarantine\payloads\legacy-b656\quarantine",
        "content_kind": "UNTRUSTED_QUARANTINE_PAYLOAD",
        "recursive": True,
        "hash_each_file_required": True,
        "source_preserved_after_migration": True,
        "execute_from_destination": False,
    },
    {
        "mapping_id": "B656_ROLLBACK_SNAPSHOTS",
        "source_token": LEGACY_ROOT + r"\rollback",
        "destination_class": "QUARANTINE_PAYLOADS",
        "destination_token": MACHINE_DATA_ROOT + r"\quarantine\payloads\legacy-b656\rollback",
        "content_kind": "UNTRUSTED_ROLLBACK_SNAPSHOT",
        "recursive": True,
        "hash_each_file_required": True,
        "source_preserved_after_migration": True,
        "execute_from_destination": False,
    },
    {
        "mapping_id": "B656_JOURNAL",
        "source_token": LEGACY_ROOT + r"\journal\events.jsonl",
        "destination_class": "QUARANTINE_METADATA",
        "destination_token": MACHINE_DATA_ROOT + r"\quarantine\metadata\legacy-b656\journal\events.jsonl",
        "content_kind": "TAMPER_EVIDENT_SECURITY_JOURNAL",
        "recursive": False,
        "hash_each_file_required": True,
        "source_preserved_after_migration": True,
        "execute_from_destination": False,
    },
    {
        "mapping_id": "B658_HOME_RESTORE_RECORDS",
        "source_token": LEGACY_ROOT + r"\home-restore",
        "destination_class": "QUARANTINE_METADATA",
        "destination_token": MACHINE_DATA_ROOT + r"\quarantine\metadata\legacy-b656\home-restore",
        "content_kind": "RESTART_SAFE_RECOVERY_METADATA",
        "recursive": True,
        "hash_each_file_required": True,
        "source_preserved_after_migration": True,
        "execute_from_destination": False,
    },
)

UPGRADE_PHASES: Final[tuple[dict[str, Any], ...]] = (
    {"phase": "DISCOVER_READ_ONLY", "mutates_host": False, "required": True},
    {"phase": "VALIDATE_SOURCE_IDENTITY", "mutates_host": False, "required": True},
    {"phase": "BUILD_STAGING_COPY", "mutates_host": True, "execution_available_in_b116": False, "required": True},
    {"phase": "VERIFY_STAGING_HASHES", "mutates_host": False, "required": True},
    {"phase": "WRITE_LIFECYCLE_MANIFEST", "mutates_host": True, "execution_available_in_b116": False, "required": True},
    {"phase": "ACTIVATE_CANONICAL_DATASET", "mutates_host": True, "execution_available_in_b116": False, "required": True},
    {"phase": "KEEP_LEGACY_SOURCE", "mutates_host": False, "required": True},
)

ROLLBACK_RULES: Final[dict[str, Any]] = {
    "mode": ROLLBACK_MODE,
    "previous_dataset_identity_required": True,
    "previous_manifest_digest_required": True,
    "current_dataset_preserved_during_rollback": True,
    "legacy_source_preserved_during_rollback": True,
    "delete_current_dataset_during_rollback": False,
    "delete_legacy_source_during_rollback": False,
    "quarantine_restore_implied_by_rollback": False,
    "rollback_requires_destructive_cleanup": False,
    "rollback_execution_available_in_b116": False,
}

CONFIG_MIGRATION_RULES: Final[dict[str, Any]] = {
    "policy": CONFIG_POLICY,
    "baseline_schema": BASELINE_CONFIG_SCHEMA,
    "active_schema": ACTIVE_CONFIG_SCHEMA,
    "known_schema_required": True,
    "source_digest_required": True,
    "source_payload_preserved": True,
    "unknown_schema_fails_closed": True,
    "future_schema_fails_closed": True,
    "malformed_payload_fails_closed": True,
    "migration_is_idempotent": True,
    "migration_execution_available_in_b116": False,
}

OWNERSHIP_AND_INTEGRITY: Final[dict[str, Any]] = {
    "exact_b115_model_required": True,
    "exact_source_checkpoint_required": True,
    "ownership_manifest_required": True,
    "source_inventory_required": True,
    "source_hash_required_for_every_file": True,
    "destination_hash_must_match_source": True,
    "unknown_source_children_fail_closed": True,
    "unmanifested_destination_entries_fail_closed": True,
    "symlink_or_reparse_escape_fails_closed": True,
    "path_escape_fails_closed": True,
}

IMPLEMENTATION_STATE: Final[dict[str, bool]] = {
    "host_migration_execution_available": False,
    "host_upgrade_execution_available": False,
    "host_rollback_execution_available": False,
    "config_write_execution_available": False,
    "legacy_source_delete_available": False,
    "canonical_dataset_delete_available": False,
    "quarantine_restore_execution_available": False,
    "quarantine_payload_execution_available": False,
    "installer_execution_available": False,
    "uninstaller_execution_available": False,
    "privilege_elevation_available": False,
    "service_registration_available": False,
    "driver_registration_available": False,
    "autostart_registration_available": False,
    "automatic_update_execution_available": False,
    "network_required": False,
    "cloud_required": False,
    "coverage_promoted": False,
    "authority_expanded": False,
}


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _normal_token(value: object) -> str:
    return str(value or "").replace("/", "\\").rstrip("\\").casefold()


def _under(path_token: object, root_token: object) -> bool:
    path = _normal_token(path_token)
    root = _normal_token(root_token)
    return bool(path) and bool(root) and (path == root or path.startswith(root + "\\"))


def contract() -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "source_coverage": dict(SOURCE_COVERAGE),
        "verified_scenarios": list(VERIFIED_SCENARIOS),
        "b115_model_digest": persistent.self_check()["model_digest"],
        "machine_data_root": MACHINE_DATA_ROOT,
        "legacy_root": LEGACY_ROOT,
        "migration_mode": MIGRATION_MODE,
        "legacy_mappings": [dict(item) for item in LEGACY_MAPPINGS],
        "upgrade_phases": [dict(item) for item in UPGRADE_PHASES],
        "rollback_rules": dict(ROLLBACK_RULES),
        "config_migration_rules": dict(CONFIG_MIGRATION_RULES),
        "ownership_and_integrity": dict(OWNERSHIP_AND_INTEGRITY),
        "implementation_state": dict(IMPLEMENTATION_STATE),
        "contract_only": True,
    }


def validate_contract(data: object) -> tuple[str, ...]:
    if not isinstance(data, dict):
        return ("b116:not_object",)

    failures: list[str] = []
    expected_keys = {
        "schema",
        "profile",
        "source_checkpoint",
        "source_checkpoint_commit",
        "source_coverage",
        "verified_scenarios",
        "b115_model_digest",
        "machine_data_root",
        "legacy_root",
        "migration_mode",
        "legacy_mappings",
        "upgrade_phases",
        "rollback_rules",
        "config_migration_rules",
        "ownership_and_integrity",
        "implementation_state",
        "contract_only",
    }
    if set(data) != expected_keys:
        failures.append("b116:unexpected_or_missing_fields")

    if data.get("schema") != SCHEMA or data.get("profile") != PROFILE:
        failures.append("b116:identity_invalid")
    if data.get("source_checkpoint") != SOURCE_CHECKPOINT or data.get("source_checkpoint_commit") != SOURCE_CHECKPOINT_COMMIT:
        failures.append("b116:source_checkpoint_invalid")
    if data.get("source_coverage") != SOURCE_COVERAGE:
        failures.append("b116:coverage_changed")
    if tuple(data.get("verified_scenarios") or ()) != VERIFIED_SCENARIOS:
        failures.append("b116:verified_scenarios_changed")
    if data.get("b115_model_digest") != persistent.self_check()["model_digest"]:
        failures.append("b116:b115_model_binding_invalid")
    if data.get("machine_data_root") != MACHINE_DATA_ROOT or data.get("legacy_root") != LEGACY_ROOT:
        failures.append("b116:data_roots_changed")
    if data.get("migration_mode") != MIGRATION_MODE or data.get("contract_only") is not True:
        failures.append("b116:migration_boundary_changed")

    mappings = data.get("legacy_mappings")
    expected_mappings = [dict(item) for item in LEGACY_MAPPINGS]
    if mappings != expected_mappings or not isinstance(mappings, list):
        failures.append("b116:legacy_mapping_contract_changed")
    else:
        ids = [str(item.get("mapping_id") or "") for item in mappings]
        if len(ids) != len(set(ids)) or len(ids) != 4:
            failures.append("b116:legacy_mapping_identity_invalid")
        payload_classes = {"B656_QUARANTINE_PAYLOADS", "B656_ROLLBACK_SNAPSHOTS"}
        metadata_classes = {"B656_JOURNAL", "B658_HOME_RESTORE_RECORDS"}
        for item in mappings:
            if not _under(item.get("source_token"), LEGACY_ROOT):
                failures.append("b116:legacy_source_path_escape")
            if not _under(item.get("destination_token"), MACHINE_DATA_ROOT):
                failures.append("b116:canonical_destination_path_escape")
            if item.get("hash_each_file_required") is not True or item.get("source_preserved_after_migration") is not True:
                failures.append("b116:mapping_integrity_or_preservation_weakened")
            if item.get("execute_from_destination") is not False:
                failures.append("b116:migrated_content_execution_enabled")
            if item.get("mapping_id") in payload_classes and item.get("destination_class") != "QUARANTINE_PAYLOADS":
                failures.append("b116:untrusted_payload_reclassified")
            if item.get("mapping_id") in metadata_classes and item.get("destination_class") != "QUARANTINE_METADATA":
                failures.append("b116:security_metadata_reclassified")

    phases = data.get("upgrade_phases")
    if phases != [dict(item) for item in UPGRADE_PHASES] or not isinstance(phases, list):
        failures.append("b116:upgrade_phase_contract_changed")
    else:
        mutating = [item for item in phases if item.get("mutates_host") is True]
        if not mutating or any(item.get("execution_available_in_b116") is not False for item in mutating):
            failures.append("b116:host_upgrade_execution_enabled")

    rollback = data.get("rollback_rules")
    if rollback != ROLLBACK_RULES or not isinstance(rollback, dict):
        failures.append("b116:rollback_contract_changed")
    elif (
        rollback.get("previous_dataset_identity_required") is not True
        or rollback.get("previous_manifest_digest_required") is not True
        or rollback.get("current_dataset_preserved_during_rollback") is not True
        or rollback.get("legacy_source_preserved_during_rollback") is not True
        or rollback.get("delete_current_dataset_during_rollback") is not False
        or rollback.get("delete_legacy_source_during_rollback") is not False
        or rollback.get("quarantine_restore_implied_by_rollback") is not False
        or rollback.get("rollback_execution_available_in_b116") is not False
    ):
        failures.append("b116:unsafe_rollback_policy")

    config = data.get("config_migration_rules")
    if config != CONFIG_MIGRATION_RULES or not isinstance(config, dict):
        failures.append("b116:config_migration_contract_changed")
    elif (
        config.get("known_schema_required") is not True
        or config.get("source_digest_required") is not True
        or config.get("source_payload_preserved") is not True
        or config.get("unknown_schema_fails_closed") is not True
        or config.get("future_schema_fails_closed") is not True
        or config.get("malformed_payload_fails_closed") is not True
        or config.get("migration_execution_available_in_b116") is not False
    ):
        failures.append("b116:unsafe_config_migration_policy")

    integrity = data.get("ownership_and_integrity")
    if integrity != OWNERSHIP_AND_INTEGRITY or not isinstance(integrity, dict):
        failures.append("b116:ownership_integrity_contract_changed")
    elif not all(integrity.values()):
        failures.append("b116:ownership_integrity_requirement_disabled")

    state = data.get("implementation_state")
    if state != IMPLEMENTATION_STATE or not isinstance(state, dict):
        failures.append("b116:implementation_state_changed")
    elif any(state.values()):
        failures.append("b116:mutation_authority_or_claim_enabled")

    return tuple(dict.fromkeys(failures))


def plan_config_migration(
    *,
    source_schema: str,
    source_payload: object,
    source_digest: str,
) -> dict[str, Any]:
    """Pure migration decision; does not write configuration."""

    reasons: list[str] = []
    if source_schema != BASELINE_CONFIG_SCHEMA:
        reasons.append("unknown_or_future_config_schema")
    if not isinstance(source_payload, dict):
        reasons.append("malformed_config_payload")
    computed_digest = _digest(source_payload)
    if source_digest != computed_digest:
        reasons.append("source_config_digest_mismatch")

    accepted = not reasons
    transformed_payload = dict(source_payload) if accepted else None
    return {
        "accepted": accepted,
        "source_schema": source_schema,
        "destination_schema": ACTIVE_CONFIG_SCHEMA if accepted else None,
        "source_digest": source_digest,
        "computed_source_digest": computed_digest,
        "transformed_payload": transformed_payload,
        "transformed_digest": _digest(transformed_payload) if accepted else None,
        "source_payload_preserved": True,
        "write_execution_available_in_b116": False,
        "reasons": reasons,
    }


def build_migration_plan(
    inventory: Iterable[dict[str, Any]],
    *,
    ownership_manifest_valid: bool,
    unknown_children_present: bool,
    unmanifested_destination_entries_present: bool,
    symlink_or_reparse_escape_present: bool,
) -> dict[str, Any]:
    """Pure deterministic planner over a caller-supplied inventory."""

    entries = [dict(item) for item in inventory]
    reasons: list[str] = []
    known_sources = {_normal_token(item["source_token"]): item for item in LEGACY_MAPPINGS}
    seen_mapping_ids: set[str] = set()
    planned_entries: list[dict[str, Any]] = []

    if not ownership_manifest_valid:
        reasons.append("ownership_manifest_invalid")
    if unknown_children_present:
        reasons.append("unknown_source_children_present")
    if unmanifested_destination_entries_present:
        reasons.append("unmanifested_destination_entries_present")
    if symlink_or_reparse_escape_present:
        reasons.append("symlink_or_reparse_escape_present")

    for entry in entries:
        source_token = _normal_token(entry.get("source_token"))
        mapping = known_sources.get(source_token)
        if mapping is None:
            reasons.append("inventory_source_not_mapped")
            continue
        mapping_id = str(mapping["mapping_id"])
        seen_mapping_ids.add(mapping_id)
        file_count = entry.get("file_count")
        tree_digest = str(entry.get("tree_digest") or "")
        if not isinstance(file_count, int) or file_count < 0:
            reasons.append("inventory_file_count_invalid")
        if len(tree_digest) != 64 or any(ch not in "0123456789abcdef" for ch in tree_digest.casefold()):
            reasons.append("inventory_tree_digest_invalid")
        planned_entries.append(
            {
                "mapping_id": mapping_id,
                "source_token": mapping["source_token"],
                "destination_token": mapping["destination_token"],
                "destination_class": mapping["destination_class"],
                "file_count": file_count,
                "tree_digest": tree_digest.casefold(),
                "source_preserved_after_migration": True,
            }
        )

    planned_entries.sort(key=lambda item: item["mapping_id"])
    eligible = not reasons
    body = {
        "schema": "bc-sentinel-beta11-migration-plan-v1",
        "profile": PROFILE,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "migration_mode": MIGRATION_MODE,
        "entries": planned_entries,
        "eligible": eligible,
        "reasons": sorted(set(reasons)),
        "host_execution_available_in_b116": False,
        "source_dataset_delete_available_in_b116": False,
    }
    return {**body, "plan_digest": _digest(body), "mapped_source_count": len(seen_mapping_ids)}


def build_rollback_plan(*, previous_dataset_id: str, previous_manifest_digest: str, current_dataset_id: str) -> dict[str, Any]:
    reasons: list[str] = []
    if not previous_dataset_id:
        reasons.append("previous_dataset_identity_missing")
    if len(previous_manifest_digest) != 64 or any(ch not in "0123456789abcdef" for ch in previous_manifest_digest.casefold()):
        reasons.append("previous_manifest_digest_invalid")
    if not current_dataset_id:
        reasons.append("current_dataset_identity_missing")
    if previous_dataset_id and current_dataset_id and previous_dataset_id == current_dataset_id:
        reasons.append("rollback_target_equals_current_dataset")

    body = {
        "schema": "bc-sentinel-beta11-rollback-plan-v1",
        "profile": PROFILE,
        "mode": ROLLBACK_MODE,
        "previous_dataset_id": previous_dataset_id,
        "previous_manifest_digest": previous_manifest_digest.casefold(),
        "current_dataset_id": current_dataset_id,
        "eligible": not reasons,
        "reasons": reasons,
        "current_dataset_preserved": True,
        "legacy_source_preserved": True,
        "quarantine_restore_implied": False,
        "host_execution_available_in_b116": False,
    }
    return {**body, "plan_digest": _digest(body)}


def self_check() -> dict[str, Any]:
    first = contract()
    second = contract()
    failures = list(validate_contract(first))
    deterministic = first == second and _digest(first) == _digest(second)
    if not deterministic:
        failures.append("b116:contract_not_deterministic")

    sample_inventory = [
        {
            "source_token": item["source_token"],
            "file_count": index + 1,
            "tree_digest": hashlib.sha256(item["mapping_id"].encode("utf-8")).hexdigest(),
        }
        for index, item in enumerate(LEGACY_MAPPINGS)
    ]
    plan_a = build_migration_plan(
        sample_inventory,
        ownership_manifest_valid=True,
        unknown_children_present=False,
        unmanifested_destination_entries_present=False,
        symlink_or_reparse_escape_present=False,
    )
    plan_b = build_migration_plan(
        sample_inventory,
        ownership_manifest_valid=True,
        unknown_children_present=False,
        unmanifested_destination_entries_present=False,
        symlink_or_reparse_escape_present=False,
    )
    if not plan_a["eligible"] or plan_a != plan_b:
        failures.append("b116:migration_plan_not_deterministic")

    config_payload = {"schema": BASELINE_CONFIG_SCHEMA, "settings": {"telemetry": "local-only"}}
    config_digest = _digest(config_payload)
    config_plan = plan_config_migration(
        source_schema=BASELINE_CONFIG_SCHEMA,
        source_payload=config_payload,
        source_digest=config_digest,
    )
    if not config_plan["accepted"] or config_plan["write_execution_available_in_b116"]:
        failures.append("b116:config_migration_self_check_failed")

    refused_plan = build_migration_plan(
        sample_inventory,
        ownership_manifest_valid=False,
        unknown_children_present=True,
        unmanifested_destination_entries_present=False,
        symlink_or_reparse_escape_present=False,
    )
    if refused_plan["eligible"]:
        failures.append("b116:unsafe_inventory_did_not_fail_closed")

    rollback_plan = build_rollback_plan(
        previous_dataset_id="dataset-b115",
        previous_manifest_digest="a" * 64,
        current_dataset_id="dataset-b116",
    )
    if not rollback_plan["eligible"] or rollback_plan["host_execution_available_in_b116"]:
        failures.append("b116:rollback_plan_self_check_failed")

    return {
        "passed": not failures,
        "failures": failures,
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "source_coverage": dict(SOURCE_COVERAGE),
        "verified_scenarios": list(VERIFIED_SCENARIOS),
        "b115_model_digest": persistent.self_check()["model_digest"],
        "contract_digest": _digest(first),
        "deterministic_contract": deterministic,
        "legacy_mapping_count": len(LEGACY_MAPPINGS),
        "upgrade_phase_count": len(UPGRADE_PHASES),
        "migration_mode": MIGRATION_MODE,
        "rollback_mode": ROLLBACK_MODE,
        "sample_migration_plan_digest": plan_a["plan_digest"],
        "sample_rollback_plan_digest": rollback_plan["plan_digest"],
        "config_migration_idempotent": True,
        "source_preserved": True,
        "host_migration_execution_available": False,
        "host_upgrade_execution_available": False,
        "host_rollback_execution_available": False,
        "config_write_execution_available": False,
        "legacy_source_delete_available": False,
        "quarantine_restore_execution_available": False,
        "network_required": False,
        "cloud_required": False,
        "authority_expanded": False,
        "coverage_promoted": False,
    }


def main() -> int:
    report = self_check()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

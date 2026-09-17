from __future__ import annotations

"""B11-5 persistent application-data, logs and quarantine model.

This milestone is deliberately contract/model-only.  It defines the canonical
machine-data namespace and lifecycle rules that a later installer/upgrade
milestone may implement.  It does not create directories, migrate legacy data,
change ACLs, delete data, quarantine files, restore files, elevate privileges or
otherwise mutate the host.
"""

import hashlib
import json
from typing import Any, Final

SCHEMA: Final[str] = "bc-sentinel-beta11-persistent-data-model-v1"
PROFILE: Final[str] = "v0.11.0-beta.11-b115-persistent-app-data-lifecycle"
SOURCE_CHECKPOINT: Final[str] = "checkpoint/v011-beta11-b114-pass"
SOURCE_CHECKPOINT_COMMIT: Final[str] = "5ec361050f4c490652f88c30ad3a3b60e586fecb"
SOURCE_COVERAGE: Final[dict[str, int]] = {"PARTIAL": 4, "GAP": 0, "VERIFIED": 2}
VERIFIED_SCENARIOS: Final[tuple[str, ...]] = (
    "B7-POWERSHELL-001",
    "B7-RANSOMWARE-001",
)

MACHINE_DATA_ROOT: Final[str] = r"{PROGRAM_DATA}\BC Sentinel"
LEGACY_HOME_QUARANTINE_ROOT: Final[str] = r"{LOCAL_APP_DATA}\BCSentinel\B656"
LEGACY_MIGRATION_POLICY: Final[str] = "DEFERRED_TO_B11_6_NO_AUTOMATIC_MIGRATION"

DATA_CLASSES: Final[tuple[dict[str, Any], ...]] = (
    {
        "class_id": "CONFIG_STATE",
        "subroot": "state",
        "path_token": MACHINE_DATA_ROOT + r"\state",
        "product_owned": True,
        "sensitivity": "INTERNAL_CONFIGURATION",
        "contains_untrusted_payload": False,
        "permission_intent": "PRODUCT_RUNTIME_READ_WRITE",
        "retention": "PRESERVE_UNTIL_EXPLICIT_OPERATOR_RESET_POLICY",
        "upgrade_behavior": "PRESERVE",
        "rollback_behavior": "PRESERVE",
        "uninstall_behavior": "PRESERVE_BY_DEFAULT",
    },
    {
        "class_id": "LOGS",
        "subroot": "logs",
        "path_token": MACHINE_DATA_ROOT + r"\logs",
        "product_owned": True,
        "sensitivity": "SECURITY_TELEMETRY",
        "contains_untrusted_payload": False,
        "permission_intent": "PRODUCT_RUNTIME_APPEND_AND_READ",
        "retention": "BOUNDED_POLICY_REQUIRED_BEFORE_AUTOMATIC_PURGE",
        "upgrade_behavior": "PRESERVE",
        "rollback_behavior": "PRESERVE",
        "uninstall_behavior": "PRESERVE_BY_DEFAULT",
    },
    {
        "class_id": "QUARANTINE_METADATA",
        "subroot": r"quarantine\metadata",
        "path_token": MACHINE_DATA_ROOT + r"\quarantine\metadata",
        "product_owned": True,
        "sensitivity": "SECURITY_SENSITIVE_METADATA",
        "contains_untrusted_payload": False,
        "permission_intent": "PRODUCT_RUNTIME_RESTRICTED_READ_WRITE",
        "retention": "PRESERVE_WITH_ASSOCIATED_QUARANTINE_RECORD",
        "upgrade_behavior": "PRESERVE",
        "rollback_behavior": "PRESERVE",
        "uninstall_behavior": "PRESERVE_BY_DEFAULT",
    },
    {
        "class_id": "QUARANTINE_PAYLOADS",
        "subroot": r"quarantine\payloads",
        "path_token": MACHINE_DATA_ROOT + r"\quarantine\payloads",
        "product_owned": True,
        "sensitivity": "UNTRUSTED_QUARANTINED_CONTENT",
        "contains_untrusted_payload": True,
        "permission_intent": "PRODUCT_RUNTIME_RESTRICTED_NO_EXECUTE",
        "retention": "PRESERVE_UNTIL_EXPLICIT_ACCEPTED_RESTORE_OR_PURGE",
        "upgrade_behavior": "PRESERVE",
        "rollback_behavior": "PRESERVE",
        "uninstall_behavior": "PRESERVE_BY_DEFAULT",
    },
    {
        "class_id": "LIFECYCLE_METADATA",
        "subroot": "lifecycle",
        "path_token": MACHINE_DATA_ROOT + r"\lifecycle",
        "product_owned": True,
        "sensitivity": "INTEGRITY_AND_OWNERSHIP_METADATA",
        "contains_untrusted_payload": False,
        "permission_intent": "LIFECYCLE_OWNER_WRITE_PRODUCT_READ",
        "retention": "PRESERVE_ACROSS_UPGRADE_AND_ROLLBACK",
        "upgrade_behavior": "PRESERVE",
        "rollback_behavior": "PRESERVE",
        "uninstall_behavior": "PRESERVE_BY_DEFAULT",
    },
)

QUARANTINE_BOUNDARY: Final[dict[str, Any]] = {
    "metadata_class": "QUARANTINE_METADATA",
    "payload_class": "QUARANTINE_PAYLOADS",
    "metadata_payload_separated": True,
    "payload_treated_as_user_document": False,
    "payload_treated_as_log": False,
    "payload_treated_as_configuration": False,
    "payload_execution_allowed_from_store": False,
    "restore_execution_available_in_b115": False,
    "purge_execution_available_in_b115": False,
    "new_quarantine_execution_available_in_b115": False,
    "legacy_root": LEGACY_HOME_QUARANTINE_ROOT,
    "legacy_migration_policy": LEGACY_MIGRATION_POLICY,
}

DESTRUCTIVE_LIFECYCLE_GATE: Final[dict[str, Any]] = {
    "persistent_data_removed_by_default_on_uninstall": False,
    "explicit_operator_purge_required": True,
    "exact_ownership_manifest_required": True,
    "exact_data_class_identity_required": True,
    "unknown_children_block_destructive_action": True,
    "unmanifested_entries_block_destructive_action": True,
    "path_must_remain_under_canonical_root": True,
    "root_only_recursive_delete_allowed": False,
    "destructive_execution_available_in_b115": False,
}

IMPLEMENTATION_STATE: Final[dict[str, bool]] = {
    "persistent_root_creation_available": False,
    "permission_enforcement_available": False,
    "retention_cleanup_execution_available": False,
    "legacy_migration_execution_available": False,
    "installer_execution_available": False,
    "uninstaller_execution_available": False,
    "repair_execution_available": False,
    "quarantine_execution_available": False,
    "restore_execution_available": False,
    "purge_execution_available": False,
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


def _under_canonical_root(path_token: object) -> bool:
    root = _normal_token(MACHINE_DATA_ROOT)
    path = _normal_token(path_token)
    return bool(path) and (path == root or path.startswith(root + "\\"))


def model() -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "source_coverage": dict(SOURCE_COVERAGE),
        "verified_scenarios": list(VERIFIED_SCENARIOS),
        "machine_data_root": MACHINE_DATA_ROOT,
        "data_classes": [dict(item) for item in DATA_CLASSES],
        "quarantine_boundary": dict(QUARANTINE_BOUNDARY),
        "destructive_lifecycle_gate": dict(DESTRUCTIVE_LIFECYCLE_GATE),
        "implementation_state": dict(IMPLEMENTATION_STATE),
        "contract_only": True,
    }


def validate_model(data: object) -> tuple[str, ...]:
    if not isinstance(data, dict):
        return ("b115:not_object",)

    failures: list[str] = []
    expected_keys = {
        "schema",
        "profile",
        "source_checkpoint",
        "source_checkpoint_commit",
        "source_coverage",
        "verified_scenarios",
        "machine_data_root",
        "data_classes",
        "quarantine_boundary",
        "destructive_lifecycle_gate",
        "implementation_state",
        "contract_only",
    }
    if set(data) != expected_keys:
        failures.append("b115:unexpected_or_missing_fields")

    if data.get("schema") != SCHEMA or data.get("profile") != PROFILE:
        failures.append("b115:identity_invalid")
    if data.get("source_checkpoint") != SOURCE_CHECKPOINT or data.get("source_checkpoint_commit") != SOURCE_CHECKPOINT_COMMIT:
        failures.append("b115:source_checkpoint_invalid")
    if data.get("source_coverage") != SOURCE_COVERAGE:
        failures.append("b115:coverage_changed")
    if tuple(data.get("verified_scenarios") or ()) != VERIFIED_SCENARIOS:
        failures.append("b115:verified_scenarios_changed")
    if data.get("machine_data_root") != MACHINE_DATA_ROOT:
        failures.append("b115:machine_data_root_changed")
    if data.get("contract_only") is not True:
        failures.append("b115:contract_only_boundary_removed")

    classes = data.get("data_classes")
    expected_classes = [dict(item) for item in DATA_CLASSES]
    if classes != expected_classes or not isinstance(classes, list):
        failures.append("b115:data_class_contract_changed")
    else:
        ids = [str(item.get("class_id") or "") for item in classes]
        subroots = [_normal_token(item.get("subroot")) for item in classes]
        paths = [_normal_token(item.get("path_token")) for item in classes]
        if ids != ["CONFIG_STATE", "LOGS", "QUARANTINE_METADATA", "QUARANTINE_PAYLOADS", "LIFECYCLE_METADATA"]:
            failures.append("b115:data_class_order_or_identity_invalid")
        if len(ids) != len(set(ids)) or len(subroots) != len(set(subroots)) or len(paths) != len(set(paths)):
            failures.append("b115:data_class_path_or_identity_not_unique")
        for item in classes:
            if item.get("product_owned") is not True:
                failures.append("b115:unowned_data_class")
            if not _under_canonical_root(item.get("path_token")):
                failures.append("b115:data_class_outside_canonical_root")
            if item.get("upgrade_behavior") != "PRESERVE" or item.get("rollback_behavior") != "PRESERVE":
                failures.append("b115:upgrade_or_rollback_not_preserved")
            if item.get("uninstall_behavior") != "PRESERVE_BY_DEFAULT":
                failures.append("b115:uninstall_default_not_preserve")

    quarantine = data.get("quarantine_boundary")
    if quarantine != QUARANTINE_BOUNDARY or not isinstance(quarantine, dict):
        failures.append("b115:quarantine_boundary_changed")
    else:
        required_false = (
            "payload_treated_as_user_document",
            "payload_treated_as_log",
            "payload_treated_as_configuration",
            "payload_execution_allowed_from_store",
            "restore_execution_available_in_b115",
            "purge_execution_available_in_b115",
            "new_quarantine_execution_available_in_b115",
        )
        if quarantine.get("metadata_payload_separated") is not True:
            failures.append("b115:quarantine_metadata_payload_not_separated")
        if any(quarantine.get(key) is not False for key in required_false):
            failures.append("b115:quarantine_execution_or_reclassification_enabled")
        if quarantine.get("legacy_migration_policy") != LEGACY_MIGRATION_POLICY:
            failures.append("b115:legacy_migration_policy_changed")

    gate = data.get("destructive_lifecycle_gate")
    if gate != DESTRUCTIVE_LIFECYCLE_GATE or not isinstance(gate, dict):
        failures.append("b115:destructive_gate_changed")
    else:
        required_true = (
            "explicit_operator_purge_required",
            "exact_ownership_manifest_required",
            "exact_data_class_identity_required",
            "unknown_children_block_destructive_action",
            "unmanifested_entries_block_destructive_action",
            "path_must_remain_under_canonical_root",
        )
        if gate.get("persistent_data_removed_by_default_on_uninstall") is not False:
            failures.append("b115:uninstall_purge_enabled")
        if any(gate.get(key) is not True for key in required_true):
            failures.append("b115:destructive_gate_weakened")
        if gate.get("root_only_recursive_delete_allowed") is not False or gate.get("destructive_execution_available_in_b115") is not False:
            failures.append("b115:destructive_execution_enabled")

    state = data.get("implementation_state")
    if state != IMPLEMENTATION_STATE or not isinstance(state, dict):
        failures.append("b115:implementation_state_changed")
    elif any(state.values()):
        failures.append("b115:mutation_authority_or_claim_enabled")

    return tuple(failures)


def destructive_decision(
    *,
    data_class_id: str,
    path_token: str,
    ownership_manifest_valid: bool,
    explicit_operator_purge: bool,
    unknown_children_present: bool,
    unmanifested_entries_present: bool,
) -> dict[str, Any]:
    """Pure fail-closed decision helper; never performs a filesystem action."""

    known_ids = {item["class_id"] for item in DATA_CLASSES}
    reasons: list[str] = []
    if data_class_id not in known_ids:
        reasons.append("unknown_data_class")
    if not _under_canonical_root(path_token):
        reasons.append("outside_canonical_root")
    if not ownership_manifest_valid:
        reasons.append("ownership_manifest_invalid")
    if not explicit_operator_purge:
        reasons.append("explicit_operator_purge_required")
    if unknown_children_present:
        reasons.append("unknown_children_present")
    if unmanifested_entries_present:
        reasons.append("unmanifested_entries_present")

    contract_conditions_satisfied = not reasons
    return {
        "eligible_for_future_purge_contract": contract_conditions_satisfied,
        "execution_available_in_b115": False,
        "reasons": reasons,
    }


def self_check() -> dict[str, Any]:
    first = model()
    second = model()
    failures = list(validate_model(first))
    deterministic = first == second and _digest(first) == _digest(second)
    if not deterministic:
        failures.append("b115:model_not_deterministic")

    safe_refusal = destructive_decision(
        data_class_id="LOGS",
        path_token=MACHINE_DATA_ROOT + r"\logs",
        ownership_manifest_valid=False,
        explicit_operator_purge=True,
        unknown_children_present=False,
        unmanifested_entries_present=False,
    )
    if safe_refusal["eligible_for_future_purge_contract"]:
        failures.append("b115:missing_ownership_did_not_fail_closed")

    all_contract_conditions = destructive_decision(
        data_class_id="LOGS",
        path_token=MACHINE_DATA_ROOT + r"\logs",
        ownership_manifest_valid=True,
        explicit_operator_purge=True,
        unknown_children_present=False,
        unmanifested_entries_present=False,
    )
    if all_contract_conditions["execution_available_in_b115"]:
        failures.append("b115:destructive_execution_available")

    return {
        "passed": not failures,
        "failures": failures,
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "source_coverage": dict(SOURCE_COVERAGE),
        "verified_scenarios": list(VERIFIED_SCENARIOS),
        "machine_data_root": MACHINE_DATA_ROOT,
        "data_class_count": len(DATA_CLASSES),
        "quarantine_metadata_payload_separated": True,
        "legacy_migration_policy": LEGACY_MIGRATION_POLICY,
        "persistent_data_preserved_by_default": True,
        "unknown_children_fail_closed": True,
        "ownership_manifest_required": True,
        "destructive_execution_available": False,
        "permission_enforcement_available": False,
        "migration_execution_available": False,
        "installer_or_uninstaller_execution_available": False,
        "network_required": False,
        "cloud_required": False,
        "authority_expanded": False,
        "coverage_promoted": False,
        "deterministic_model": deterministic,
        "model_digest": _digest(first),
    }


def main() -> int:
    result = self_check()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

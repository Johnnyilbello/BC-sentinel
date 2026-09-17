from __future__ import annotations

"""B11-3 Installer / Uninstaller Contract.

This milestone defines the future Windows install lifecycle before any installer
is allowed to mutate a real machine.  It is deliberately contract-only:
installer/uninstaller execution is not available here.

The contract keeps mutation bounded to explicitly declared product-owned
resources, requires exact ownership evidence before removal, preserves unknown
or user data, and does not introduce services, drivers, autostart, security
product exclusions, remediation authority or detection-coverage promotion.
"""

import hashlib
import json
from typing import Any, Final

SCHEMA: Final[str] = "bc-sentinel-beta11-install-lifecycle-contract-v1"
PROFILE: Final[str] = "v0.11.0-beta.11-b113-installer-uninstaller-contract"
SOURCE_CHECKPOINT: Final[str] = "checkpoint/v011-beta11-b112-pass"
SOURCE_CHECKPOINT_COMMIT: Final[str] = "92b6317aa9e642a0062268bce9f92bb0a4ffb1a1"
SOURCE_COVERAGE: Final[dict[str, int]] = {"PARTIAL": 4, "GAP": 0, "VERIFIED": 2}
VERIFIED_SCENARIOS: Final[tuple[str, ...]] = (
    "B7-POWERSHELL-001",
    "B7-RANSOMWARE-001",
)

ELEVATION_POLICY: Final[str] = "ON_DEMAND_MACHINE_SCOPE_ONLY"
DATA_POLICY_STATE: Final[str] = "DEFERRED_TO_B11_5_PRESERVE_BY_DEFAULT"
OWNERSHIP_PROOF: Final[str] = "EXACT_PRODUCT_OWNERSHIP_MANIFEST_REQUIRED"

PLANNED_PRODUCT_RESOURCES: Final[tuple[dict[str, Any], ...]] = (
    {
        "resource_id": "APPLICATION_PAYLOAD",
        "scope": "MACHINE",
        "path_token": "{PROGRAM_FILES}\\BC Sentinel",
        "product_owned": True,
        "installer_may_create": True,
        "uninstaller_may_remove": True,
        "ownership_manifest_required": True,
        "preserve_unknown_children": True,
    },
    {
        "resource_id": "UNINSTALL_METADATA",
        "scope": "MACHINE",
        "path_token": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\BCSentinel",
        "product_owned": True,
        "installer_may_create": True,
        "uninstaller_may_remove": True,
        "ownership_manifest_required": True,
        "preserve_unknown_children": True,
    },
    {
        "resource_id": "START_MENU_SHORTCUT",
        "scope": "MACHINE",
        "path_token": "{COMMON_PROGRAMS}\\BC Sentinel\\BC Sentinel.lnk",
        "product_owned": True,
        "installer_may_create": True,
        "uninstaller_may_remove": True,
        "ownership_manifest_required": True,
        "preserve_unknown_children": True,
    },
    {
        "resource_id": "PERSISTENT_APP_DATA",
        "scope": "MACHINE_DATA",
        "path_token": "{PROGRAM_DATA}\\BC Sentinel",
        "product_owned": True,
        "installer_may_create": False,
        "uninstaller_may_remove": False,
        "ownership_manifest_required": True,
        "preserve_unknown_children": True,
        "policy": DATA_POLICY_STATE,
    },
)

LIFECYCLE_OPERATIONS: Final[tuple[dict[str, Any], ...]] = (
    {
        "operation": "INSTALL",
        "explicit_operator_action_required": True,
        "silent_mutation_enabled": False,
        "elevation_policy": ELEVATION_POLICY,
        "execution_available_in_b113": False,
    },
    {
        "operation": "REPAIR",
        "explicit_operator_action_required": True,
        "silent_mutation_enabled": False,
        "elevation_policy": ELEVATION_POLICY,
        "execution_available_in_b113": False,
    },
    {
        "operation": "UPGRADE",
        "explicit_operator_action_required": True,
        "silent_mutation_enabled": False,
        "elevation_policy": ELEVATION_POLICY,
        "execution_available_in_b113": False,
    },
    {
        "operation": "UNINSTALL",
        "explicit_operator_action_required": True,
        "silent_mutation_enabled": False,
        "elevation_policy": ELEVATION_POLICY,
        "execution_available_in_b113": False,
    },
)

UNINSTALL_SAFETY: Final[dict[str, Any]] = {
    "ownership_proof": OWNERSHIP_PROOF,
    "missing_ownership_evidence_fails_closed": True,
    "remove_only_manifested_product_resources": True,
    "recursive_delete_outside_owned_roots": False,
    "remove_unknown_files": False,
    "remove_user_documents": False,
    "remove_unrelated_registry_values": False,
    "persistent_app_data_removed_by_default": False,
    "quarantine_removed_by_default": False,
    "logs_removed_by_default": False,
    "unknown_children_preserved": True,
    "future_data_removal_requires_separate_explicit_choice": True,
}

FORBIDDEN_INSTALL_MUTATIONS: Final[dict[str, bool]] = {
    "windows_system_directory_mutation": False,
    "arbitrary_user_profile_mutation": False,
    "user_documents_mutation": False,
    "defender_exclusion_creation": False,
    "firewall_rule_creation": False,
    "scheduled_task_creation": False,
    "windows_service_installation": False,
    "kernel_driver_installation": False,
    "autostart_registration": False,
    "browser_extension_installation": False,
    "certificate_store_mutation": False,
    "environment_path_mutation": False,
    "automatic_update_registration": False,
}

INHERITED_SECURITY_BOUNDARY: Final[dict[str, bool]] = {
    "automatic_quarantine": False,
    "automatic_repair": False,
    "automatic_restore": False,
    "general_home_execution": False,
    "delete_authority": False,
    "repair_authority": False,
    "terminate_process_authority": False,
    "trust_allowlist_mutation": False,
    "privileged_system_mutation": False,
    "coverage_promoted": False,
    "broad_protection_claimed": False,
}


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def contract() -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "source_coverage": dict(SOURCE_COVERAGE),
        "verified_scenarios": list(VERIFIED_SCENARIOS),
        "contract_only": True,
        "installer_available": False,
        "uninstaller_available": False,
        "install_execution_available": False,
        "repair_execution_available": False,
        "upgrade_execution_available": False,
        "uninstall_execution_available": False,
        "artifact_signed": False,
        "elevation_policy": ELEVATION_POLICY,
        "data_policy_state": DATA_POLICY_STATE,
        "planned_product_resources": [dict(item) for item in PLANNED_PRODUCT_RESOURCES],
        "lifecycle_operations": [dict(item) for item in LIFECYCLE_OPERATIONS],
        "uninstall_safety": dict(UNINSTALL_SAFETY),
        "forbidden_install_mutations": dict(FORBIDDEN_INSTALL_MUTATIONS),
        "inherited_security_boundary": dict(INHERITED_SECURITY_BOUNDARY),
    }


def validate_contract(data: object) -> tuple[str, ...]:
    if not isinstance(data, dict):
        return ("b113:not_object",)

    failures: list[str] = []
    expected_keys = {
        "schema",
        "profile",
        "source_checkpoint",
        "source_checkpoint_commit",
        "source_coverage",
        "verified_scenarios",
        "contract_only",
        "installer_available",
        "uninstaller_available",
        "install_execution_available",
        "repair_execution_available",
        "upgrade_execution_available",
        "uninstall_execution_available",
        "artifact_signed",
        "elevation_policy",
        "data_policy_state",
        "planned_product_resources",
        "lifecycle_operations",
        "uninstall_safety",
        "forbidden_install_mutations",
        "inherited_security_boundary",
    }
    if set(data) != expected_keys:
        failures.append("b113:unexpected_or_missing_fields")

    if data.get("schema") != SCHEMA or data.get("profile") != PROFILE:
        failures.append("b113:identity_invalid")
    if data.get("source_checkpoint") != SOURCE_CHECKPOINT or data.get("source_checkpoint_commit") != SOURCE_CHECKPOINT_COMMIT:
        failures.append("b113:source_checkpoint_invalid")
    if data.get("source_coverage") != SOURCE_COVERAGE:
        failures.append("b113:coverage_changed")
    if tuple(data.get("verified_scenarios") or ()) != VERIFIED_SCENARIOS:
        failures.append("b113:verified_scenarios_changed")

    if data.get("contract_only") is not True:
        failures.append("b113:contract_only_boundary_removed")
    for key in (
        "installer_available",
        "uninstaller_available",
        "install_execution_available",
        "repair_execution_available",
        "upgrade_execution_available",
        "uninstall_execution_available",
        "artifact_signed",
    ):
        if data.get(key) is not False:
            failures.append(f"b113:premature_capability:{key}")

    if data.get("elevation_policy") != ELEVATION_POLICY:
        failures.append("b113:elevation_policy_invalid")
    if data.get("data_policy_state") != DATA_POLICY_STATE:
        failures.append("b113:data_policy_invalid")

    resources = data.get("planned_product_resources")
    expected_resources = [dict(item) for item in PLANNED_PRODUCT_RESOURCES]
    if resources != expected_resources:
        failures.append("b113:product_resource_contract_changed")
    elif not all(item.get("product_owned") is True for item in resources):
        failures.append("b113:unowned_resource_declared")
    else:
        ids = [item["resource_id"] for item in resources]
        if len(ids) != len(set(ids)):
            failures.append("b113:duplicate_resource_identity")
        for item in resources:
            if item.get("ownership_manifest_required") is not True:
                failures.append("b113:ownership_manifest_not_required")
            if item.get("preserve_unknown_children") is not True:
                failures.append("b113:unknown_children_not_preserved")

    operations = data.get("lifecycle_operations")
    expected_operations = [dict(item) for item in LIFECYCLE_OPERATIONS]
    if operations != expected_operations:
        failures.append("b113:lifecycle_operation_contract_changed")
    elif [item.get("operation") for item in operations] != ["INSTALL", "REPAIR", "UPGRADE", "UNINSTALL"]:
        failures.append("b113:lifecycle_operation_order_invalid")
    else:
        for item in operations:
            if item.get("explicit_operator_action_required") is not True:
                failures.append("b113:operator_confirmation_removed")
            if item.get("silent_mutation_enabled") is not False:
                failures.append("b113:silent_mutation_enabled")
            if item.get("execution_available_in_b113") is not False:
                failures.append("b113:execution_enabled_too_early")
            if item.get("elevation_policy") != ELEVATION_POLICY:
                failures.append("b113:operation_elevation_policy_invalid")

    safety = data.get("uninstall_safety")
    if safety != UNINSTALL_SAFETY:
        failures.append("b113:uninstall_safety_changed")
    elif (
        safety.get("ownership_proof") != OWNERSHIP_PROOF
        or safety.get("missing_ownership_evidence_fails_closed") is not True
        or safety.get("remove_only_manifested_product_resources") is not True
        or safety.get("recursive_delete_outside_owned_roots") is not False
        or safety.get("remove_unknown_files") is not False
        or safety.get("remove_user_documents") is not False
        or safety.get("persistent_app_data_removed_by_default") is not False
        or safety.get("unknown_children_preserved") is not True
    ):
        failures.append("b113:unsafe_uninstall_policy")

    forbidden = data.get("forbidden_install_mutations")
    if forbidden != FORBIDDEN_INSTALL_MUTATIONS:
        failures.append("b113:forbidden_mutation_contract_changed")
    elif any(forbidden.values()):
        failures.append("b113:forbidden_install_mutation_enabled")

    boundary = data.get("inherited_security_boundary")
    if boundary != INHERITED_SECURITY_BOUNDARY:
        failures.append("b113:security_boundary_changed")
    elif any(boundary.values()):
        failures.append("b113:security_authority_or_claim_expanded")

    return tuple(failures)


def self_check() -> dict[str, Any]:
    first = contract()
    second = contract()
    failures = list(validate_contract(first))
    deterministic = first == second and _digest(first) == _digest(second)
    if not deterministic:
        failures.append("b113:contract_not_deterministic")

    resources = first["planned_product_resources"]
    return {
        "passed": not failures,
        "failures": failures,
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "source_coverage": dict(SOURCE_COVERAGE),
        "verified_scenarios": list(VERIFIED_SCENARIOS),
        "contract_only": True,
        "contract_digest": _digest(first),
        "deterministic_contract": deterministic,
        "planned_resource_count": len(resources),
        "lifecycle_operation_count": len(LIFECYCLE_OPERATIONS),
        "installer_available": False,
        "uninstaller_available": False,
        "lifecycle_execution_available": False,
        "artifact_signed": False,
        "elevation_policy": ELEVATION_POLICY,
        "ownership_manifest_required": all(item["ownership_manifest_required"] for item in resources),
        "unknown_children_preserved": all(item["preserve_unknown_children"] for item in resources),
        "persistent_app_data_removed_by_default": False,
        "service_or_driver_installation_available": False,
        "autostart_registration_available": False,
        "authority_expanded": False,
        "coverage_promoted": False,
    }


def main() -> int:
    result = self_check()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

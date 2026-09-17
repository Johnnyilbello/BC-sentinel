from __future__ import annotations

import copy

from sentinel import beta11_install_lifecycle_contract as lifecycle


def _contract() -> dict:
    return lifecycle.contract()


def test_b113_contract_self_check_passes() -> None:
    result = lifecycle.self_check()
    assert result["passed"] is True
    assert result["failures"] == []
    assert result["source_checkpoint"] == "checkpoint/v011-beta11-b112-pass"
    assert result["source_checkpoint_commit"] == "92b6317aa9e642a0062268bce9f92bb0a4ffb1a1"
    assert result["planned_resource_count"] == 4
    assert result["lifecycle_operation_count"] == 4


def test_b113_is_contract_only_and_cannot_claim_installer_execution() -> None:
    data = _contract()
    assert data["contract_only"] is True
    assert data["installer_available"] is False
    assert data["uninstaller_available"] is False
    assert data["install_execution_available"] is False
    assert data["repair_execution_available"] is False
    assert data["upgrade_execution_available"] is False
    assert data["uninstall_execution_available"] is False
    assert data["artifact_signed"] is False


def test_b113_preserves_coverage_and_verified_identity() -> None:
    data = _contract()
    assert data["source_coverage"] == {"PARTIAL": 4, "GAP": 0, "VERIFIED": 2}
    assert data["verified_scenarios"] == ["B7-POWERSHELL-001", "B7-RANSOMWARE-001"]
    assert data["inherited_security_boundary"]["coverage_promoted"] is False
    assert data["inherited_security_boundary"]["broad_protection_claimed"] is False


def test_b113_resources_are_explicit_product_owned_and_manifest_bound() -> None:
    resources = _contract()["planned_product_resources"]
    assert [item["resource_id"] for item in resources] == [
        "APPLICATION_PAYLOAD",
        "UNINSTALL_METADATA",
        "START_MENU_SHORTCUT",
        "PERSISTENT_APP_DATA",
    ]
    assert all(item["product_owned"] is True for item in resources)
    assert all(item["ownership_manifest_required"] is True for item in resources)
    assert all(item["preserve_unknown_children"] is True for item in resources)


def test_b113_persistent_data_is_preserved_until_b115() -> None:
    data = _contract()
    resource = next(item for item in data["planned_product_resources"] if item["resource_id"] == "PERSISTENT_APP_DATA")
    assert resource["installer_may_create"] is False
    assert resource["uninstaller_may_remove"] is False
    assert resource["policy"] == "DEFERRED_TO_B11_5_PRESERVE_BY_DEFAULT"
    assert data["uninstall_safety"]["persistent_app_data_removed_by_default"] is False
    assert data["uninstall_safety"]["quarantine_removed_by_default"] is False
    assert data["uninstall_safety"]["logs_removed_by_default"] is False


def test_b113_lifecycle_operations_require_explicit_action_and_no_silent_mutation() -> None:
    operations = _contract()["lifecycle_operations"]
    assert [item["operation"] for item in operations] == ["INSTALL", "REPAIR", "UPGRADE", "UNINSTALL"]
    assert all(item["explicit_operator_action_required"] is True for item in operations)
    assert all(item["silent_mutation_enabled"] is False for item in operations)
    assert all(item["execution_available_in_b113"] is False for item in operations)
    assert all(item["elevation_policy"] == "ON_DEMAND_MACHINE_SCOPE_ONLY" for item in operations)


def test_b113_uninstall_fails_closed_without_ownership_evidence() -> None:
    safety = _contract()["uninstall_safety"]
    assert safety["ownership_proof"] == "EXACT_PRODUCT_OWNERSHIP_MANIFEST_REQUIRED"
    assert safety["missing_ownership_evidence_fails_closed"] is True
    assert safety["remove_only_manifested_product_resources"] is True
    assert safety["recursive_delete_outside_owned_roots"] is False
    assert safety["remove_unknown_files"] is False
    assert safety["remove_user_documents"] is False
    assert safety["remove_unrelated_registry_values"] is False
    assert safety["unknown_children_preserved"] is True


def test_b113_forbids_privileged_install_side_effects() -> None:
    forbidden = _contract()["forbidden_install_mutations"]
    assert forbidden
    assert not any(forbidden.values())
    for key in (
        "defender_exclusion_creation",
        "firewall_rule_creation",
        "scheduled_task_creation",
        "windows_service_installation",
        "kernel_driver_installation",
        "autostart_registration",
        "certificate_store_mutation",
        "automatic_update_registration",
    ):
        assert forbidden[key] is False


def test_b113_rejects_source_checkpoint_change() -> None:
    broken = copy.deepcopy(_contract())
    broken["source_checkpoint_commit"] = "0" * 40
    assert "b113:source_checkpoint_invalid" in lifecycle.validate_contract(broken)


def test_b113_rejects_coverage_promotion() -> None:
    broken = copy.deepcopy(_contract())
    broken["source_coverage"]["PARTIAL"] = 3
    broken["source_coverage"]["VERIFIED"] = 3
    assert "b113:coverage_changed" in lifecycle.validate_contract(broken)


def test_b113_rejects_premature_installer_or_uninstaller_claims() -> None:
    for key in (
        "installer_available",
        "uninstaller_available",
        "install_execution_available",
        "repair_execution_available",
        "upgrade_execution_available",
        "uninstall_execution_available",
        "artifact_signed",
    ):
        broken = copy.deepcopy(_contract())
        broken[key] = True
        assert f"b113:premature_capability:{key}" in lifecycle.validate_contract(broken)


def test_b113_rejects_unowned_or_unbounded_resource_changes() -> None:
    broken = copy.deepcopy(_contract())
    broken["planned_product_resources"][0]["path_token"] = "{SYSTEM_ROOT}\\System32"
    failures = lifecycle.validate_contract(broken)
    assert "b113:product_resource_contract_changed" in failures


def test_b113_rejects_silent_lifecycle_mutation() -> None:
    broken = copy.deepcopy(_contract())
    broken["lifecycle_operations"][0]["silent_mutation_enabled"] = True
    assert "b113:lifecycle_operation_contract_changed" in lifecycle.validate_contract(broken)


def test_b113_rejects_unsafe_uninstall_data_deletion() -> None:
    broken = copy.deepcopy(_contract())
    broken["uninstall_safety"]["persistent_app_data_removed_by_default"] = True
    assert "b113:uninstall_safety_changed" in lifecycle.validate_contract(broken)


def test_b113_rejects_service_driver_or_autostart_enablement() -> None:
    for key in ("windows_service_installation", "kernel_driver_installation", "autostart_registration"):
        broken = copy.deepcopy(_contract())
        broken["forbidden_install_mutations"][key] = True
        failures = lifecycle.validate_contract(broken)
        assert "b113:forbidden_mutation_contract_changed" in failures


def test_b113_rejects_security_authority_expansion() -> None:
    broken = copy.deepcopy(_contract())
    broken["inherited_security_boundary"]["privileged_system_mutation"] = True
    assert "b113:security_boundary_changed" in lifecycle.validate_contract(broken)


def test_b113_contract_is_deterministic() -> None:
    first = lifecycle.self_check()
    second = lifecycle.self_check()
    assert first["contract_digest"] == second["contract_digest"]
    assert first["deterministic_contract"] is True

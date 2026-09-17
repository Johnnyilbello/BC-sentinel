from __future__ import annotations

import copy

from sentinel import beta11_persistent_data_model as data_model


def _mutated() -> dict:
    return copy.deepcopy(data_model.model())


def test_b115_model_is_deterministic_and_valid() -> None:
    first = data_model.model()
    second = data_model.model()
    assert first == second
    assert data_model.validate_model(first) == ()
    report = data_model.self_check()
    assert report["passed"] is True
    assert report["deterministic_model"] is True
    assert len(report["model_digest"]) == 64


def test_b115_is_bound_to_exact_b114_checkpoint() -> None:
    model = data_model.model()
    assert model["source_checkpoint"] == "checkpoint/v011-beta11-b114-pass"
    assert model["source_checkpoint_commit"] == "5ec361050f4c490652f88c30ad3a3b60e586fecb"


def test_b115_canonical_machine_root_and_data_classes_are_distinct() -> None:
    model = data_model.model()
    assert model["machine_data_root"] == r"{PROGRAM_DATA}\BC Sentinel"
    classes = model["data_classes"]
    assert [item["class_id"] for item in classes] == [
        "CONFIG_STATE",
        "LOGS",
        "QUARANTINE_METADATA",
        "QUARANTINE_PAYLOADS",
        "LIFECYCLE_METADATA",
    ]
    assert len({item["path_token"].casefold() for item in classes}) == 5
    expected_prefix = "{program_data}\\bc sentinel\\"
    assert all(item["path_token"].casefold().startswith(expected_prefix) for item in classes)


def test_b115_all_persistent_classes_are_owned_and_preserved() -> None:
    for item in data_model.model()["data_classes"]:
        assert item["product_owned"] is True
        assert item["upgrade_behavior"] == "PRESERVE"
        assert item["rollback_behavior"] == "PRESERVE"
        assert item["uninstall_behavior"] == "PRESERVE_BY_DEFAULT"


def test_b115_quarantine_metadata_and_payload_are_separated() -> None:
    model = data_model.model()
    classes = {item["class_id"]: item for item in model["data_classes"]}
    metadata = classes["QUARANTINE_METADATA"]
    payloads = classes["QUARANTINE_PAYLOADS"]
    boundary = model["quarantine_boundary"]
    assert metadata["path_token"] != payloads["path_token"]
    assert metadata["contains_untrusted_payload"] is False
    assert payloads["contains_untrusted_payload"] is True
    assert payloads["permission_intent"] == "PRODUCT_RUNTIME_RESTRICTED_NO_EXECUTE"
    assert boundary["metadata_payload_separated"] is True
    assert boundary["payload_execution_allowed_from_store"] is False
    assert boundary["payload_treated_as_user_document"] is False
    assert boundary["payload_treated_as_log"] is False
    assert boundary["payload_treated_as_configuration"] is False


def test_b115_legacy_quarantine_migration_is_explicitly_deferred() -> None:
    boundary = data_model.model()["quarantine_boundary"]
    assert boundary["legacy_root"] == r"{LOCAL_APP_DATA}\BCSentinel\B656"
    assert boundary["legacy_migration_policy"] == "DEFERRED_TO_B11_6_NO_AUTOMATIC_MIGRATION"
    assert data_model.model()["implementation_state"]["legacy_migration_execution_available"] is False


def test_b115_uninstall_and_destructive_policy_fail_closed() -> None:
    gate = data_model.model()["destructive_lifecycle_gate"]
    assert gate["persistent_data_removed_by_default_on_uninstall"] is False
    assert gate["explicit_operator_purge_required"] is True
    assert gate["exact_ownership_manifest_required"] is True
    assert gate["exact_data_class_identity_required"] is True
    assert gate["unknown_children_block_destructive_action"] is True
    assert gate["unmanifested_entries_block_destructive_action"] is True
    assert gate["root_only_recursive_delete_allowed"] is False
    assert gate["destructive_execution_available_in_b115"] is False


def test_b115_destructive_decision_rejects_missing_ownership_unknown_and_unmanifested_data() -> None:
    decision = data_model.destructive_decision(
        data_class_id="LOGS",
        path_token=r"{PROGRAM_DATA}\BC Sentinel\logs",
        ownership_manifest_valid=False,
        explicit_operator_purge=True,
        unknown_children_present=True,
        unmanifested_entries_present=True,
    )
    assert decision["eligible_for_future_purge_contract"] is False
    assert decision["execution_available_in_b115"] is False
    assert decision["reasons"] == [
        "ownership_manifest_invalid",
        "unknown_children_present",
        "unmanifested_entries_present",
    ]


def test_b115_even_complete_future_purge_contract_does_not_execute() -> None:
    decision = data_model.destructive_decision(
        data_class_id="LOGS",
        path_token=r"{PROGRAM_DATA}\BC Sentinel\logs",
        ownership_manifest_valid=True,
        explicit_operator_purge=True,
        unknown_children_present=False,
        unmanifested_entries_present=False,
    )
    assert decision["eligible_for_future_purge_contract"] is True
    assert decision["execution_available_in_b115"] is False
    assert decision["reasons"] == []


def test_b115_destructive_decision_rejects_path_escape_and_unknown_class() -> None:
    decision = data_model.destructive_decision(
        data_class_id="USER_DOCUMENTS",
        path_token=r"{USER_PROFILE}\Documents",
        ownership_manifest_valid=True,
        explicit_operator_purge=True,
        unknown_children_present=False,
        unmanifested_entries_present=False,
    )
    assert decision["eligible_for_future_purge_contract"] is False
    assert "unknown_data_class" in decision["reasons"]
    assert "outside_canonical_root" in decision["reasons"]


def test_b115_has_no_mutating_implementation_authority() -> None:
    state = data_model.model()["implementation_state"]
    assert state
    assert not any(state.values())
    report = data_model.self_check()
    assert report["destructive_execution_available"] is False
    assert report["permission_enforcement_available"] is False
    assert report["migration_execution_available"] is False
    assert report["installer_or_uninstaller_execution_available"] is False
    assert report["authority_expanded"] is False


def test_b115_preserves_coverage_and_verified_scenarios() -> None:
    model = data_model.model()
    assert model["source_coverage"] == {"PARTIAL": 4, "GAP": 0, "VERIFIED": 2}
    assert model["verified_scenarios"] == ["B7-POWERSHELL-001", "B7-RANSOMWARE-001"]
    assert model["implementation_state"]["coverage_promoted"] is False


def test_b115_validator_rejects_path_or_uninstall_policy_change() -> None:
    broken = _mutated()
    broken["data_classes"][0]["path_token"] = r"{USER_PROFILE}\Documents\BC Sentinel"
    failures = data_model.validate_model(broken)
    assert "b115:data_class_contract_changed" in failures

    broken = _mutated()
    broken["data_classes"][0]["uninstall_behavior"] = "DELETE"
    failures = data_model.validate_model(broken)
    assert "b115:data_class_contract_changed" in failures


def test_b115_validator_rejects_destructive_or_migration_execution() -> None:
    broken = _mutated()
    broken["destructive_lifecycle_gate"]["destructive_execution_available_in_b115"] = True
    failures = data_model.validate_model(broken)
    assert "b115:destructive_gate_changed" in failures

    broken = _mutated()
    broken["implementation_state"]["legacy_migration_execution_available"] = True
    failures = data_model.validate_model(broken)
    assert "b115:implementation_state_changed" in failures


def test_b115_validator_rejects_coverage_or_checkpoint_promotion() -> None:
    broken = _mutated()
    broken["source_coverage"] = {"PARTIAL": 3, "GAP": 0, "VERIFIED": 3}
    assert "b115:coverage_changed" in data_model.validate_model(broken)

    broken = _mutated()
    broken["source_checkpoint_commit"] = "0" * 40
    assert "b115:source_checkpoint_invalid" in data_model.validate_model(broken)

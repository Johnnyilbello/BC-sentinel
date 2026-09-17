from __future__ import annotations

import copy
import hashlib

from sentinel import beta11_persistent_data_model as persistent
from sentinel import beta11_upgrade_migration_contract as migration


def _mutated() -> dict:
    return copy.deepcopy(migration.contract())


def _inventory() -> list[dict]:
    return [
        {
            "source_token": item["source_token"],
            "file_count": index + 1,
            "tree_digest": hashlib.sha256(item["mapping_id"].encode("utf-8")).hexdigest(),
        }
        for index, item in enumerate(migration.LEGACY_MAPPINGS)
    ]


def test_b116_contract_is_deterministic_and_valid() -> None:
    first = migration.contract()
    second = migration.contract()
    assert first == second
    assert migration.validate_contract(first) == ()
    report = migration.self_check()
    assert report["passed"] is True
    assert report["deterministic_contract"] is True
    assert len(report["contract_digest"]) == 64


def test_b116_is_bound_to_exact_b115_checkpoint_and_model() -> None:
    contract = migration.contract()
    assert contract["source_checkpoint"] == "checkpoint/v011-beta11-b115-pass"
    assert contract["source_checkpoint_commit"] == "19e40b9b41f4d87b3f081bb7e8bfb5b155db4660"
    assert contract["b115_model_digest"] == "38df2751392cd71bec8662c6d4f80b287c30aeb70841606399057254fe7a2a08"
    assert contract["b115_model_digest"] == persistent.self_check()["model_digest"]


def test_b116_preserves_coverage_and_verified_scenarios() -> None:
    contract = migration.contract()
    assert contract["source_coverage"] == {"PARTIAL": 4, "GAP": 0, "VERIFIED": 2}
    assert contract["verified_scenarios"] == ["B7-POWERSHELL-001", "B7-RANSOMWARE-001"]
    assert migration.IMPLEMENTATION_STATE["coverage_promoted"] is False
    assert migration.IMPLEMENTATION_STATE["authority_expanded"] is False


def test_b116_legacy_mapping_types_payloads_and_metadata_without_reclassification() -> None:
    mappings = {item["mapping_id"]: item for item in migration.contract()["legacy_mappings"]}
    assert mappings["B656_QUARANTINE_PAYLOADS"]["destination_class"] == "QUARANTINE_PAYLOADS"
    assert mappings["B656_ROLLBACK_SNAPSHOTS"]["destination_class"] == "QUARANTINE_PAYLOADS"
    assert mappings["B656_JOURNAL"]["destination_class"] == "QUARANTINE_METADATA"
    assert mappings["B658_HOME_RESTORE_RECORDS"]["destination_class"] == "QUARANTINE_METADATA"
    assert all(item["source_preserved_after_migration"] is True for item in mappings.values())
    assert all(item["execute_from_destination"] is False for item in mappings.values())


def test_b116_legacy_sources_stay_under_exact_b656_root_and_destinations_under_programdata() -> None:
    for item in migration.LEGACY_MAPPINGS:
        assert item["source_token"].casefold().startswith(migration.LEGACY_ROOT.casefold() + "\\")
        assert item["destination_token"].casefold().startswith(migration.MACHINE_DATA_ROOT.casefold() + "\\")


def test_b116_upgrade_mutation_phases_are_explicit_but_not_executable() -> None:
    phases = migration.contract()["upgrade_phases"]
    mutating = [item for item in phases if item["mutates_host"]]
    assert [item["phase"] for item in mutating] == [
        "BUILD_STAGING_COPY",
        "WRITE_LIFECYCLE_MANIFEST",
        "ACTIVATE_CANONICAL_DATASET",
    ]
    assert all(item["execution_available_in_b116"] is False for item in mutating)


def test_b116_migration_plan_is_deterministic_and_non_executing() -> None:
    kwargs = dict(
        ownership_manifest_valid=True,
        unknown_children_present=False,
        unmanifested_destination_entries_present=False,
        symlink_or_reparse_escape_present=False,
    )
    first = migration.build_migration_plan(_inventory(), **kwargs)
    second = migration.build_migration_plan(_inventory(), **kwargs)
    assert first == second
    assert first["eligible"] is True
    assert first["mapped_source_count"] == 4
    assert first["host_execution_available_in_b116"] is False
    assert first["source_dataset_delete_available_in_b116"] is False
    assert len(first["plan_digest"]) == 64


def test_b116_migration_plan_fails_closed_on_ownership_unknown_or_unmanifested_data() -> None:
    plan = migration.build_migration_plan(
        _inventory(),
        ownership_manifest_valid=False,
        unknown_children_present=True,
        unmanifested_destination_entries_present=True,
        symlink_or_reparse_escape_present=False,
    )
    assert plan["eligible"] is False
    assert plan["reasons"] == [
        "ownership_manifest_invalid",
        "unmanifested_destination_entries_present",
        "unknown_source_children_present",
    ]


def test_b116_migration_plan_rejects_unmapped_source_and_invalid_digest() -> None:
    inventory = _inventory()
    inventory.append(
        {
            "source_token": migration.LEGACY_ROOT + r"\unknown-child",
            "file_count": 1,
            "tree_digest": "not-a-sha256",
        }
    )
    plan = migration.build_migration_plan(
        inventory,
        ownership_manifest_valid=True,
        unknown_children_present=False,
        unmanifested_destination_entries_present=False,
        symlink_or_reparse_escape_present=False,
    )
    assert plan["eligible"] is False
    assert "inventory_source_not_mapped" in plan["reasons"]


def test_b116_migration_plan_rejects_symlink_or_reparse_escape() -> None:
    plan = migration.build_migration_plan(
        _inventory(),
        ownership_manifest_valid=True,
        unknown_children_present=False,
        unmanifested_destination_entries_present=False,
        symlink_or_reparse_escape_present=True,
    )
    assert plan["eligible"] is False
    assert plan["reasons"] == ["symlink_or_reparse_escape_present"]


def test_b116_config_migration_accepts_only_known_valid_schema_and_is_idempotent() -> None:
    payload = {"schema": migration.BASELINE_CONFIG_SCHEMA, "settings": {"telemetry": "local-only"}}
    digest = migration._digest(payload)
    first = migration.plan_config_migration(
        source_schema=migration.BASELINE_CONFIG_SCHEMA,
        source_payload=payload,
        source_digest=digest,
    )
    second = migration.plan_config_migration(
        source_schema=migration.BASELINE_CONFIG_SCHEMA,
        source_payload=payload,
        source_digest=digest,
    )
    assert first == second
    assert first["accepted"] is True
    assert first["destination_schema"] == migration.ACTIVE_CONFIG_SCHEMA
    assert first["transformed_payload"] == payload
    assert first["transformed_digest"] == digest
    assert first["source_payload_preserved"] is True
    assert first["write_execution_available_in_b116"] is False


def test_b116_config_migration_fails_closed_for_unknown_schema_bad_payload_or_digest() -> None:
    unknown = migration.plan_config_migration(
        source_schema="bc-sentinel-config-state-v99",
        source_payload={"settings": {}},
        source_digest="0" * 64,
    )
    assert unknown["accepted"] is False
    assert "unknown_or_future_config_schema" in unknown["reasons"]
    assert "source_config_digest_mismatch" in unknown["reasons"]

    malformed = migration.plan_config_migration(
        source_schema=migration.BASELINE_CONFIG_SCHEMA,
        source_payload=["not", "a", "dict"],
        source_digest=migration._digest(["not", "a", "dict"]),
    )
    assert malformed["accepted"] is False
    assert malformed["reasons"] == ["malformed_config_payload"]


def test_b116_rollback_is_non_destructive_and_does_not_restore_quarantine() -> None:
    plan = migration.build_rollback_plan(
        previous_dataset_id="dataset-b115",
        previous_manifest_digest="a" * 64,
        current_dataset_id="dataset-b116",
    )
    assert plan["eligible"] is True
    assert plan["current_dataset_preserved"] is True
    assert plan["legacy_source_preserved"] is True
    assert plan["quarantine_restore_implied"] is False
    assert plan["host_execution_available_in_b116"] is False


def test_b116_rollback_fails_closed_without_prior_identity_or_manifest() -> None:
    plan = migration.build_rollback_plan(
        previous_dataset_id="",
        previous_manifest_digest="bad",
        current_dataset_id="dataset-b116",
    )
    assert plan["eligible"] is False
    assert plan["reasons"] == [
        "previous_dataset_identity_missing",
        "previous_manifest_digest_invalid",
    ]


def test_b116_no_host_mutating_authority_is_enabled() -> None:
    state = migration.contract()["implementation_state"]
    assert state
    assert not any(state.values())
    report = migration.self_check()
    assert report["host_migration_execution_available"] is False
    assert report["host_upgrade_execution_available"] is False
    assert report["host_rollback_execution_available"] is False
    assert report["config_write_execution_available"] is False
    assert report["legacy_source_delete_available"] is False
    assert report["quarantine_restore_execution_available"] is False


def test_b116_validator_rejects_payload_reclassification_or_source_deletion() -> None:
    broken = _mutated()
    broken["legacy_mappings"][0]["destination_class"] = "CONFIG_STATE"
    assert "b116:legacy_mapping_contract_changed" in migration.validate_contract(broken)

    broken = _mutated()
    broken["legacy_mappings"][0]["source_preserved_after_migration"] = False
    assert "b116:legacy_mapping_contract_changed" in migration.validate_contract(broken)


def test_b116_validator_rejects_rollback_execution_or_quarantine_restore() -> None:
    broken = _mutated()
    broken["rollback_rules"]["rollback_execution_available_in_b116"] = True
    assert "b116:rollback_contract_changed" in migration.validate_contract(broken)

    broken = _mutated()
    broken["rollback_rules"]["quarantine_restore_implied_by_rollback"] = True
    assert "b116:rollback_contract_changed" in migration.validate_contract(broken)


def test_b116_validator_rejects_checkpoint_coverage_or_host_execution_promotion() -> None:
    broken = _mutated()
    broken["source_checkpoint_commit"] = "0" * 40
    assert "b116:source_checkpoint_invalid" in migration.validate_contract(broken)

    broken = _mutated()
    broken["source_coverage"] = {"PARTIAL": 3, "GAP": 0, "VERIFIED": 3}
    assert "b116:coverage_changed" in migration.validate_contract(broken)

    broken = _mutated()
    broken["implementation_state"]["host_migration_execution_available"] = True
    assert "b116:implementation_state_changed" in migration.validate_contract(broken)

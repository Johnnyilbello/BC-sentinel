from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel import beta11_clean_pc_lifecycle_acceptance as b118


def _workspace(tmp_path: Path, name: str = "case") -> Path:
    root = tmp_path / f"{b118.WORKSPACE_PREFIX}{name}"
    root.mkdir()
    b118.initialize_disposable_workspace(root, confirmed=True)
    return root


def test_contract_identity_and_predecessor_are_exact() -> None:
    data = b118.contract()
    assert data["schema"] == "bc-sentinel-beta11-clean-pc-lifecycle-acceptance-v1"
    assert data["profile"] == "v0.11.0-beta.11-b118-clean-pc-install-upgrade-uninstall-acceptance"
    assert data["source_checkpoint"] == "checkpoint/v011-beta11-b117-pass"
    assert data["source_checkpoint_commit"] == "c7ca5e86af196863cc980bcd1e8616447d9f3d8a"


def test_contract_binds_all_accepted_productization_contracts() -> None:
    data = b118.contract()
    assert data["source_b113_contract_digest"] == b118.SOURCE_B113_CONTRACT_DIGEST
    assert data["source_b115_model_digest"] == b118.SOURCE_B115_MODEL_DIGEST
    assert data["source_b116_contract_digest"] == b118.SOURCE_B116_CONTRACT_DIGEST
    assert data["source_b117_contract_digest"] == b118.SOURCE_B117_CONTRACT_DIGEST


def test_coverage_and_verified_scenarios_are_not_promoted() -> None:
    data = b118.contract()
    assert data["source_coverage"] == {"PARTIAL": 4, "GAP": 0, "VERIFIED": 2}
    assert data["verified_scenarios"] == ["B7-POWERSHELL-001", "B7-RANSOMWARE-001"]
    assert data["implementation_state"]["coverage_promoted"] is False


def test_only_disposable_workspace_execution_is_enabled() -> None:
    state = b118.contract()["implementation_state"]
    assert state["disposable_workspace_lifecycle_execution_available"] is True
    assert all(
        value is False
        for key, value in state.items()
        if key != "disposable_workspace_lifecycle_execution_available"
    )


def test_lifecycle_policy_preserves_data_and_unknown_children() -> None:
    policy = b118.contract()["lifecycle_policy"]
    assert policy["execution_scope"] == "EXPLICIT_DISPOSABLE_TEMP_WORKSPACE_ONLY"
    assert policy["persistent_data_preserved_across_upgrade"] is True
    assert policy["persistent_data_preserved_on_uninstall"] is True
    assert policy["unknown_children_preserved_on_uninstall"] is True
    assert policy["exact_ownership_manifest_required"] is True


def test_initialization_requires_explicit_confirmation(tmp_path: Path) -> None:
    root = tmp_path / f"{b118.WORKSPACE_PREFIX}confirm"
    root.mkdir()
    with pytest.raises(b118.LifecycleSafetyError, match="explicit_confirmation_required"):
        b118.initialize_disposable_workspace(root, confirmed=False)
    assert list(root.iterdir()) == []


def test_initialization_rejects_non_b118_workspace(tmp_path: Path) -> None:
    root = tmp_path / "ordinary-folder"
    root.mkdir()
    with pytest.raises(b118.LifecycleSafetyError, match="workspace_prefix_invalid"):
        b118.initialize_disposable_workspace(root, confirmed=True)
    assert list(root.iterdir()) == []


def test_initialization_requires_clean_workspace(tmp_path: Path) -> None:
    root = tmp_path / f"{b118.WORKSPACE_PREFIX}dirty"
    root.mkdir()
    (root / "existing.txt").write_text("not clean", encoding="utf-8")
    with pytest.raises(b118.LifecycleSafetyError, match="workspace_not_clean"):
        b118.initialize_disposable_workspace(root, confirmed=True)


def test_marker_tamper_fails_closed_before_install(tmp_path: Path) -> None:
    root = _workspace(tmp_path, "marker")
    marker = root / b118.MARKER_FILENAME
    marker.write_text("{}", encoding="utf-8")
    with pytest.raises(b118.LifecycleSafetyError, match="workspace_marker_invalid"):
        b118.install_fixture(root)
    assert not (root / b118.ARTIFACT_FIXTURE_REL).exists()


def test_path_escape_is_rejected(tmp_path: Path) -> None:
    root = _workspace(tmp_path, "escape")
    with pytest.raises(b118.LifecycleSafetyError, match="path_escape_rejected"):
        b118._safe_path(root.resolve(), "../outside.txt")


def test_clean_install_creates_exact_owned_fixture(tmp_path: Path) -> None:
    root = _workspace(tmp_path, "install")
    report = b118.install_fixture(root)
    assert report["operation"] == "INSTALL"
    assert report["managed_file_count"] == 4
    manifest = json.loads((root / b118.OWNERSHIP_MANIFEST_REL).read_text(encoding="utf-8"))
    assert manifest["persistent_data_removed_by_default"] is False
    assert manifest["unknown_children_preserved"] is True
    assert len(manifest["managed_files"]) == 4


def test_install_cannot_run_twice_over_existing_product(tmp_path: Path) -> None:
    root = _workspace(tmp_path, "double-install")
    b118.install_fixture(root)
    with pytest.raises(b118.LifecycleSafetyError, match="clean_install_workspace_not_empty"):
        b118.install_fixture(root)


def test_runtime_data_seeds_all_persistent_classes(tmp_path: Path) -> None:
    root = _workspace(tmp_path, "persistent")
    b118.install_fixture(root)
    report = b118.seed_runtime_persistent_data(root)
    assert report["persistent_file_count"] == 5
    assert len(report["persistent_tree_digest"]) == 64
    assert (root / b118.PERSISTENT_ROOT_REL / "quarantine" / "payloads" / "sample.quarantine").is_file()


def test_upgrade_keeps_previous_payload_and_persistent_data(tmp_path: Path) -> None:
    root = _workspace(tmp_path, "upgrade")
    b118.install_fixture(root)
    seeded = b118.seed_runtime_persistent_data(root)
    report = b118.upgrade_fixture(root)
    assert report["operation"] == "UPGRADE"
    assert report["kept_source_file_count"] == 2
    assert report["persistent_tree_digest_before"] == seeded["persistent_tree_digest"]
    assert report["persistent_tree_digest_after"] == seeded["persistent_tree_digest"]
    previous = root / "ProgramFiles" / "BC Sentinel" / ".previous" / "0.11.0-b118-a"
    assert (previous / "BC-Sentinel-Beta11.exe.fixture").is_file()
    assert (previous / "runtime-identity.json").is_file()


def test_upgrade_preserves_unknown_application_child(tmp_path: Path) -> None:
    root = _workspace(tmp_path, "upgrade-unknown")
    b118.install_fixture(root)
    b118.seed_runtime_persistent_data(root)
    unknown = root / "ProgramFiles" / "BC Sentinel" / "operator.keep"
    unknown.write_text("operator-owned", encoding="utf-8")
    b118.upgrade_fixture(root)
    assert unknown.read_text(encoding="utf-8") == "operator-owned"


def test_uninstall_preserves_persistent_data_and_unknown_child(tmp_path: Path) -> None:
    root = _workspace(tmp_path, "uninstall")
    b118.install_fixture(root)
    seeded = b118.seed_runtime_persistent_data(root)
    unknown = root / "ProgramFiles" / "BC Sentinel" / "operator.keep"
    unknown.write_text("operator-owned", encoding="utf-8")
    b118.upgrade_fixture(root)
    report = b118.uninstall_fixture(root)
    assert report["operation"] == "UNINSTALL"
    assert report["ownership_manifest_removed"] is True
    assert report["persistent_tree_digest_after"] == seeded["persistent_tree_digest"]
    assert unknown.read_text(encoding="utf-8") == "operator-owned"
    assert not (root / b118.ARTIFACT_FIXTURE_REL).exists()


def test_tampered_managed_file_blocks_uninstall_without_removing_it(tmp_path: Path) -> None:
    root = _workspace(tmp_path, "tamper")
    b118.install_fixture(root)
    artifact = root / b118.ARTIFACT_FIXTURE_REL
    artifact.write_bytes(b"tampered")
    with pytest.raises(b118.LifecycleSafetyError, match="managed_file_hash_mismatch"):
        b118.uninstall_fixture(root)
    assert artifact.read_bytes() == b"tampered"
    assert (root / b118.OWNERSHIP_MANIFEST_REL).is_file()


def test_missing_ownership_manifest_blocks_uninstall(tmp_path: Path) -> None:
    root = _workspace(tmp_path, "missing-manifest")
    b118.install_fixture(root)
    (root / b118.OWNERSHIP_MANIFEST_REL).unlink()
    with pytest.raises(b118.LifecycleSafetyError, match="ownership_manifest_missing"):
        b118.uninstall_fixture(root)
    assert (root / b118.ARTIFACT_FIXTURE_REL).is_file()


def test_full_disposable_lifecycle_acceptance_passes() -> None:
    report = b118.run_disposable_acceptance()
    assert report["passed"] is True
    assert report["event_count"] == 4
    assert report["unknown_child_preserved"] is True
    assert report["persistent_data_preserved"] is True
    assert report["outside_canary_preserved"] is True
    assert report["unsafe_scope_rejected"] is True
    assert len(report["transcript_digest"]) == 64


def test_lifecycle_transcript_is_deterministic() -> None:
    first = b118.run_disposable_acceptance()
    second = b118.run_disposable_acceptance()
    assert first["transcript_digest"] == second["transcript_digest"]
    assert first["events"] == second["events"]


def test_contract_validation_fails_if_host_execution_is_enabled() -> None:
    data = b118.contract()
    data["implementation_state"]["host_machine_scope_install_execution_available"] = True
    failures = b118.validate_contract(data)
    assert "b118:implementation_state_changed" in failures


def test_contract_validation_fails_if_coverage_changes() -> None:
    data = b118.contract()
    data["source_coverage"]["VERIFIED"] = 3
    assert "b118:coverage_changed" in b118.validate_contract(data)


def test_self_check_reports_no_authority_expansion() -> None:
    report = b118.self_check()
    assert report["passed"] is True
    assert report["failures"] == []
    assert report["disposable_workspace_lifecycle_execution_available"] is True
    assert report["host_machine_scope_install_execution_available"] is False
    assert report["host_machine_scope_upgrade_execution_available"] is False
    assert report["host_machine_scope_uninstall_execution_available"] is False
    assert report["host_registry_mutation_available"] is False
    assert report["privilege_elevation_available"] is False
    assert report["service_or_driver_registration_available"] is False
    assert report["autostart_registration_available"] is False
    assert report["network_required"] is False
    assert report["cloud_required"] is False
    assert report["coverage_promoted"] is False
    assert report["authority_expanded"] is False

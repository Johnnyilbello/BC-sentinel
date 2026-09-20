from __future__ import annotations

from sentinel import beta14_external_lab_provisioning_evidence as b149


def test_b149_binds_exact_b148_checkpoint() -> None:
    report = b149.self_check()
    assert report["passed"] is True
    assert report["source_checkpoint"] == "checkpoint/v014-b148-pass"
    assert report["source_checkpoint_commit"] == "8df6218b2db9e7738b2e2f719531fd24912ad0bc"


def test_b149_ci_fixture_is_valid_but_never_authoritative_physical_lab() -> None:
    fixture = b149.fixture_attestation(evidence_class=b149.EVIDENCE_CI)
    assert b149.validate_attestation(fixture) == ()
    summary = b149.readiness_summary(fixture)
    assert summary["passed"] is True
    assert summary["authoritative_physical_lab"] is False
    assert summary["t2_real_campaign_ready"] is False
    assert summary["t3_real_campaign_ready"] is False


def test_b149_real_host_observation_can_be_authoritative() -> None:
    fixture = b149.fixture_attestation(evidence_class=b149.EVIDENCE_REAL)
    summary = b149.readiness_summary(fixture)
    assert summary["passed"] is True
    assert summary["authoritative_physical_lab"] is True
    assert summary["t2_real_campaign_ready"] is True
    assert summary["t3_real_campaign_ready"] is True


def test_b149_rejects_direct_internet_bridge_and_normal_nat() -> None:
    for field in (
        "direct_internet_route_present",
        "bridged_networking_present",
        "normal_nat_to_internet_present",
    ):
        fixture = b149.fixture_attestation()
        fixture[field] = True
        assert f"b149:{field}_forbidden" in b149.validate_attestation(fixture)


def test_b149_requires_snapshot_create_revert_and_revert_drill() -> None:
    for field in (
        "snapshot_create_verified",
        "snapshot_revert_verified",
        "revert_drill_verified",
    ):
        fixture = b149.fixture_attestation()
        fixture[field] = False
        assert f"b149:{field}_required" in b149.validate_attestation(fixture)


def test_b149_rejects_shared_host_surfaces() -> None:
    for field in (
        "shared_folders_enabled",
        "shared_clipboard_enabled",
        "drag_drop_enabled",
        "usb_passthrough_enabled",
        "host_drive_mount_enabled",
    ):
        fixture = b149.fixture_attestation()
        fixture[field] = True
        assert f"b149:{field}_forbidden" in b149.validate_attestation(fixture)


def test_b149_rejects_real_user_data_and_credentials_on_host_or_guest() -> None:
    for field in (
        "host_has_real_user_data",
        "host_has_development_credentials",
        "guest_contains_real_user_data",
        "host_credentials_present_in_guest",
    ):
        fixture = b149.fixture_attestation()
        fixture[field] = True
        assert f"b149:{field}_forbidden" in b149.validate_attestation(fixture)


def test_b149_requires_internal_cape_channel_and_isolated_networks() -> None:
    for field in (
        "cape_agent_ready",
        "cape_result_channel_internal_only",
        "analysis_network_isolated",
        "management_network_separate",
        "host_firewall_protects_management_services",
    ):
        fixture = b149.fixture_attestation()
        fixture[field] = False
        assert f"b149:{field}_required" in b149.validate_attestation(fixture)


def test_b149_inetsim_requires_separate_service() -> None:
    fixture = b149.fixture_attestation()
    fixture["network_mode"] = b149.NETWORK_INETSIM
    fixture["inetsim_separate_service"] = False
    assert "b149:inetsim_separate_service_required" in b149.validate_attestation(fixture)


def test_b149_requires_authorization_and_one_sample_revert_workflows() -> None:
    for field in (
        "sample_authorization_workflow_ready",
        "one_sample_per_revert_workflow_ready",
        "b143_importer_ready",
        "t2_operator_drill_passed",
        "t3_operator_drill_passed",
    ):
        fixture = b149.fixture_attestation()
        fixture[field] = False
        assert f"b149:{field}_required" in b149.validate_attestation(fixture)


def test_b149_rejects_raw_or_sensitive_export_enablement() -> None:
    for field in ("raw_sample_bytes_export_enabled", "sensitive_export_enabled"):
        fixture = b149.fixture_attestation()
        fixture[field] = True
        assert f"b149:{field}_forbidden" in b149.validate_attestation(fixture)


def test_b149_module_has_no_vm_network_hypervisor_or_sample_authority() -> None:
    report = b149.self_check()
    assert report["module_creates_vms"] is False
    assert report["module_modifies_networking"] is False
    assert report["module_manages_hypervisor"] is False
    assert report["module_executes_samples"] is False
    assert report["module_downloads_samples"] is False
    assert report["module_stores_samples"] is False
    assert report["module_transfers_samples"] is False
    assert report["module_unpacks_samples"] is False


def test_b149_preserves_canonical_coverage() -> None:
    report = b149.self_check()
    assert report["source_coverage"] == {"PARTIAL": 4, "GAP": 0, "VERIFIED": 7}
    assert report["coverage_promoted"] is False
    assert report["authority_expanded"] is False


def test_b149_contract_is_deterministic() -> None:
    first = b149.self_check()
    second = b149.self_check()
    assert first["passed"] is True
    assert first["deterministic_contract"] is True
    assert first["contract_digest"] == second["contract_digest"]

from __future__ import annotations

from sentinel import beta14_isolated_lab_readiness as b146


def test_b146_binds_exact_b145_checkpoint() -> None:
    report = b146.self_check()
    assert report["passed"] is True
    assert report["source_checkpoint"] == "checkpoint/v014-b145-pass"
    assert report["source_checkpoint_commit"] == "e8fd49ca12f51e132d497913d01d3edc07f020a3"


def test_b146_baseline_profile_is_t2_t3_ready() -> None:
    profile = b146.baseline_profile()
    assert b146.validate_profile(profile) == ()
    summary = b146.readiness_summary(profile)
    assert summary["passed"] is True
    assert summary["t2_ready"] is True
    assert summary["t3_ready"] is True


def test_b146_accepts_only_none_drop_inetsim_network_modes() -> None:
    for mode in (b146.NETWORK_NONE, b146.NETWORK_DROP, b146.NETWORK_INETSIM):
        profile = b146.baseline_profile()
        profile["network_mode"] = mode
        if mode != b146.NETWORK_INETSIM:
            profile["fake_network_services_separate"] = False
        assert b146.validate_profile(profile) == ()


def test_b146_rejects_direct_internet() -> None:
    profile = b146.baseline_profile()
    profile["direct_internet_enabled"] = True
    assert "b146:direct_internet_enabled_forbidden" in b146.validate_profile(profile)


def test_b146_rejects_bridged_or_normal_nat_internet() -> None:
    profile = b146.baseline_profile()
    profile["bridged_networking_enabled"] = True
    assert "b146:bridged_networking_enabled_forbidden" in b146.validate_profile(profile)

    profile = b146.baseline_profile()
    profile["normal_nat_to_internet_enabled"] = True
    assert "b146:normal_nat_to_internet_enabled_forbidden" in b146.validate_profile(profile)


def test_b146_requires_dedicated_non_daily_host() -> None:
    profile = b146.baseline_profile()
    profile["dedicated_physical_host"] = False
    assert "b146:dedicated_physical_host_required" in b146.validate_profile(profile)

    profile = b146.baseline_profile()
    profile["daily_use_host"] = True
    assert "b146:daily_use_host_forbidden" in b146.validate_profile(profile)


def test_b146_requires_snapshot_and_verified_revert() -> None:
    profile = b146.baseline_profile()
    profile["snapshot_supported"] = False
    assert "b146:snapshot_supported_required" in b146.validate_profile(profile)

    profile = b146.baseline_profile()
    profile["snapshot_revert_verified"] = False
    assert "b146:snapshot_revert_verified_required" in b146.validate_profile(profile)


def test_b146_rejects_host_sharing_surfaces() -> None:
    for field in (
        "shared_folders_enabled",
        "shared_clipboard_enabled",
        "drag_drop_enabled",
        "usb_passthrough_enabled",
        "host_drive_mount_enabled",
    ):
        profile = b146.baseline_profile()
        profile[field] = True
        assert f"b146:{field}_forbidden" in b146.validate_profile(profile)


def test_b146_rejects_real_data_and_credentials_in_guest() -> None:
    profile = b146.baseline_profile()
    profile["guest_contains_real_user_data"] = True
    assert "b146:guest_contains_real_user_data_forbidden" in b146.validate_profile(profile)

    profile = b146.baseline_profile()
    profile["host_credentials_present_in_guest"] = True
    assert "b146:host_credentials_present_in_guest_forbidden" in b146.validate_profile(profile)


def test_b146_inetsim_requires_separate_fake_network_service() -> None:
    profile = b146.baseline_profile()
    profile["network_mode"] = b146.NETWORK_INETSIM
    profile["fake_network_services_separate"] = False
    assert "b146:inetsim_requires_separate_fake_services" in b146.validate_profile(profile)


def test_b146_rejects_raw_and_sensitive_exports() -> None:
    for field in (
        "raw_sample_bytes_exported",
        "raw_paths_exported",
        "command_lines_exported",
        "usernames_exported",
        "credentials_exported",
        "file_contents_exported",
    ):
        profile = b146.baseline_profile()
        profile[field] = True
        assert f"b146:{field}_forbidden" in b146.validate_profile(profile)


def test_b146_requires_sample_authorization_and_one_sample_per_revert_cycle() -> None:
    profile = b146.baseline_profile()
    profile["sample_authorization_required"] = False
    assert "b146:sample_authorization_required_required" in b146.validate_profile(profile)

    profile = b146.baseline_profile()
    profile["one_sample_per_revert_cycle"] = False
    assert "b146:one_sample_per_revert_cycle_required" in b146.validate_profile(profile)


def test_b146_requires_b143_importer_profile() -> None:
    profile = b146.baseline_profile()
    profile["evidence_importer_profile"] = "wrong"
    assert "b146:evidence_importer_profile_invalid" in b146.validate_profile(profile)


def test_b146_module_has_no_sample_or_hypervisor_authority() -> None:
    report = b146.self_check()
    assert report["sample_execution_capability_in_module"] is False
    assert report["sample_download_capability_in_module"] is False
    assert report["sample_transfer_capability_in_module"] is False
    assert report["hypervisor_mutation_capability_in_module"] is False


def test_b146_preserves_canonical_coverage_and_authority() -> None:
    report = b146.self_check()
    assert report["source_coverage"] == {"PARTIAL": 4, "GAP": 0, "VERIFIED": 7}
    assert report["coverage_promoted"] is False
    assert report["authority_expanded"] is False


def test_b146_contract_is_deterministic() -> None:
    first = b146.self_check()
    second = b146.self_check()
    assert first["passed"] is True
    assert first["deterministic_contract"] is True
    assert first["contract_digest"] == second["contract_digest"]

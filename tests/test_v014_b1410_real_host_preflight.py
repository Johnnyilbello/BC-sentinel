from __future__ import annotations

from sentinel import beta14_real_host_preflight as b1410


def test_b1410_binds_exact_b149_checkpoint() -> None:
    report = b1410.self_check()
    assert report["passed"] is True
    assert report["source_checkpoint"] == "checkpoint/v014-b149-pass"
    assert report["source_checkpoint_commit"] == "e743af638f97860aaa0cfebbdfdbf8efc484a973"


def test_b1410_fixture_passes_but_is_not_lab_authority() -> None:
    summary = b1410.summarize(b1410.fixture())
    assert summary["passed"] is True
    assert summary["real_host_preflight"] is True
    assert summary["ready_for_revert_drill"] is True
    assert summary["authoritative_physical_lab"] is False
    assert summary["t2_real_campaign_ready"] is False
    assert summary["t3_real_campaign_ready"] is False


def test_b1410_requires_linux_kvm_tooling_and_vm_snapshot() -> None:
    for field in (
        "kvm_device_present", "kvm_device_accessible", "virsh_present",
        "qemu_present", "virt_host_validate_present", "virt_host_validate_passed",
        "analysis_vm_present", "snapshot_present",
    ):
        item = b1410.fixture()
        item[field] = False
        assert f"b1410:{field}_required" in b1410.validate(item)


def test_b1410_requires_distinct_analysis_and_management_interfaces() -> None:
    for field in (
        "analysis_interface_present",
        "management_interface_present",
        "interfaces_distinct",
    ):
        item = b1410.fixture()
        item[field] = False
        assert f"b1410:{field}_required" in b1410.validate(item)


def test_b1410_rejects_default_route_on_analysis_interface() -> None:
    item = b1410.fixture()
    item["analysis_interface_has_default_route"] = True
    assert "b1410:analysis_default_route_forbidden" in b1410.validate(item)


def test_b1410_rejects_shared_filesystem_and_usb_passthrough() -> None:
    item = b1410.fixture()
    item["shared_filesystem_device_present"] = True
    assert "b1410:shared_filesystem_forbidden" in b1410.validate(item)

    item = b1410.fixture()
    item["usb_hostdev_present"] = True
    assert "b1410:usb_hostdev_forbidden" in b1410.validate(item)


def test_b1410_is_strictly_read_only() -> None:
    for field in (
        "direct_internet_test_performed",
        "sample_execution_performed",
        "network_configuration_modified",
        "hypervisor_state_modified",
    ):
        item = b1410.fixture()
        item[field] = True
        assert f"b1410:{field}_forbidden" in b1410.validate(item)


def test_b1410_preserves_coverage_and_authority() -> None:
    report = b1410.self_check()
    assert report["source_coverage"] == {"PARTIAL": 4, "GAP": 0, "VERIFIED": 7}
    assert report["coverage_promoted"] is False
    assert report["authority_expanded"] is False


def test_b1410_contract_is_deterministic() -> None:
    first = b1410.self_check()
    second = b1410.self_check()
    assert first["passed"] is True
    assert first["deterministic_contract"] is True
    assert first["contract_digest"] == second["contract_digest"]

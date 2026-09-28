from __future__ import annotations

"""B14-10 read-only real-host preflight for the dedicated CAPE/KVM lab.

The preflight validates sanitized observations produced on a dedicated Linux
host. It does not install packages, create VMs, modify networking, revert
snapshots, execute samples, or handle malware. Passing B14-10 means the host is
ready for the separate snapshot/revert drill; it does NOT yet make B14-9
REAL_HOST_OBSERVATION authoritative.
"""

import hashlib
import json
import re
from typing import Any, Final, Mapping

SCHEMA: Final[str] = "bc-sentinel-beta14-real-host-preflight-v1"
PROFILE: Final[str] = "v0.14.0-b1410-real-host-preflight"
SOURCE_CHECKPOINT: Final[str] = "checkpoint/v014-b149-pass"
SOURCE_CHECKPOINT_COMMIT: Final[str] = "e743af638f97860aaa0cfebbdfdbf8efc484a973"
SOURCE_COVERAGE: Final[dict[str, int]] = {"PARTIAL": 4, "GAP": 0, "VERIFIED": 7}

_REQUIRED: Final[set[str]] = {
    "schema", "evidence_class", "host_fingerprint_sha256", "host_os",
    "architecture", "kvm_device_present", "kvm_device_accessible",
    "virsh_present", "qemu_present", "virt_host_validate_present",
    "virt_host_validate_passed", "analysis_vm_present", "snapshot_present",
    "analysis_interface_present", "management_interface_present",
    "interfaces_distinct", "analysis_interface_has_default_route",
    "shared_filesystem_device_present", "usb_hostdev_present",
    "direct_internet_test_performed", "sample_execution_performed",
    "network_configuration_modified", "hypervisor_state_modified",
}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode()).hexdigest()


def _safe_digest(value: object) -> str:
    try:
        return _digest(value)
    except (TypeError, ValueError, OverflowError):
        return _digest({"invalid_observation_type": type(value).__name__})


def _valid_allowed_string(value: object, allowed: set[str] | frozenset[str]) -> bool:
    return isinstance(value, str) and value in allowed


def validate(observation: object) -> tuple[str, ...]:
    if not isinstance(observation, dict):
        return ("b1410:not_object",)
    f: list[str] = []
    if set(observation) != _REQUIRED:
        f.append("b1410:fields_invalid")
    if observation.get("schema") != SCHEMA:
        f.append("b1410:schema_invalid")
    if observation.get("evidence_class") != "REAL_HOST_PREFLIGHT":
        f.append("b1410:evidence_class_invalid")
    if not isinstance(observation.get("host_fingerprint_sha256"), str) or not _SHA256.fullmatch(str(observation.get("host_fingerprint_sha256")).lower()):
        f.append("b1410:host_fingerprint_invalid")
    if observation.get("host_os") != "LINUX":
        f.append("b1410:linux_host_required")
    if not _valid_allowed_string(observation.get("architecture"), {"x86_64", "amd64"}):
        f.append("b1410:architecture_invalid")

    for field in (
        "kvm_device_present", "kvm_device_accessible", "virsh_present",
        "qemu_present", "virt_host_validate_present", "virt_host_validate_passed",
        "analysis_vm_present", "snapshot_present", "analysis_interface_present",
        "management_interface_present", "interfaces_distinct",
    ):
        if observation.get(field) is not True:
            f.append(f"b1410:{field}_required")

    if observation.get("analysis_interface_has_default_route") is not False:
        f.append("b1410:analysis_default_route_forbidden")
    if observation.get("shared_filesystem_device_present") is not False:
        f.append("b1410:shared_filesystem_forbidden")
    if observation.get("usb_hostdev_present") is not False:
        f.append("b1410:usb_hostdev_forbidden")

    for field in (
        "direct_internet_test_performed", "sample_execution_performed",
        "network_configuration_modified", "hypervisor_state_modified",
    ):
        if observation.get(field) is not False:
            f.append(f"b1410:{field}_forbidden")

    return tuple(dict.fromkeys(f))


def summarize(observation: object) -> dict[str, Any]:
    failures = validate(observation)
    passed = not failures
    return {
        "passed": passed,
        "failures": list(failures),
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "source_coverage": dict(SOURCE_COVERAGE),
        "real_host_preflight": passed,
        "ready_for_revert_drill": passed,
        "authoritative_physical_lab": False,
        "t2_real_campaign_ready": False,
        "t3_real_campaign_ready": False,
        "read_only_observation": True,
        "sample_execution_performed": False,
        "network_configuration_modified": False,
        "hypervisor_state_modified": False,
        "coverage_promoted": False,
        "authority_expanded": False,
        "observation_digest": _safe_digest(observation),
    }


def fixture() -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "evidence_class": "REAL_HOST_PREFLIGHT",
        "host_fingerprint_sha256": "b" * 64,
        "host_os": "LINUX",
        "architecture": "x86_64",
        "kvm_device_present": True,
        "kvm_device_accessible": True,
        "virsh_present": True,
        "qemu_present": True,
        "virt_host_validate_present": True,
        "virt_host_validate_passed": True,
        "analysis_vm_present": True,
        "snapshot_present": True,
        "analysis_interface_present": True,
        "management_interface_present": True,
        "interfaces_distinct": True,
        "analysis_interface_has_default_route": False,
        "shared_filesystem_device_present": False,
        "usb_hostdev_present": False,
        "direct_internet_test_performed": False,
        "sample_execution_performed": False,
        "network_configuration_modified": False,
        "hypervisor_state_modified": False,
    }


def self_check() -> dict[str, Any]:
    base = fixture()
    failures = list(summarize(base)["failures"])

    bad = dict(base)
    bad["analysis_interface_has_default_route"] = True
    if "b1410:analysis_default_route_forbidden" not in validate(bad):
        failures.append("b1410:default_route_not_rejected")

    bad = dict(base)
    bad["shared_filesystem_device_present"] = True
    if "b1410:shared_filesystem_forbidden" not in validate(bad):
        failures.append("b1410:shared_fs_not_rejected")

    digest = _digest({
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
    })
    return {
        **summarize(base),
        "passed": not failures,
        "failures": failures,
        "contract_digest": digest,
        "deterministic_contract": digest == _digest({
            "schema": SCHEMA,
            "profile": PROFILE,
            "source_checkpoint": SOURCE_CHECKPOINT,
            "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        }),
    }


def main() -> int:
    result = self_check()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

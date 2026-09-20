from __future__ import annotations

"""B14-6 Isolated Lab Readiness Contract.

Defines and validates the external lab profile that is allowed to produce T2/T3
BC Sentinel evidence. This module does not create VMs, execute samples, open
network connections, download malware, or manage hypervisors. It only validates
a declarative lab profile and emits readiness evidence.

The contract follows the accepted Beta14 safety model:
- real samples stay outside the development repository and daily-use host;
- T2 is static/non-executing;
- T3 is external isolated disposable-lab only;
- direct Internet is rejected;
- snapshot/revert and cleanup evidence are mandatory;
- imported results must use the B14-3 sanitized evidence path.
"""

import hashlib
import json
import re
from typing import Any, Final, Mapping

SCHEMA: Final[str] = "bc-sentinel-beta14-isolated-lab-readiness-v1"
PROFILE: Final[str] = "v0.14.0-b146-isolated-lab-readiness"
SOURCE_CHECKPOINT: Final[str] = "checkpoint/v014-b145-pass"
SOURCE_CHECKPOINT_COMMIT: Final[str] = "e8fd49ca12f51e132d497913d01d3edc07f020a3"
SOURCE_COVERAGE: Final[dict[str, int]] = {"PARTIAL": 4, "GAP": 0, "VERIFIED": 7}

NETWORK_NONE: Final[str] = "NONE"
NETWORK_DROP: Final[str] = "DROP"
NETWORK_INETSIM: Final[str] = "INETSIM"
ALLOWED_NETWORK_MODES: Final[set[str]] = {
    NETWORK_NONE,
    NETWORK_DROP,
    NETWORK_INETSIM,
}

HYPERVISORS: Final[set[str]] = {
    "KVM",
    "VIRTUALBOX",
    "VMWARE_WORKSTATION",
    "XENSERVER",
}

_REQUIRED_FIELDS: Final[set[str]] = {
    "schema",
    "lab_id",
    "dedicated_physical_host",
    "daily_use_host",
    "hypervisor",
    "snapshot_supported",
    "clean_snapshot_id",
    "snapshot_revert_verified",
    "guest_os",
    "guest_contains_real_user_data",
    "host_credentials_present_in_guest",
    "network_mode",
    "analysis_network_isolated",
    "bridged_networking_enabled",
    "normal_nat_to_internet_enabled",
    "direct_internet_enabled",
    "shared_folders_enabled",
    "shared_clipboard_enabled",
    "drag_drop_enabled",
    "usb_passthrough_enabled",
    "host_drive_mount_enabled",
    "cape_result_channel_internal_only",
    "fake_network_services_separate",
    "sample_authorization_required",
    "one_sample_per_revert_cycle",
    "cleanup_revert_required",
    "evidence_importer_profile",
    "raw_sample_bytes_exported",
    "raw_paths_exported",
    "command_lines_exported",
    "usernames_exported",
    "credentials_exported",
    "file_contents_exported",
    "t2_static_real_sample_ready",
    "t3_dynamic_real_sample_ready",
}

_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,160}$")

SAFETY_BOUNDARIES: Final[dict[str, bool]] = {
    "lab_profile_can_execute_samples": False,
    "lab_profile_can_download_samples": False,
    "lab_profile_can_transfer_samples": False,
    "lab_profile_can_create_network_routes": False,
    "lab_profile_can_mutate_hypervisor": False,
    "direct_internet_allowed": False,
    "sample_bytes_export_allowed": False,
    "coverage_promoted": False,
    "authority_expanded": False,
}


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _valid_id(value: object) -> bool:
    return isinstance(value, str) and bool(_ID_RE.fullmatch(value))


def validate_profile(profile: object) -> tuple[str, ...]:
    if not isinstance(profile, dict):
        return ("b146:not_object",)

    failures: list[str] = []
    if set(profile) != _REQUIRED_FIELDS:
        failures.append("b146:fields_invalid")
    if profile.get("schema") != SCHEMA:
        failures.append("b146:schema_invalid")
    if not _valid_id(profile.get("lab_id")):
        failures.append("b146:lab_id_invalid")
    if profile.get("hypervisor") not in HYPERVISORS:
        failures.append("b146:hypervisor_invalid")
    if not _valid_id(profile.get("clean_snapshot_id")):
        failures.append("b146:clean_snapshot_id_invalid")
    if profile.get("guest_os") not in {"WINDOWS_10_X64", "WINDOWS_11_X64"}:
        failures.append("b146:guest_os_invalid")
    if profile.get("network_mode") not in ALLOWED_NETWORK_MODES:
        failures.append("b146:network_mode_invalid")
    if profile.get("evidence_importer_profile") != "v0.14.0-b143-isolated-lab-evidence-importer":
        failures.append("b146:evidence_importer_profile_invalid")

    required_true = (
        "dedicated_physical_host",
        "snapshot_supported",
        "snapshot_revert_verified",
        "analysis_network_isolated",
        "cape_result_channel_internal_only",
        "sample_authorization_required",
        "one_sample_per_revert_cycle",
        "cleanup_revert_required",
    )
    for field in required_true:
        if profile.get(field) is not True:
            failures.append(f"b146:{field}_required")

    required_false = (
        "daily_use_host",
        "guest_contains_real_user_data",
        "host_credentials_present_in_guest",
        "bridged_networking_enabled",
        "normal_nat_to_internet_enabled",
        "direct_internet_enabled",
        "shared_folders_enabled",
        "shared_clipboard_enabled",
        "drag_drop_enabled",
        "usb_passthrough_enabled",
        "host_drive_mount_enabled",
        "raw_sample_bytes_exported",
        "raw_paths_exported",
        "command_lines_exported",
        "usernames_exported",
        "credentials_exported",
        "file_contents_exported",
    )
    for field in required_false:
        if profile.get(field) is not False:
            failures.append(f"b146:{field}_forbidden")

    if profile.get("network_mode") == NETWORK_INETSIM:
        if profile.get("fake_network_services_separate") is not True:
            failures.append("b146:inetsim_requires_separate_fake_services")
    else:
        if profile.get("fake_network_services_separate") not in {True, False}:
            failures.append("b146:fake_network_services_flag_invalid")

    if profile.get("t2_static_real_sample_ready") is not True:
        failures.append("b146:t2_readiness_required")
    if profile.get("t3_dynamic_real_sample_ready") is not True:
        failures.append("b146:t3_readiness_required")

    return tuple(dict.fromkeys(failures))


def readiness_summary(profile: Mapping[str, Any]) -> dict[str, Any]:
    failures = validate_profile(dict(profile))
    if failures:
        return {
            "passed": False,
            "failures": list(failures),
            "t2_ready": False,
            "t3_ready": False,
        }

    return {
        "passed": True,
        "failures": [],
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "source_coverage": dict(SOURCE_COVERAGE),
        "lab_id": profile["lab_id"],
        "hypervisor": profile["hypervisor"],
        "network_mode": profile["network_mode"],
        "snapshot_revert_verified": True,
        "t2_ready": True,
        "t3_ready": True,
        "direct_internet": False,
        "bridged_networking": False,
        "normal_nat_to_internet": False,
        "shared_host_surfaces": False,
        "sample_bytes_exported": False,
        "sensitive_exports": False,
        "b143_importer_required": True,
        "one_sample_per_revert_cycle": True,
        "coverage_promoted": False,
        "authority_expanded": False,
        "readiness_digest": _digest(dict(profile)),
    }


def baseline_profile() -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "lab_id": "bc-sentinel-lab-b146",
        "dedicated_physical_host": True,
        "daily_use_host": False,
        "hypervisor": "KVM",
        "snapshot_supported": True,
        "clean_snapshot_id": "win11-clean-b146",
        "snapshot_revert_verified": True,
        "guest_os": "WINDOWS_11_X64",
        "guest_contains_real_user_data": False,
        "host_credentials_present_in_guest": False,
        "network_mode": NETWORK_INETSIM,
        "analysis_network_isolated": True,
        "bridged_networking_enabled": False,
        "normal_nat_to_internet_enabled": False,
        "direct_internet_enabled": False,
        "shared_folders_enabled": False,
        "shared_clipboard_enabled": False,
        "drag_drop_enabled": False,
        "usb_passthrough_enabled": False,
        "host_drive_mount_enabled": False,
        "cape_result_channel_internal_only": True,
        "fake_network_services_separate": True,
        "sample_authorization_required": True,
        "one_sample_per_revert_cycle": True,
        "cleanup_revert_required": True,
        "evidence_importer_profile": "v0.14.0-b143-isolated-lab-evidence-importer",
        "raw_sample_bytes_exported": False,
        "raw_paths_exported": False,
        "command_lines_exported": False,
        "usernames_exported": False,
        "credentials_exported": False,
        "file_contents_exported": False,
        "t2_static_real_sample_ready": True,
        "t3_dynamic_real_sample_ready": True,
    }


def contract() -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "source_coverage": dict(SOURCE_COVERAGE),
        "allowed_network_modes": sorted(ALLOWED_NETWORK_MODES),
        "allowed_hypervisors": sorted(HYPERVISORS),
        "safety_boundaries": dict(SAFETY_BOUNDARIES),
    }


def self_check() -> dict[str, Any]:
    failures: list[str] = []
    base = baseline_profile()
    summary = readiness_summary(base)
    if summary.get("passed") is not True:
        failures.append("b146:baseline_profile_failed")

    direct = dict(base)
    direct["direct_internet_enabled"] = True
    if "b146:direct_internet_enabled_forbidden" not in validate_profile(direct):
        failures.append("b146:direct_internet_not_rejected")

    bridged = dict(base)
    bridged["bridged_networking_enabled"] = True
    if "b146:bridged_networking_enabled_forbidden" not in validate_profile(bridged):
        failures.append("b146:bridged_network_not_rejected")

    no_revert = dict(base)
    no_revert["snapshot_revert_verified"] = False
    if "b146:snapshot_revert_verified_required" not in validate_profile(no_revert):
        failures.append("b146:no_revert_not_rejected")

    shared = dict(base)
    shared["shared_folders_enabled"] = True
    if "b146:shared_folders_enabled_forbidden" not in validate_profile(shared):
        failures.append("b146:shared_folder_not_rejected")

    raw = dict(base)
    raw["raw_sample_bytes_exported"] = True
    if "b146:raw_sample_bytes_exported_forbidden" not in validate_profile(raw):
        failures.append("b146:raw_sample_export_not_rejected")

    contract_digest = _digest(contract())
    deterministic = contract_digest == _digest(contract())
    if not deterministic:
        failures.append("b146:contract_not_deterministic")

    return {
        "passed": not failures,
        "failures": list(dict.fromkeys(failures)),
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "source_coverage": dict(SOURCE_COVERAGE),
        "t2_ready": summary.get("t2_ready") is True,
        "t3_ready": summary.get("t3_ready") is True,
        "direct_internet_rejected": True,
        "bridged_network_rejected": True,
        "missing_revert_rejected": True,
        "shared_host_surface_rejected": True,
        "raw_sample_export_rejected": True,
        "sample_execution_capability_in_module": False,
        "sample_download_capability_in_module": False,
        "sample_transfer_capability_in_module": False,
        "hypervisor_mutation_capability_in_module": False,
        "coverage_promoted": False,
        "authority_expanded": False,
        "contract_digest": contract_digest,
        "deterministic_contract": deterministic,
    }


def main() -> int:
    result = self_check()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

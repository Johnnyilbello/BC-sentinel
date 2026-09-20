from __future__ import annotations

"""B14-9 External Lab Provisioning Evidence.

Validates a sanitized attestation describing the real external malware-analysis
lab. CI fixtures can exercise this contract, but CI can never claim that a
physical lab exists. Only REAL_HOST_OBSERVATION evidence may become
authoritative.

This module does not create VMs, modify host networking, execute samples,
download malware, or manage a hypervisor. It only validates provisioning
evidence and exposes whether the lab is ready for later T2/T3 campaigns.
"""

import hashlib
import json
import re
from typing import Any, Final, Mapping

SCHEMA: Final[str] = "bc-sentinel-beta14-external-lab-provisioning-evidence-v1"
PROFILE: Final[str] = "v0.14.0-b149-external-lab-provisioning-evidence"
SOURCE_CHECKPOINT: Final[str] = "checkpoint/v014-b148-pass"
SOURCE_CHECKPOINT_COMMIT: Final[str] = "8df6218b2db9e7738b2e2f719531fd24912ad0bc"
SOURCE_COVERAGE: Final[dict[str, int]] = {"PARTIAL": 4, "GAP": 0, "VERIFIED": 7}

EVIDENCE_CI: Final[str] = "CI_FIXTURE"
EVIDENCE_REAL: Final[str] = "REAL_HOST_OBSERVATION"
ALLOWED_EVIDENCE_CLASSES: Final[set[str]] = {EVIDENCE_CI, EVIDENCE_REAL}

NETWORK_NONE: Final[str] = "NONE"
NETWORK_DROP: Final[str] = "DROP"
NETWORK_INETSIM: Final[str] = "INETSIM"
ALLOWED_NETWORK_MODES: Final[set[str]] = {
    NETWORK_NONE,
    NETWORK_DROP,
    NETWORK_INETSIM,
}

ALLOWED_HYPERVISORS: Final[set[str]] = {
    "KVM",
    "VIRTUALBOX",
    "VMWARE_WORKSTATION",
    "XENSERVER",
}

_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,160}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

_REQUIRED_FIELDS: Final[set[str]] = {
    "schema",
    "evidence_class",
    "attestation_id",
    "lab_id",
    "host_fingerprint_sha256",
    "dedicated_physical_host",
    "daily_use_host",
    "host_has_real_user_data",
    "host_has_development_credentials",
    "hypervisor",
    "analysis_vm_id",
    "clean_snapshot_id",
    "snapshot_create_verified",
    "snapshot_revert_verified",
    "revert_drill_verified",
    "guest_os",
    "guest_contains_real_user_data",
    "host_credentials_present_in_guest",
    "cape_agent_ready",
    "cape_result_channel_internal_only",
    "network_mode",
    "analysis_network_isolated",
    "management_network_separate",
    "direct_internet_route_present",
    "bridged_networking_present",
    "normal_nat_to_internet_present",
    "inetsim_separate_service",
    "host_firewall_protects_management_services",
    "shared_folders_enabled",
    "shared_clipboard_enabled",
    "drag_drop_enabled",
    "usb_passthrough_enabled",
    "host_drive_mount_enabled",
    "sample_authorization_workflow_ready",
    "one_sample_per_revert_workflow_ready",
    "b143_importer_ready",
    "raw_sample_bytes_export_enabled",
    "sensitive_export_enabled",
    "t2_operator_drill_passed",
    "t3_operator_drill_passed",
}

SAFETY_BOUNDARIES: Final[dict[str, bool]] = {
    "module_creates_vms": False,
    "module_modifies_networking": False,
    "module_manages_hypervisor": False,
    "module_executes_samples": False,
    "module_downloads_samples": False,
    "module_stores_samples": False,
    "module_transfers_samples": False,
    "module_unpacks_samples": False,
    "ci_can_claim_physical_lab": False,
    "coverage_promoted": False,
    "authority_expanded": False,
}


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _valid_id(value: object) -> bool:
    return isinstance(value, str) and bool(_ID_RE.fullmatch(value))


def _valid_sha256(value: object) -> bool:
    return isinstance(value, str) and bool(_SHA256_RE.fullmatch(value.lower()))


def validate_attestation(attestation: object) -> tuple[str, ...]:
    if not isinstance(attestation, dict):
        return ("b149:not_object",)

    failures: list[str] = []
    if set(attestation) != _REQUIRED_FIELDS:
        failures.append("b149:fields_invalid")
    if attestation.get("schema") != SCHEMA:
        failures.append("b149:schema_invalid")
    if attestation.get("evidence_class") not in ALLOWED_EVIDENCE_CLASSES:
        failures.append("b149:evidence_class_invalid")

    for field in ("attestation_id", "lab_id", "analysis_vm_id", "clean_snapshot_id"):
        if not _valid_id(attestation.get(field)):
            failures.append(f"b149:{field}_invalid")
    if not _valid_sha256(attestation.get("host_fingerprint_sha256")):
        failures.append("b149:host_fingerprint_invalid")

    if attestation.get("hypervisor") not in ALLOWED_HYPERVISORS:
        failures.append("b149:hypervisor_invalid")
    if attestation.get("guest_os") not in {"WINDOWS_10_X64", "WINDOWS_11_X64"}:
        failures.append("b149:guest_os_invalid")
    if attestation.get("network_mode") not in ALLOWED_NETWORK_MODES:
        failures.append("b149:network_mode_invalid")

    required_true = (
        "dedicated_physical_host",
        "snapshot_create_verified",
        "snapshot_revert_verified",
        "revert_drill_verified",
        "cape_agent_ready",
        "cape_result_channel_internal_only",
        "analysis_network_isolated",
        "management_network_separate",
        "host_firewall_protects_management_services",
        "sample_authorization_workflow_ready",
        "one_sample_per_revert_workflow_ready",
        "b143_importer_ready",
        "t2_operator_drill_passed",
        "t3_operator_drill_passed",
    )
    for field in required_true:
        if attestation.get(field) is not True:
            failures.append(f"b149:{field}_required")

    required_false = (
        "daily_use_host",
        "host_has_real_user_data",
        "host_has_development_credentials",
        "guest_contains_real_user_data",
        "host_credentials_present_in_guest",
        "direct_internet_route_present",
        "bridged_networking_present",
        "normal_nat_to_internet_present",
        "shared_folders_enabled",
        "shared_clipboard_enabled",
        "drag_drop_enabled",
        "usb_passthrough_enabled",
        "host_drive_mount_enabled",
        "raw_sample_bytes_export_enabled",
        "sensitive_export_enabled",
    )
    for field in required_false:
        if attestation.get(field) is not False:
            failures.append(f"b149:{field}_forbidden")

    if attestation.get("network_mode") == NETWORK_INETSIM:
        if attestation.get("inetsim_separate_service") is not True:
            failures.append("b149:inetsim_separate_service_required")
    elif attestation.get("inetsim_separate_service") not in {True, False}:
        failures.append("b149:inetsim_flag_invalid")

    return tuple(dict.fromkeys(failures))


def authoritative_physical_lab(attestation: Mapping[str, Any]) -> bool:
    if validate_attestation(dict(attestation)):
        return False
    return attestation["evidence_class"] == EVIDENCE_REAL


def readiness_summary(attestation: Mapping[str, Any]) -> dict[str, Any]:
    failures = validate_attestation(dict(attestation))
    if failures:
        return {
            "passed": False,
            "failures": list(failures),
            "authoritative_physical_lab": False,
            "t2_real_campaign_ready": False,
            "t3_real_campaign_ready": False,
        }

    authoritative = authoritative_physical_lab(attestation)
    return {
        "passed": True,
        "failures": [],
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "source_coverage": dict(SOURCE_COVERAGE),
        "evidence_class": attestation["evidence_class"],
        "attestation_id": attestation["attestation_id"],
        "lab_id": attestation["lab_id"],
        "hypervisor": attestation["hypervisor"],
        "network_mode": attestation["network_mode"],
        "authoritative_physical_lab": authoritative,
        "t2_real_campaign_ready": authoritative,
        "t3_real_campaign_ready": authoritative,
        "snapshot_revert_verified": True,
        "revert_drill_verified": True,
        "direct_internet": False,
        "bridged_networking": False,
        "normal_nat_to_internet": False,
        "shared_host_surfaces": False,
        "sample_bytes_export_enabled": False,
        "sensitive_exports_enabled": False,
        "b143_importer_ready": True,
        "coverage_promoted": False,
        "authority_expanded": False,
        "attestation_digest": _digest(dict(attestation)),
    }


def fixture_attestation(*, evidence_class: str = EVIDENCE_CI) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "evidence_class": evidence_class,
        "attestation_id": "b149-fixture-attestation",
        "lab_id": "bc-sentinel-external-lab",
        "host_fingerprint_sha256": "a" * 64,
        "dedicated_physical_host": True,
        "daily_use_host": False,
        "host_has_real_user_data": False,
        "host_has_development_credentials": False,
        "hypervisor": "KVM",
        "analysis_vm_id": "bc-sentinel-win11-analysis",
        "clean_snapshot_id": "bc-sentinel-win11-clean",
        "snapshot_create_verified": True,
        "snapshot_revert_verified": True,
        "revert_drill_verified": True,
        "guest_os": "WINDOWS_11_X64",
        "guest_contains_real_user_data": False,
        "host_credentials_present_in_guest": False,
        "cape_agent_ready": True,
        "cape_result_channel_internal_only": True,
        "network_mode": NETWORK_INETSIM,
        "analysis_network_isolated": True,
        "management_network_separate": True,
        "direct_internet_route_present": False,
        "bridged_networking_present": False,
        "normal_nat_to_internet_present": False,
        "inetsim_separate_service": True,
        "host_firewall_protects_management_services": True,
        "shared_folders_enabled": False,
        "shared_clipboard_enabled": False,
        "drag_drop_enabled": False,
        "usb_passthrough_enabled": False,
        "host_drive_mount_enabled": False,
        "sample_authorization_workflow_ready": True,
        "one_sample_per_revert_workflow_ready": True,
        "b143_importer_ready": True,
        "raw_sample_bytes_export_enabled": False,
        "sensitive_export_enabled": False,
        "t2_operator_drill_passed": True,
        "t3_operator_drill_passed": True,
    }


def contract() -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "source_coverage": dict(SOURCE_COVERAGE),
        "evidence_classes": sorted(ALLOWED_EVIDENCE_CLASSES),
        "network_modes": sorted(ALLOWED_NETWORK_MODES),
        "hypervisors": sorted(ALLOWED_HYPERVISORS),
        "safety_boundaries": dict(SAFETY_BOUNDARIES),
    }


def self_check() -> dict[str, Any]:
    failures: list[str] = []
    fixture = fixture_attestation(evidence_class=EVIDENCE_CI)
    summary = readiness_summary(fixture)
    if summary.get("passed") is not True:
        failures.append("b149:fixture_failed")
    if summary.get("authoritative_physical_lab") is not False:
        failures.append("b149:ci_fixture_claimed_physical_lab")
    if summary.get("t2_real_campaign_ready") is not False:
        failures.append("b149:ci_fixture_claimed_t2_ready")
    if summary.get("t3_real_campaign_ready") is not False:
        failures.append("b149:ci_fixture_claimed_t3_ready")

    direct = dict(fixture)
    direct["direct_internet_route_present"] = True
    if "b149:direct_internet_route_present_forbidden" not in validate_attestation(direct):
        failures.append("b149:direct_internet_not_rejected")

    no_revert = dict(fixture)
    no_revert["revert_drill_verified"] = False
    if "b149:revert_drill_verified_required" not in validate_attestation(no_revert):
        failures.append("b149:no_revert_drill_not_rejected")

    shared = dict(fixture)
    shared["shared_folders_enabled"] = True
    if "b149:shared_folders_enabled_forbidden" not in validate_attestation(shared):
        failures.append("b149:shared_folder_not_rejected")

    ci_real = dict(fixture)
    ci_real["evidence_class"] = EVIDENCE_REAL
    real_summary = readiness_summary(ci_real)
    if real_summary.get("authoritative_physical_lab") is not True:
        failures.append("b149:real_observation_not_authoritative")

    contract_digest = _digest(contract())
    deterministic = contract_digest == _digest(contract())
    if not deterministic:
        failures.append("b149:contract_not_deterministic")

    return {
        "passed": not failures,
        "failures": list(dict.fromkeys(failures)),
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "source_coverage": dict(SOURCE_COVERAGE),
        "ci_fixture_valid": summary.get("passed") is True,
        "ci_fixture_authoritative_physical_lab": False,
        "ci_fixture_t2_real_campaign_ready": False,
        "ci_fixture_t3_real_campaign_ready": False,
        "real_observation_can_be_authoritative": real_summary.get("authoritative_physical_lab") is True,
        "direct_internet_rejected": True,
        "missing_revert_drill_rejected": True,
        "shared_host_surface_rejected": True,
        "module_creates_vms": False,
        "module_modifies_networking": False,
        "module_manages_hypervisor": False,
        "module_executes_samples": False,
        "module_downloads_samples": False,
        "module_stores_samples": False,
        "module_transfers_samples": False,
        "module_unpacks_samples": False,
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

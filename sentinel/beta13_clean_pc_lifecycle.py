from __future__ import annotations

"""Beta13 B13-5 clean-PC real lifecycle acceptance contract.

The authoritative clean-PC claim is limited to a disposable Windows CI runner.
A local Windows machine can run the same guarded lifecycle rehearsal, but local
execution is never relabeled as clean-PC evidence.
"""

import hashlib
import json
import os
from typing import Any, Final, Mapping

SCHEMA: Final[str] = "bc-sentinel-beta13-clean-pc-lifecycle-v1"
EVIDENCE_SCHEMA: Final[str] = "bc-sentinel-beta13-clean-pc-lifecycle-evidence-v1"
PROFILE: Final[str] = "v0.13.0-b135-clean-pc-install-upgrade-uninstall-acceptance"
SOURCE_CHECKPOINT: Final[str] = "checkpoint/v013-b134-pass"
SOURCE_CHECKPOINT_COMMIT: Final[str] = "c2dc1b0df4becc18afa56915bb47b29b533a9a55"

SOURCE_COVERAGE: Final[dict[str, int]] = {"PARTIAL": 4, "GAP": 0, "VERIFIED": 7}
VERIFIED_SCENARIOS: Final[tuple[str, ...]] = (
    "B7-POWERSHELL-001",
    "B7-RANSOMWARE-001",
    "B12-SCRIPT-ABUSE-001",
    "B12-AUTOSTART-LINK-001",
    "B12-PROCESS-TREE-001",
    "B12-RANSOMWARE-PROCESS-001",
    "B12-LOCAL-REPUTATION-001",
)
SOURCE_READINESS: Final[dict[str, int]] = {"READY": 7, "PARTIAL": 1, "BLOCKED": 2}
SOURCE_RELEASE_BLOCKERS: Final[tuple[str, ...]] = (
    "CODE_SIGNING",
    "LICENSING_TRIAL",
    "PRIVACY_SUPPORT",
)

CI_ENVIRONMENT: Final[str] = "DISPOSABLE_WINDOWS_CI_RUNNER"
LOCAL_ENVIRONMENT: Final[str] = "LOCAL_GUARDED_REHEARSAL"

LIFECYCLE_POLICY: Final[dict[str, Any]] = {
    "authoritative_clean_pc_environment": CI_ENVIRONMENT,
    "local_environment": LOCAL_ENVIRONMENT,
    "predecessor_installer_format": "B13-3_UNSIGNED_REAL_NSIS",
    "target_installer_format": "B13-4_ENGINEERING_SIGNED_REAL_NSIS",
    "real_per_user_install_required": True,
    "real_per_user_upgrade_required": True,
    "real_per_user_uninstall_required": True,
    "existing_product_must_be_absent_before_test": True,
    "custom_temp_install_root_required": True,
    "packaged_self_check_required_before_upgrade": True,
    "packaged_ui_smoke_required_before_upgrade": True,
    "packaged_self_check_required_after_upgrade": True,
    "packaged_ui_smoke_required_after_upgrade": True,
    "target_application_signature_required": True,
    "target_uninstaller_signature_required": True,
    "target_rfc3161_timestamp_required": True,
    "signer_consistency_required": True,
    "unknown_install_child_preserved_across_upgrade": True,
    "unknown_install_child_preserved_after_uninstall": True,
    "external_persistent_data_preserved_across_upgrade": True,
    "external_persistent_data_preserved_after_uninstall": True,
    "registry_metadata_removed_after_uninstall": True,
    "start_menu_metadata_removed_after_uninstall": True,
    "administrator_required": False,
    "service_registration_allowed": False,
    "driver_registration_allowed": False,
    "autostart_registration_allowed": False,
    "public_trust_required_for_code_signing_blocker_resolution": True,
    "smartscreen_reputation_guaranteed": False,
}

IMPLEMENTATION_STATE: Final[dict[str, bool]] = {
    "clean_pc_ci_lifecycle_execution_available": True,
    "local_guarded_rehearsal_available": True,
    "real_per_user_install_execution_available": True,
    "real_per_user_upgrade_execution_available": True,
    "real_per_user_uninstall_execution_available": True,
    "engineering_signed_target_available": True,
    "public_trust_signature_verified": False,
    "code_signing_release_blocker_resolved": False,
    "service_registration_available": False,
    "driver_registration_available": False,
    "autostart_registration_available": False,
    "release_publication_available": False,
    "coverage_promoted": False,
    "authority_expanded": False,
}


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def classify_environment(env: Mapping[str, str] | None = None) -> str:
    source = os.environ if env is None else env
    if (
        str(source.get("GITHUB_ACTIONS", "")).lower() == "true"
        and str(source.get("RUNNER_OS", "")).lower() == "windows"
    ):
        return CI_ENVIRONMENT
    return LOCAL_ENVIRONMENT


def contract() -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "source_coverage": dict(SOURCE_COVERAGE),
        "verified_scenarios": list(VERIFIED_SCENARIOS),
        "source_readiness": dict(SOURCE_READINESS),
        "source_release_blockers": list(SOURCE_RELEASE_BLOCKERS),
        "lifecycle_policy": dict(LIFECYCLE_POLICY),
        "implementation_state": dict(IMPLEMENTATION_STATE),
    }


def validate_contract(data: object) -> tuple[str, ...]:
    if not isinstance(data, dict):
        return ("b135:not_object",)
    failures: list[str] = []
    expected = contract()
    if set(data) != set(expected):
        failures.append("b135:unexpected_or_missing_fields")
    for key, value in expected.items():
        if data.get(key) != value:
            failures.append(f"b135:contract_mismatch:{key}")
    return tuple(dict.fromkeys(failures))


_EVIDENCE_BOOL_TRUE: Final[tuple[str, ...]] = (
    "predecessor_install_passed",
    "predecessor_unsigned_observed",
    "predecessor_self_check_passed",
    "predecessor_ui_smoke_passed",
    "upgrade_passed",
    "target_signed_observed",
    "signer_consistent",
    "timestamp_present",
    "target_hash_changed",
    "upgraded_self_check_passed",
    "upgraded_ui_smoke_passed",
    "unknown_child_preserved_across_upgrade",
    "persistent_data_preserved_across_upgrade",
    "uninstall_passed",
    "unknown_child_preserved_after_uninstall",
    "persistent_data_preserved_after_uninstall",
    "registry_cleaned",
    "start_menu_cleaned",
)

_EVIDENCE_BOOL_FALSE: Final[tuple[str, ...]] = (
    "service_registration_observed",
    "driver_registration_observed",
    "autostart_registration_observed",
    "administrator_required",
    "public_trust_signature_verified",
    "smartscreen_reputation_guaranteed",
    "coverage_promoted",
    "authority_expanded",
)


def finalize_lifecycle_evidence(payload: Mapping[str, Any]) -> dict[str, Any]:
    data = dict(payload)
    data.pop("evidence_digest", None)
    data["evidence_digest"] = _digest(data)
    return data


def validate_lifecycle_evidence(
    data: object, *, expected_build_commit: str
) -> tuple[str, ...]:
    if not isinstance(data, dict):
        return ("b135:evidence_not_object",)

    failures: list[str] = []
    required = {
        "schema",
        "profile",
        "source_checkpoint",
        "source_checkpoint_commit",
        "build_commit",
        "environment",
        "authoritative_clean_pc_evidence",
        "predecessor_installer_format",
        "target_installer_format",
        *_EVIDENCE_BOOL_TRUE,
        *_EVIDENCE_BOOL_FALSE,
        "predecessor_app_sha256",
        "upgraded_app_sha256",
        "target_signer_thumbprint",
        "evidence_digest",
    }
    if set(data) != required:
        failures.append("b135:evidence_fields_invalid")

    if data.get("schema") != EVIDENCE_SCHEMA or data.get("profile") != PROFILE:
        failures.append("b135:evidence_identity_invalid")
    if (
        data.get("source_checkpoint") != SOURCE_CHECKPOINT
        or data.get("source_checkpoint_commit") != SOURCE_CHECKPOINT_COMMIT
    ):
        failures.append("b135:evidence_source_invalid")

    expected_build_commit = str(expected_build_commit).lower()
    if (
        len(expected_build_commit) != 40
        or any(ch not in "0123456789abcdef" for ch in expected_build_commit)
        or str(data.get("build_commit", "")).lower() != expected_build_commit
    ):
        failures.append("b135:evidence_build_commit_invalid")

    environment = data.get("environment")
    if environment not in {CI_ENVIRONMENT, LOCAL_ENVIRONMENT}:
        failures.append("b135:evidence_environment_invalid")
    expected_authoritative = environment == CI_ENVIRONMENT
    if data.get("authoritative_clean_pc_evidence") is not expected_authoritative:
        failures.append("b135:clean_pc_authority_invalid")

    if data.get("predecessor_installer_format") != LIFECYCLE_POLICY["predecessor_installer_format"]:
        failures.append("b135:predecessor_format_invalid")
    if data.get("target_installer_format") != LIFECYCLE_POLICY["target_installer_format"]:
        failures.append("b135:target_format_invalid")

    for key in _EVIDENCE_BOOL_TRUE:
        if data.get(key) is not True:
            failures.append(f"b135:required_pass_missing:{key}")
    for key in _EVIDENCE_BOOL_FALSE:
        if data.get(key) is not False:
            failures.append(f"b135:forbidden_state_observed:{key}")

    for key in ("predecessor_app_sha256", "upgraded_app_sha256"):
        value = str(data.get(key, "")).lower()
        if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
            failures.append(f"b135:sha256_invalid:{key}")
    if data.get("predecessor_app_sha256") == data.get("upgraded_app_sha256"):
        failures.append("b135:upgrade_did_not_change_application_hash")

    thumbprint = str(data.get("target_signer_thumbprint", "")).lower()
    if len(thumbprint) not in {40, 64} or any(ch not in "0123456789abcdef" for ch in thumbprint):
        failures.append("b135:target_signer_thumbprint_invalid")

    observed_digest = data.get("evidence_digest")
    core = dict(data)
    core.pop("evidence_digest", None)
    if observed_digest != _digest(core):
        failures.append("b135:evidence_digest_invalid")

    return tuple(dict.fromkeys(failures))


def self_check() -> dict[str, Any]:
    first = contract()
    second = contract()
    failures = list(validate_contract(first))
    deterministic = first == second and _digest(first) == _digest(second)
    if not deterministic:
        failures.append("b135:contract_not_deterministic")
    return {
        "passed": not failures,
        "failures": failures,
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "source_coverage": dict(SOURCE_COVERAGE),
        "verified_scenarios": list(VERIFIED_SCENARIOS),
        "source_readiness": dict(SOURCE_READINESS),
        "source_release_blockers": list(SOURCE_RELEASE_BLOCKERS),
        "contract_digest": _digest(first),
        "deterministic_contract": deterministic,
        "authoritative_clean_pc_environment": CI_ENVIRONMENT,
        "local_environment": LOCAL_ENVIRONMENT,
        "public_trust_signature_verified": False,
        "code_signing_release_blocker_resolved": False,
        "smartscreen_reputation_guaranteed": False,
        "coverage_promoted": False,
        "authority_expanded": False,
    }


if __name__ == "__main__":
    result = self_check()
    print(json.dumps(result, indent=2, sort_keys=True))
    raise SystemExit(0 if result["passed"] else 1)

from __future__ import annotations

"""B11-1 canonical desktop runtime identity.

This module gives the Beta11 desktop product one factual, machine-verifiable
runtime identity while preserving the accepted Beta10 protection and authority
boundaries. It does not create or imply an installer, signature, service,
driver, autostart registration, network dependency, or new protection claim.
"""

import hashlib
import json
from typing import Any, Final

from sentinel import beta11_productization_foundation as foundation

SCHEMA: Final[str] = "bc-sentinel-beta11-runtime-identity-v1"
PROFILE: Final[str] = "v0.11.0-beta.11-b111-canonical-desktop-entry"
PRODUCT_NAME: Final[str] = "BC Sentinel"
PRODUCT_VERSION: Final[str] = "0.11.0-beta.11"
PRODUCT_CHANNEL: Final[str] = "Beta11"
SOURCE_CHECKPOINT: Final[str] = "checkpoint/v011-beta11-b110-pass"
SOURCE_CHECKPOINT_COMMIT: Final[str] = "0bee65100c6713d11dedd56c28ee3118f0082624"
CANONICAL_ENTRYPOINT: Final[str] = "packaging/beta11_desktop_entry.py"
CANONICAL_UI_MODULE: Final[str] = "sentinel.beta10_trust_center_ui"
CANONICAL_UI_CLASS: Final[str] = "TrustCenterWindow"
EXPECTED_PAGE_COUNT: Final[int] = 7
SOURCE_COVERAGE: Final[dict[str, int]] = dict(foundation.SOURCE_COVERAGE)
VERIFIED_SCENARIOS: Final[tuple[str, ...]] = tuple(foundation.VERIFIED_SCENARIOS)

DISTRIBUTION_STATE: Final[dict[str, bool]] = {
    "canonical_beta11_desktop_entry_available": True,
    "runtime_identity_available": True,
    "trust_center_included": True,
    "beta11_release_artifact_available": False,
    "installer_available": False,
    "uninstaller_available": False,
    "artifact_signed": False,
    "windows_service_installed": False,
    "kernel_driver_installed": False,
    "autostart_registered": False,
    "automatic_update_enabled": False,
}

STARTUP_BOUNDARY: Final[dict[str, bool]] = {
    "requires_administrator": False,
    "mutates_system": False,
    "performs_remediation": False,
    "performs_automatic_quarantine": False,
    "performs_automatic_repair": False,
    "performs_automatic_restore": False,
    "registers_autostart": False,
    "installs_service": False,
    "installs_driver": False,
    "requires_network": False,
    "requires_cloud": False,
    "reads_credentials": False,
    "expands_general_home_execution": False,
    "promotes_detection_coverage": False,
}


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def runtime_identity() -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "product_name": PRODUCT_NAME,
        "product_version": PRODUCT_VERSION,
        "product_channel": PRODUCT_CHANNEL,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "canonical_entrypoint": CANONICAL_ENTRYPOINT,
        "canonical_ui_module": CANONICAL_UI_MODULE,
        "canonical_ui_class": CANONICAL_UI_CLASS,
        "expected_page_count": EXPECTED_PAGE_COUNT,
        "coverage_summary": dict(SOURCE_COVERAGE),
        "verified_scenarios": list(VERIFIED_SCENARIOS),
        "distribution_state": dict(DISTRIBUTION_STATE),
        "startup_boundary": dict(STARTUP_BOUNDARY),
        "artifact_identity_state": "SOURCE_RUNTIME_ONLY",
        "release_artifact_claimed": False,
        "signing_claimed": False,
        "authority_expanded_in_b111": False,
        "coverage_promoted_in_b111": False,
    }


def validate_runtime_identity(data: object) -> tuple[str, ...]:
    if not isinstance(data, dict):
        return ("b111:not_object",)

    failures: list[str] = []
    expected_keys = {
        "schema",
        "profile",
        "product_name",
        "product_version",
        "product_channel",
        "source_checkpoint",
        "source_checkpoint_commit",
        "canonical_entrypoint",
        "canonical_ui_module",
        "canonical_ui_class",
        "expected_page_count",
        "coverage_summary",
        "verified_scenarios",
        "distribution_state",
        "startup_boundary",
        "artifact_identity_state",
        "release_artifact_claimed",
        "signing_claimed",
        "authority_expanded_in_b111",
        "coverage_promoted_in_b111",
    }
    if set(data) != expected_keys:
        failures.append("b111:unexpected_or_missing_fields")

    if data.get("schema") != SCHEMA or data.get("profile") != PROFILE:
        failures.append("b111:identity_invalid")
    if data.get("product_name") != PRODUCT_NAME or data.get("product_version") != PRODUCT_VERSION:
        failures.append("b111:product_identity_invalid")
    if data.get("product_channel") != PRODUCT_CHANNEL:
        failures.append("b111:channel_invalid")
    if data.get("source_checkpoint") != SOURCE_CHECKPOINT or data.get("source_checkpoint_commit") != SOURCE_CHECKPOINT_COMMIT:
        failures.append("b111:source_checkpoint_invalid")
    if data.get("canonical_entrypoint") != CANONICAL_ENTRYPOINT:
        failures.append("b111:entrypoint_invalid")
    if data.get("canonical_ui_module") != CANONICAL_UI_MODULE or data.get("canonical_ui_class") != CANONICAL_UI_CLASS:
        failures.append("b111:canonical_ui_invalid")
    if data.get("expected_page_count") != EXPECTED_PAGE_COUNT:
        failures.append("b111:page_count_invalid")
    if data.get("coverage_summary") != SOURCE_COVERAGE:
        failures.append("b111:coverage_changed")
    if tuple(data.get("verified_scenarios") or ()) != VERIFIED_SCENARIOS:
        failures.append("b111:verified_scenarios_changed")

    distribution = data.get("distribution_state")
    if distribution != DISTRIBUTION_STATE or not isinstance(distribution, dict):
        failures.append("b111:distribution_state_invalid")
    else:
        for required_true in (
            "canonical_beta11_desktop_entry_available",
            "runtime_identity_available",
            "trust_center_included",
        ):
            if distribution.get(required_true) is not True:
                failures.append(f"b111:required_distribution_state_false:{required_true}")
        for forbidden_true in (
            "beta11_release_artifact_available",
            "installer_available",
            "uninstaller_available",
            "artifact_signed",
            "windows_service_installed",
            "kernel_driver_installed",
            "autostart_registered",
            "automatic_update_enabled",
        ):
            if distribution.get(forbidden_true) is not False:
                failures.append(f"b111:premature_distribution_claim:{forbidden_true}")

    startup = data.get("startup_boundary")
    if startup != STARTUP_BOUNDARY or not isinstance(startup, dict):
        failures.append("b111:startup_boundary_invalid")
    elif any(startup.values()):
        failures.append("b111:startup_authority_expanded")

    if data.get("artifact_identity_state") != "SOURCE_RUNTIME_ONLY":
        failures.append("b111:artifact_identity_state_invalid")
    for key in (
        "release_artifact_claimed",
        "signing_claimed",
        "authority_expanded_in_b111",
        "coverage_promoted_in_b111",
    ):
        if data.get(key) is not False:
            failures.append(f"b111:forbidden_claim:{key}")

    return tuple(failures)


def self_check() -> dict[str, Any]:
    first = runtime_identity()
    second = runtime_identity()
    failures = list(validate_runtime_identity(first))
    deterministic = first == second and _digest(first) == _digest(second)
    if not deterministic:
        failures.append("b111:runtime_identity_not_deterministic")
    return {
        "passed": not failures,
        "failures": failures,
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "canonical_entrypoint": CANONICAL_ENTRYPOINT,
        "canonical_ui_module": CANONICAL_UI_MODULE,
        "canonical_ui_class": CANONICAL_UI_CLASS,
        "expected_page_count": EXPECTED_PAGE_COUNT,
        "coverage_summary": dict(SOURCE_COVERAGE),
        "verified_scenarios": list(VERIFIED_SCENARIOS),
        "identity_digest": _digest(first),
        "deterministic_identity": deterministic,
        "release_artifact_available": False,
        "installer_available": False,
        "artifact_signed": False,
        "startup_authority_expanded": False,
        "coverage_promoted": False,
    }


def main() -> int:
    result = self_check()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

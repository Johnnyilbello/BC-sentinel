from __future__ import annotations

"""B11-0 Windows Productization Foundation.

Beta11 starts from the immutable Beta10 final checkpoint and defines the rules
for turning the accepted engine/UI into a distributable Windows product.

This milestone is contract-only. It does not create an installer, register
startup, install a service/driver, enable auto-update, require cloud/network
access, or expand remediation/protection authority.
"""

import hashlib
import json
from typing import Any, Final

SCHEMA: Final[str] = "bc-sentinel-beta11-productization-foundation-v1"
PROFILE: Final[str] = "v0.11.0-beta.11-b110-productization-foundation"
SOURCE_CHECKPOINT: Final[str] = "checkpoint/v011-beta10-b109-pass"
SOURCE_CHECKPOINT_COMMIT: Final[str] = "89d2b0d59c73ad5d07d46af58db03d03c6fbfdc9"
SOURCE_COVERAGE: Final[dict[str, int]] = {"PARTIAL": 4, "GAP": 0, "VERIFIED": 2}
VERIFIED_SCENARIOS: Final[tuple[str, ...]] = (
    "B7-POWERSHELL-001",
    "B7-RANSOMWARE-001",
)

PRODUCTIZATION_PILLARS: Final[tuple[dict[str, Any], ...]] = (
    {
        "pillar_id": "CANONICAL_DESKTOP_ENTRY",
        "customer_value": "One supported Windows entrypoint with clear runtime identity and predictable startup behavior.",
        "acceptance_metrics": (
            "one canonical desktop entrypoint is declared",
            "startup identity is machine-verifiable",
            "startup performs no hidden remediation or privileged mutation",
        ),
    },
    {
        "pillar_id": "REPRODUCIBLE_ARTIFACT",
        "customer_value": "A Windows artifact can be rebuilt from an accepted checkpoint with an integrity manifest and exact source identity.",
        "acceptance_metrics": (
            "artifact source commit is recorded",
            "artifact SHA-256 is recorded",
            "build inputs and tool versions are recorded",
            "build output is verified before release promotion",
        ),
    },
    {
        "pillar_id": "INSTALL_LIFECYCLE",
        "customer_value": "Install, repair, upgrade and uninstall behavior is explicit, bounded and testable instead of being hidden in scripts.",
        "acceptance_metrics": (
            "install scope is explicit",
            "uninstall removes only product-owned resources",
            "upgrade and rollback rules are defined before mutation",
        ),
    },
    {
        "pillar_id": "FIRST_RUN_HEALTH",
        "customer_value": "The product can explain whether required runtime components are healthy before the user relies on protection claims.",
        "acceptance_metrics": (
            "first-run health is read-only by default",
            "missing dependencies fail closed",
            "health status cannot promote detection coverage",
        ),
    },
    {
        "pillar_id": "RELEASE_PROVENANCE",
        "customer_value": "Every candidate release has a traceable checkpoint, artifact manifest, signing state and acceptance evidence.",
        "acceptance_metrics": (
            "release checkpoint is immutable",
            "signing state is factual and never implied",
            "CI and local acceptance bind to the same candidate identity",
        ),
    },
    {
        "pillar_id": "SAFE_UPGRADE_RECOVERY",
        "customer_value": "Product updates preserve user data and accepted safety boundaries, with rollback when an upgrade cannot be completed safely.",
        "acceptance_metrics": (
            "persistent data ownership is defined",
            "configuration migration is deterministic",
            "rollback does not widen remediation authority",
        ),
    },
)

BETA11_MILESTONES: Final[tuple[dict[str, Any], ...]] = (
    {"id": "B11-0", "name": "Windows Productization Foundation", "primary_pillars": ("REPRODUCIBLE_ARTIFACT", "RELEASE_PROVENANCE")},
    {"id": "B11-1", "name": "Canonical Desktop Entry + Runtime Identity", "primary_pillars": ("CANONICAL_DESKTOP_ENTRY", "FIRST_RUN_HEALTH")},
    {"id": "B11-2", "name": "Reproducible Windows Onedir Build", "primary_pillars": ("REPRODUCIBLE_ARTIFACT", "RELEASE_PROVENANCE")},
    {"id": "B11-3", "name": "Installer / Uninstaller Contract", "primary_pillars": ("INSTALL_LIFECYCLE", "RELEASE_PROVENANCE")},
    {"id": "B11-4", "name": "First-Run Health + Repair Guidance", "primary_pillars": ("FIRST_RUN_HEALTH", "CANONICAL_DESKTOP_ENTRY")},
    {"id": "B11-5", "name": "Persistent App Data + Logs + Quarantine Model", "primary_pillars": ("INSTALL_LIFECYCLE", "SAFE_UPGRADE_RECOVERY")},
    {"id": "B11-6", "name": "Upgrade / Rollback + Config Migration", "primary_pillars": ("SAFE_UPGRADE_RECOVERY", "INSTALL_LIFECYCLE")},
    {"id": "B11-7", "name": "Release Provenance + Signing Readiness", "primary_pillars": ("RELEASE_PROVENANCE", "REPRODUCIBLE_ARTIFACT")},
    {"id": "B11-8", "name": "Clean-PC Install / Upgrade / Uninstall Acceptance", "primary_pillars": tuple(p["pillar_id"] for p in PRODUCTIZATION_PILLARS)},
    {"id": "B11-9", "name": "Windows Release Candidate Acceptance & Freeze", "primary_pillars": tuple(p["pillar_id"] for p in PRODUCTIZATION_PILLARS)},
)

CURRENT_DISTRIBUTION_STATE: Final[dict[str, bool]] = {
    "canonical_beta11_desktop_entry_available": False,
    "beta11_release_artifact_available": False,
    "installer_available": False,
    "uninstaller_available": False,
    "artifact_signed": False,
    "windows_service_installed": False,
    "kernel_driver_installed": False,
    "autostart_registered": False,
    "automatic_update_enabled": False,
    "silent_mutating_install_enabled": False,
    "network_required_for_core_startup": False,
    "cloud_required_for_core_startup": False,
}

INHERITED_AUTHORITY_BOUNDARY: Final[dict[str, bool]] = {
    "automatic_quarantine": False,
    "automatic_repair": False,
    "automatic_restore": False,
    "general_home_execution": False,
    "delete_authority": False,
    "repair_authority": False,
    "terminate_process_authority": False,
    "trust_allowlist_mutation": False,
    "privileged_system_mutation": False,
    "network_test_authority": False,
    "credential_access_authority": False,
    "broad_protection_claimed": False,
}

B11_FOUNDATION_GUARDRAILS: Final[dict[str, bool]] = {
    "source_checkpoint_must_be_immutable": True,
    "accepted_beta10_sources_may_be_modified": False,
    "installer_may_be_claimed_before_acceptance": False,
    "signature_may_be_claimed_before_verification": False,
    "release_may_promote_detection_coverage": False,
    "release_may_expand_response_authority": False,
    "release_requires_exact_ci_and_local_acceptance": True,
    "clean_pc_acceptance_required_before_rc_freeze": True,
}


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def contract() -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "source_coverage": dict(SOURCE_COVERAGE),
        "verified_scenarios": list(VERIFIED_SCENARIOS),
        "productization_pillars": [
            {**pillar, "acceptance_metrics": list(pillar["acceptance_metrics"])}
            for pillar in PRODUCTIZATION_PILLARS
        ],
        "milestones": [
            {**milestone, "primary_pillars": list(milestone["primary_pillars"])}
            for milestone in BETA11_MILESTONES
        ],
        "current_distribution_state": dict(CURRENT_DISTRIBUTION_STATE),
        "inherited_authority_boundary": dict(INHERITED_AUTHORITY_BOUNDARY),
        "foundation_guardrails": dict(B11_FOUNDATION_GUARDRAILS),
        "adds_installer_in_b110": False,
        "adds_service_or_driver_in_b110": False,
        "adds_network_or_cloud_dependency_in_b110": False,
        "adds_protection_claim_in_b110": False,
        "adds_response_authority_in_b110": False,
    }


def validate_contract(data: object) -> tuple[str, ...]:
    if not isinstance(data, dict):
        return ("b110:not_object",)

    failures: list[str] = []
    expected_keys = {
        "schema",
        "profile",
        "source_checkpoint",
        "source_checkpoint_commit",
        "source_coverage",
        "verified_scenarios",
        "productization_pillars",
        "milestones",
        "current_distribution_state",
        "inherited_authority_boundary",
        "foundation_guardrails",
        "adds_installer_in_b110",
        "adds_service_or_driver_in_b110",
        "adds_network_or_cloud_dependency_in_b110",
        "adds_protection_claim_in_b110",
        "adds_response_authority_in_b110",
    }
    if set(data) != expected_keys:
        failures.append("b110:unexpected_or_missing_fields")

    if data.get("schema") != SCHEMA or data.get("profile") != PROFILE:
        failures.append("b110:identity_invalid")
    if data.get("source_checkpoint") != SOURCE_CHECKPOINT or data.get("source_checkpoint_commit") != SOURCE_CHECKPOINT_COMMIT:
        failures.append("b110:source_checkpoint_invalid")
    if data.get("source_coverage") != SOURCE_COVERAGE:
        failures.append("b110:coverage_changed")
    if tuple(data.get("verified_scenarios") or ()) != VERIFIED_SCENARIOS:
        failures.append("b110:verified_scenarios_changed")

    distribution = data.get("current_distribution_state")
    if distribution != CURRENT_DISTRIBUTION_STATE or not isinstance(distribution, dict):
        failures.append("b110:distribution_state_invalid")
    elif any(distribution.values()):
        failures.append("b110:distribution_capability_claimed_too_early")

    authority = data.get("inherited_authority_boundary")
    if authority != INHERITED_AUTHORITY_BOUNDARY or not isinstance(authority, dict):
        failures.append("b110:authority_boundary_invalid")
    elif any(authority.values()):
        failures.append("b110:authority_expansion_forbidden")

    guardrails = data.get("foundation_guardrails")
    if guardrails != B11_FOUNDATION_GUARDRAILS:
        failures.append("b110:guardrails_invalid")

    for key in (
        "adds_installer_in_b110",
        "adds_service_or_driver_in_b110",
        "adds_network_or_cloud_dependency_in_b110",
        "adds_protection_claim_in_b110",
        "adds_response_authority_in_b110",
    ):
        if data.get(key) is not False:
            failures.append(f"b110:forbidden_foundation_expansion:{key}")

    pillars = data.get("productization_pillars")
    if not isinstance(pillars, list) or len(pillars) != len(PRODUCTIZATION_PILLARS):
        failures.append("b110:pillar_count_invalid")
    else:
        expected_ids = [p["pillar_id"] for p in PRODUCTIZATION_PILLARS]
        ids = [p.get("pillar_id") for p in pillars if isinstance(p, dict)]
        if ids != expected_ids or len(set(ids)) != len(expected_ids):
            failures.append("b110:pillar_identity_invalid")
        for pillar in pillars:
            if not isinstance(pillar, dict):
                failures.append("b110:pillar_not_object")
                continue
            metrics = pillar.get("acceptance_metrics")
            if not isinstance(metrics, list) or len(metrics) < 3 or not all(isinstance(x, str) and x for x in metrics):
                failures.append("b110:pillar_metrics_invalid")

    milestones = data.get("milestones")
    expected_milestones = [f"B11-{i}" for i in range(10)]
    if not isinstance(milestones, list) or [m.get("id") for m in milestones if isinstance(m, dict)] != expected_milestones:
        failures.append("b110:milestone_order_invalid")
    else:
        pillar_ids = {p["pillar_id"] for p in PRODUCTIZATION_PILLARS}
        for milestone in milestones:
            primary = milestone.get("primary_pillars")
            if not isinstance(primary, list) or not primary or not set(primary).issubset(pillar_ids):
                failures.append("b110:milestone_pillars_invalid")

    return tuple(failures)


def self_check() -> dict[str, Any]:
    first = contract()
    second = contract()
    failures = list(validate_contract(first))
    deterministic = first == second and _digest(first) == _digest(second)
    if not deterministic:
        failures.append("b110:contract_not_deterministic")
    return {
        "passed": not failures,
        "failures": failures,
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "source_coverage": dict(SOURCE_COVERAGE),
        "verified_scenarios": list(VERIFIED_SCENARIOS),
        "pillar_count": len(PRODUCTIZATION_PILLARS),
        "milestone_count": len(BETA11_MILESTONES),
        "contract_digest": _digest(first),
        "deterministic_contract": deterministic,
        "installer_available": False,
        "artifact_signed": False,
        "authority_expanded": False,
        "coverage_promoted": False,
    }


def main() -> int:
    result = self_check()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

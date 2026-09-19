from __future__ import annotations

"""B13-0 Consumer Product Readiness Foundation.

This milestone freezes a factual, fail-closed consumer-readiness baseline on top
of the immutable Beta12 final checkpoint. It does not add response authority,
network/cloud dependencies, installer execution, signing, licensing enforcement
or release claims.

The purpose is to prevent "installable" from being confused with "ready to sell".
"""

import hashlib
import json
from typing import Any, Final

SCHEMA: Final[str] = "bc-sentinel-beta13-consumer-readiness-v1"
PROFILE: Final[str] = "v0.13.0-b130-consumer-product-readiness"
SOURCE_CHECKPOINT: Final[str] = "checkpoint/v012-beta12-b129-pass"
SOURCE_CHECKPOINT_COMMIT: Final[str] = "c8e51a2a3fc34c593905896d3b055f9fec252c4b"
SOURCE_COVERAGE: Final[dict[str, int]] = {"PARTIAL": 4, "GAP": 0, "VERIFIED": 7}

READY: Final[str] = "READY"
PARTIAL: Final[str] = "PARTIAL"
BLOCKED: Final[str] = "BLOCKED"

PILLARS: Final[tuple[dict[str, Any], ...]] = (
    {
        "pillar_id": "ACTIVE_PROTECTION",
        "label": "Active protection evidence",
        "status": READY,
        "release_blocking": False,
        "evidence": "BETA12_FINAL_FREEZE",
        "detail": "7 VERIFIED scenarios, low-noise gate, product Trust Center and exact CI/local freeze evidence accepted.",
    },
    {
        "pillar_id": "USER_MEDIATED_QUARANTINE",
        "label": "Quarantine / restore",
        "status": READY,
        "release_blocking": False,
        "evidence": "HOME_QUARANTINE_USER_MEDIATED",
        "detail": "Verified user-mediated quarantine and restart-safe restore exist; silent automatic quarantine is not claimed.",
    },
    {
        "pillar_id": "SAFE_THREAT_RESPONSE",
        "label": "Safe threat response",
        "status": BLOCKED,
        "release_blocking": True,
        "evidence": "AUTO_RESPONSE_NOT_ACCEPTED",
        "detail": "High-confidence reversible containment and consumer response policy still need explicit acceptance.",
    },
    {
        "pillar_id": "BACKGROUND_ALERTS",
        "label": "Background alerts / tray UX",
        "status": PARTIAL,
        "release_blocking": True,
        "evidence": "INTERNAL_INBOX_ONLY",
        "detail": "Internal incident notifications exist, but a dedicated consumer background/tray alert surface is not accepted.",
    },
    {
        "pillar_id": "SECURE_UPDATES",
        "label": "Secure application / rule updates",
        "status": BLOCKED,
        "release_blocking": True,
        "evidence": "NO_ACCEPTED_CONSUMER_UPDATER",
        "detail": "Signed manifests, rollback, version pinning and update-channel acceptance are still missing.",
    },
    {
        "pillar_id": "FIRST_RUN_HEALTH",
        "label": "First-run health",
        "status": READY,
        "release_blocking": False,
        "evidence": "B11_FIRST_RUN_HEALTH",
        "detail": "Bounded first-run health and repair guidance exist without silent system mutation.",
    },
    {
        "pillar_id": "INSTALLER_LIFECYCLE",
        "label": "Installer / upgrade / uninstall",
        "status": BLOCKED,
        "release_blocking": True,
        "evidence": "CONTRACT_ONLY",
        "detail": "Lifecycle contracts exist, but real machine-scope installer execution has not yet been accepted.",
    },
    {
        "pillar_id": "CODE_SIGNING",
        "label": "Publisher signing / SmartScreen readiness",
        "status": BLOCKED,
        "release_blocking": True,
        "evidence": "UNSIGNED_ENGINEERING_STATE",
        "detail": "A consistent verified publisher identity and Authenticode/timestamp evidence are still missing.",
    },
    {
        "pillar_id": "LICENSING_TRIAL",
        "label": "Trial / licensing / activation",
        "status": BLOCKED,
        "release_blocking": True,
        "evidence": "NO_ACCEPTED_COMMERCIAL_ENTITLEMENT",
        "detail": "No accepted trial, activation or paid-entitlement lifecycle exists yet.",
    },
    {
        "pillar_id": "PRIVACY_SUPPORT",
        "label": "Privacy / support / diagnostics",
        "status": PARTIAL,
        "release_blocking": True,
        "evidence": "DIAGNOSTICS_EXIST_POLICY_SURFACES_MISSING",
        "detail": "Diagnostic primitives exist, but launch-ready privacy/EULA/support and export UX are not yet accepted.",
    },
)

LAUNCH_POLICY: Final[dict[str, bool]] = {
    "all_release_blocking_pillars_must_be_ready": True,
    "installer_alone_is_not_launch_readiness": True,
    "unsigned_public_release_allowed": False,
    "silent_destructive_response_allowed": False,
    "protection_may_be_disabled_by_license_failure": False,
    "unknown_file_may_be_called_malicious_without_evidence": False,
    "mandatory_cloud_for_core_protection": False,
}

INHERITED_BOUNDARY: Final[dict[str, bool]] = {
    "automatic_quarantine": False,
    "automatic_repair": False,
    "automatic_restore": False,
    "terminate_process_authority": False,
    "trust_allowlist_mutation": False,
    "privileged_system_mutation": False,
    "installer_execution": False,
    "artifact_signing": False,
    "licensing_enforcement": False,
    "release_publication": False,
    "network_required": False,
    "cloud_required": False,
    "coverage_promoted": False,
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
        "pillars": [dict(item) for item in PILLARS],
        "launch_policy": dict(LAUNCH_POLICY),
        "inherited_boundary": dict(INHERITED_BOUNDARY),
    }


def summarize(data: object | None = None) -> dict[str, Any]:
    value = contract() if data is None else data
    failures: list[str] = []
    if not isinstance(value, dict):
        return {"passed": False, "failures": ["b130:not_object"]}

    expected = contract()
    if value != expected:
        failures.append("b130:contract_changed")

    pillars = value.get("pillars")
    if not isinstance(pillars, list):
        return {"passed": False, "failures": list(dict.fromkeys(failures + ["b130:pillars_invalid"]))}

    ids = [item.get("pillar_id") for item in pillars if isinstance(item, dict)]
    if len(ids) != len(PILLARS) or len(ids) != len(set(ids)):
        failures.append("b130:pillar_inventory_invalid")

    counts = {status: 0 for status in (READY, PARTIAL, BLOCKED)}
    blockers: list[str] = []
    for item in pillars:
        if not isinstance(item, dict):
            failures.append("b130:pillar_not_object")
            continue
        status = item.get("status")
        if status not in counts:
            failures.append("b130:pillar_status_invalid")
            continue
        counts[status] += 1
        if item.get("release_blocking") is True and status != READY:
            blockers.append(str(item.get("pillar_id")))

    if value.get("source_checkpoint") != SOURCE_CHECKPOINT or value.get("source_checkpoint_commit") != SOURCE_CHECKPOINT_COMMIT:
        failures.append("b130:source_checkpoint_changed")
    if value.get("source_coverage") != SOURCE_COVERAGE:
        failures.append("b130:coverage_changed")
    if value.get("launch_policy") != LAUNCH_POLICY:
        failures.append("b130:launch_policy_changed")
    boundary = value.get("inherited_boundary")
    if boundary != INHERITED_BOUNDARY:
        failures.append("b130:boundary_changed")
    elif any(boundary.values()):
        failures.append("b130:authority_or_release_capability_enabled")

    ready_for_public_launch = not blockers and not failures
    return {
        "passed": not failures,
        "failures": list(dict.fromkeys(failures)),
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "source_coverage": dict(SOURCE_COVERAGE),
        "pillar_counts": counts,
        "release_blockers": blockers,
        "release_blocker_count": len(blockers),
        "ready_for_public_launch": ready_for_public_launch,
        "ready_for_paid_launch": ready_for_public_launch,
        "ready_for_installer_work": True,
        "installer_alone_is_launch_readiness": False,
        "coverage_promoted": False,
        "authority_expanded": False,
        "network_required": False,
        "cloud_required": False,
        "contract_digest": _digest(expected),
    }


def self_check() -> dict[str, Any]:
    first = contract()
    second = contract()
    report = summarize(first)
    deterministic = first == second and _digest(first) == _digest(second)
    if not deterministic:
        report = dict(report)
        report["passed"] = False
        report["failures"] = list(report["failures"]) + ["b130:contract_not_deterministic"]
    return {
        **report,
        "deterministic_contract": deterministic,
    }


def main() -> int:
    result = self_check()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

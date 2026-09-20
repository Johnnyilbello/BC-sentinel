from __future__ import annotations

"""B14-0 Verified Protection & Independent-Test Readiness Foundation.

This milestone starts Beta14 from the immutable Beta13 engineering RC freeze.
It defines evidence gates for broader antivirus quality without promoting
coverage, expanding remediation authority or claiming independent certification.

Normal CI/local acceptance remains harmless-fixture only. Authentic malicious
samples, if ever used in later milestones, require a separately authorized,
isolated lab contract and are outside B14-0.
"""

import hashlib
import json
from typing import Any, Final

SCHEMA: Final[str] = "bc-sentinel-beta14-test-readiness-v1"
PROFILE: Final[str] = "v0.14.0-b140-verified-protection-test-readiness"
SOURCE_CHECKPOINT: Final[str] = "checkpoint/v013-b137-pass"
SOURCE_CHECKPOINT_COMMIT: Final[str] = "01df0a9c58b856cfe841909fb5c39f7ef71decb8"
SOURCE_COVERAGE: Final[dict[str, int]] = {"PARTIAL": 4, "GAP": 0, "VERIFIED": 7}

READY: Final[str] = "READY"
PARTIAL: Final[str] = "PARTIAL"
BLOCKED: Final[str] = "BLOCKED"

VERIFIED_SCENARIOS: Final[tuple[str, ...]] = (
    "B7-POWERSHELL-001",
    "B7-RANSOMWARE-001",
    "B12-SCRIPT-ABUSE-001",
    "B12-AUTOSTART-LINK-001",
    "B12-PROCESS-TREE-001",
    "B12-RANSOMWARE-PROCESS-001",
    "B12-LOCAL-REPUTATION-001",
)

EVIDENCE_GATES: Final[tuple[dict[str, Any], ...]] = (
    {
        "gate_id": "REPRODUCIBLE_ENGINEERING_EVIDENCE",
        "status": READY,
        "detail": "Exact CI/local checkpoints, deterministic contracts, hashes and release provenance are accepted.",
    },
    {
        "gate_id": "WINDOWS_PRODUCT_LIFECYCLE",
        "status": READY,
        "detail": "Engineering RC install, self-check, UI smoke, diagnostics and uninstall are accepted.",
    },
    {
        "gate_id": "REAL_WORLD_PROTECTION_CORPUS",
        "status": BLOCKED,
        "detail": "No broad real-world malware corpus has earned an accepted protection claim.",
    },
    {
        "gate_id": "PREVALENT_MALWARE_REFERENCE_SET",
        "status": BLOCKED,
        "detail": "No large representative prevalent-malware reference set has been accepted.",
    },
    {
        "gate_id": "FALSE_POSITIVE_BREADTH",
        "status": PARTIAL,
        "detail": "Accepted low-noise controls exist, but not a large benign-software corpus.",
    },
    {
        "gate_id": "SYSTEM_PERFORMANCE_IMPACT",
        "status": PARTIAL,
        "detail": "Accepted microbench evidence exists, but not full system-level workload impact.",
    },
    {
        "gate_id": "BEHAVIORAL_DETECTION_BREADTH",
        "status": PARTIAL,
        "detail": "Several behavior-oriented scenarios are VERIFIED, but only scenario-specifically.",
    },
    {
        "gate_id": "OFFLINE_ONLINE_PROTECTION_MATRIX",
        "status": BLOCKED,
        "detail": "No accepted broad comparison of offline-only versus optional connected protection exists.",
    },
    {
        "gate_id": "INDEPENDENT_LAB_SUBMISSION_READINESS",
        "status": BLOCKED,
        "detail": "BC Sentinel is not independently certified and B14-0 does not claim submission readiness.",
    },
    {
        "gate_id": "PUBLIC_TRUST_CODE_SIGNING",
        "status": BLOCKED,
        "detail": "Engineering Authenticode is accepted; trusted publisher Public Trust remains unresolved.",
    },
)

SAFE_LAB_POLICY: Final[dict[str, Any]] = {
    "ordinary_ci_local_authentic_malware_execution_allowed": False,
    "ordinary_ci_local_harmless_fixtures_only": True,
    "synthetic_only_evidence_may_promote_verified": False,
    "future_authentic_sample_work_requires_separate_authorized_isolated_lab": True,
    "future_authentic_sample_work_requires_explicit_scope_and_cleanup": True,
}

BOUNDARIES: Final[dict[str, bool]] = {
    "coverage_promoted": False,
    "authority_expanded": False,
    "automatic_quarantine": False,
    "automatic_repair": False,
    "automatic_restore": False,
    "terminate_process_authority": False,
    "privileged_system_mutation": False,
    "mandatory_network_for_core_protection": False,
    "mandatory_cloud_for_core_protection": False,
    "independent_certification_claimed": False,
    "public_release_ready": False,
    "paid_release_ready": False,
    "public_trust_signature_verified": False,
}

RELEASE_BLOCKERS: Final[tuple[str, ...]] = ("CODE_SIGNING",)


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
        "evidence_gates": [dict(item) for item in EVIDENCE_GATES],
        "safe_lab_policy": dict(SAFE_LAB_POLICY),
        "boundaries": dict(BOUNDARIES),
        "release_blockers": list(RELEASE_BLOCKERS),
    }


def summarize(data: object | None = None) -> dict[str, Any]:
    value = contract() if data is None else data
    failures: list[str] = []

    if not isinstance(value, dict):
        return {"passed": False, "failures": ["b140:not_object"]}

    expected = contract()
    if value != expected:
        failures.append("b140:contract_changed")

    if value.get("source_checkpoint") != SOURCE_CHECKPOINT:
        failures.append("b140:source_checkpoint_changed")
    if value.get("source_checkpoint_commit") != SOURCE_CHECKPOINT_COMMIT:
        failures.append("b140:source_checkpoint_commit_changed")
    if value.get("source_coverage") != SOURCE_COVERAGE:
        failures.append("b140:coverage_changed")
    if value.get("verified_scenarios") != list(VERIFIED_SCENARIOS):
        failures.append("b140:verified_scenarios_changed")

    gates = value.get("evidence_gates")
    counts = {READY: 0, PARTIAL: 0, BLOCKED: 0}
    if not isinstance(gates, list) or len(gates) != len(EVIDENCE_GATES):
        failures.append("b140:evidence_gate_inventory_invalid")
    else:
        ids: list[str] = []
        for item in gates:
            if not isinstance(item, dict):
                failures.append("b140:evidence_gate_not_object")
                continue
            gate_id = str(item.get("gate_id", ""))
            ids.append(gate_id)
            status = item.get("status")
            if status not in counts:
                failures.append(f"b140:evidence_gate_status_invalid:{gate_id}")
                continue
            counts[status] += 1
        if len(ids) != len(set(ids)):
            failures.append("b140:evidence_gate_ids_not_unique")

    if counts != {READY: 2, PARTIAL: 3, BLOCKED: 5}:
        failures.append("b140:evidence_gate_counts_invalid")

    policy = value.get("safe_lab_policy")
    if policy != SAFE_LAB_POLICY:
        failures.append("b140:safe_lab_policy_changed")
    elif (
        policy["ordinary_ci_local_authentic_malware_execution_allowed"] is not False
        or policy["ordinary_ci_local_harmless_fixtures_only"] is not True
        or policy["synthetic_only_evidence_may_promote_verified"] is not False
    ):
        failures.append("b140:safe_lab_policy_unsafe")

    boundaries = value.get("boundaries")
    if boundaries != BOUNDARIES:
        failures.append("b140:boundaries_changed")
    elif any(boundaries.values()):
        failures.append("b140:authority_or_claim_expanded")

    if value.get("release_blockers") != list(RELEASE_BLOCKERS):
        failures.append("b140:release_blockers_changed")

    return {
        "passed": not failures,
        "failures": list(dict.fromkeys(failures)),
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "source_coverage": dict(SOURCE_COVERAGE),
        "verified_scenario_count": len(VERIFIED_SCENARIOS),
        "evidence_gate_counts": counts,
        "independent_test_ready": False,
        "independent_certification_claimed": False,
        "engineering_release_candidate_inherited": True,
        "public_release_ready": False,
        "paid_release_ready": False,
        "release_blockers": list(RELEASE_BLOCKERS),
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
        report["failures"] = list(report["failures"]) + ["b140:contract_not_deterministic"]
    return {**report, "deterministic_contract": deterministic}


def main() -> int:
    result = self_check()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

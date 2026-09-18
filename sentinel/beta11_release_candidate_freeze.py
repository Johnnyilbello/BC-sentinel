from __future__ import annotations

"""B11-9 Windows Release Candidate Acceptance & Freeze contract.

This final Beta11 milestone reconciles the accepted productization evidence and
defines the exact evidence required before the Beta11 release-candidate
checkpoint can be frozen. It does not publish a release, sign an artifact,
elevate privileges, install into machine scope, or expand protection authority.
"""

import hashlib
import json
from typing import Any, Final

from sentinel import beta11_clean_pc_lifecycle_acceptance as b118
from sentinel import beta11_first_run_health as health
from sentinel import beta11_install_lifecycle_contract as b113
from sentinel import beta11_persistent_data_model as b115
from sentinel import beta11_release_provenance as b117
from sentinel import beta11_upgrade_migration_contract as b116

SCHEMA: Final[str] = "bc-sentinel-beta11-release-candidate-freeze-v1"
PROFILE: Final[str] = "v0.11.0-beta.11-b119-windows-release-candidate-acceptance-freeze"
SOURCE_CHECKPOINT: Final[str] = "checkpoint/v011-beta11-b118-pass"
SOURCE_CHECKPOINT_COMMIT: Final[str] = "46d18b77aa382573e1e4e2a2eb381bcb71e03a69"
SOURCE_COVERAGE: Final[dict[str, int]] = {"PARTIAL": 4, "GAP": 0, "VERIFIED": 2}
VERIFIED_SCENARIOS: Final[tuple[str, ...]] = ("B7-POWERSHELL-001", "B7-RANSOMWARE-001")

SOURCE_B113_CONTRACT_DIGEST: Final[str] = "f084b67d16b87e17722e70890be13ba33fcd10d7c3ece43b499fcb01020e5aa6"
SOURCE_B115_MODEL_DIGEST: Final[str] = "38df2751392cd71bec8662c6d4f80b287c30aeb70841606399057254fe7a2a08"
SOURCE_B116_CONTRACT_DIGEST: Final[str] = "d2aa15228ba6d7e84b8cef074f132718549373d51b35d93da6f12aac54c700d9"
SOURCE_B117_CONTRACT_DIGEST: Final[str] = "a19d1ea8ad887b670cbbb9aef1a09db17e806fd59e5e89b603f9574c1912f109"
SOURCE_B118_CONTRACT_DIGEST: Final[str] = "8fb9060e3e41146a400a9cebdeec8978b96909c6aa6b2e29327ad9c60fb36269"
SOURCE_B118_TRANSCRIPT_DIGEST: Final[str] = "1d010b2ff4a4e52f8fed405180ff404331c4ada08684cf1bc1e126600b62bf22"

ACCEPTED_BETA11_CHECKPOINTS: Final[tuple[tuple[str, str], ...]] = (
    ("checkpoint/v011-beta11-b110-pass", "0bee65100c6713d11dedd56c28ee3118f0082624"),
    ("checkpoint/v011-beta11-b111-pass", "2d49bc2037d3d1f3fb40280277cf8d53927cc68b"),
    ("checkpoint/v011-beta11-b112-pass", "92b6317aa9e642a0062268bce9f92bb0a4ffb1a1"),
    ("checkpoint/v011-beta11-b113-pass", "4ce33199bb72d87c09b0c204a40c2046efcb615a"),
    ("checkpoint/v011-beta11-b114-pass", "5ec361050f4c490652f88c30ad3a3b60e586fecb"),
    ("checkpoint/v011-beta11-b115-pass", "19e40b9b41f4d87b3f081bb7e8bfb5b155db4660"),
    ("checkpoint/v011-beta11-b116-pass", "25fc9b50b17d9deb65d61a8e8994334259bb5042"),
    ("checkpoint/v011-beta11-b117-pass", "c7ca5e86af196863cc980bcd1e8616447d9f3d8a"),
    ("checkpoint/v011-beta11-b118-pass", SOURCE_CHECKPOINT_COMMIT),
)

REQUIRED_FINAL_EVIDENCE: Final[tuple[str, ...]] = (
    "FULL_BETA5_TO_BETA11_REGRESSION",
    "REPRODUCED_WINDOWS_ONEDIR_ARTIFACT",
    "ARTIFACT_MANIFEST_VALID",
    "PACKAGED_IDENTITY_PROBE",
    "PACKAGED_SELF_CHECK_PROBE",
    "PACKAGED_SMOKE_PROBE",
    "LIVE_FIRST_RUN_HEALTH_READY",
    "B118_DISPOSABLE_LIFECYCLE_REPLAY",
    "FACTUAL_AUTHENTICODE_STATE",
    "EXACT_CI_AND_LOCAL_ACCEPTANCE_SAME_COMMIT",
)

FREEZE_POLICY: Final[dict[str, Any]] = {
    "release_candidate_requires_exact_source_commit": True,
    "all_beta11_checkpoints_must_match": True,
    "accepted_predecessor_source_immutable": True,
    "full_regression_required": True,
    "fresh_windows_onedir_build_required": True,
    "artifact_manifest_validation_required": True,
    "packaged_runtime_probes_required": True,
    "live_first_run_health_ready_required": True,
    "b118_lifecycle_replay_required": True,
    "authenticode_state_must_be_observed": True,
    "unsigned_release_candidate_allowed": True,
    "invalid_or_unverified_signature_fails_closed": True,
    "signed_release_claim_requires_verified_signature": True,
    "ci_and_local_same_commit_required_before_freeze": True,
    "release_publication_performed_by_b119": False,
    "artifact_signing_performed_by_b119": False,
}

IMPLEMENTATION_STATE: Final[dict[str, bool]] = {
    "release_publication_execution_available": False,
    "artifact_signing_execution_available": False,
    "private_key_access_available": False,
    "certificate_enrollment_available": False,
    "automatic_update_execution_available": False,
    "host_machine_scope_install_execution_available": False,
    "host_registry_mutation_available": False,
    "privilege_elevation_available": False,
    "service_registration_available": False,
    "driver_registration_available": False,
    "autostart_registration_available": False,
    "network_required": False,
    "cloud_required": False,
    "coverage_promoted": False,
    "authority_expanded": False,
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
        "accepted_beta11_checkpoints": [
            {"checkpoint": checkpoint, "commit": commit}
            for checkpoint, commit in ACCEPTED_BETA11_CHECKPOINTS
        ],
        "source_b113_contract_digest": SOURCE_B113_CONTRACT_DIGEST,
        "source_b115_model_digest": SOURCE_B115_MODEL_DIGEST,
        "source_b116_contract_digest": SOURCE_B116_CONTRACT_DIGEST,
        "source_b117_contract_digest": SOURCE_B117_CONTRACT_DIGEST,
        "source_b118_contract_digest": SOURCE_B118_CONTRACT_DIGEST,
        "source_b118_transcript_digest": SOURCE_B118_TRANSCRIPT_DIGEST,
        "required_final_evidence": list(REQUIRED_FINAL_EVIDENCE),
        "freeze_policy": dict(FREEZE_POLICY),
        "implementation_state": dict(IMPLEMENTATION_STATE),
    }


def validate_contract(data: object) -> tuple[str, ...]:
    if not isinstance(data, dict):
        return ("b119:not_object",)
    failures: list[str] = []
    if data != contract():
        failures.append("b119:contract_changed")
    if b113.self_check()["contract_digest"] != SOURCE_B113_CONTRACT_DIGEST:
        failures.append("b119:b113_digest_mismatch")
    if b115.self_check()["model_digest"] != SOURCE_B115_MODEL_DIGEST:
        failures.append("b119:b115_digest_mismatch")
    if b116.self_check()["contract_digest"] != SOURCE_B116_CONTRACT_DIGEST:
        failures.append("b119:b116_digest_mismatch")
    if b117.self_check()["contract_digest"] != SOURCE_B117_CONTRACT_DIGEST:
        failures.append("b119:b117_digest_mismatch")
    b118_report = b118.self_check()
    if b118_report["contract_digest"] != SOURCE_B118_CONTRACT_DIGEST:
        failures.append("b119:b118_contract_digest_mismatch")
    if b118_report["lifecycle_transcript_digest"] != SOURCE_B118_TRANSCRIPT_DIGEST:
        failures.append("b119:b118_transcript_digest_mismatch")
    if b118_report["source_coverage"] != SOURCE_COVERAGE:
        failures.append("b119:coverage_changed")
    if tuple(b118_report["verified_scenarios"]) != VERIFIED_SCENARIOS:
        failures.append("b119:verified_scenarios_changed")
    if any(IMPLEMENTATION_STATE.values()):
        failures.append("b119:authority_or_claim_expanded")
    return tuple(dict.fromkeys(failures))


def evaluate_candidate_evidence(
    *,
    build_commit: str,
    artifact_manifest_valid: bool,
    packaged_identity_passed: bool,
    packaged_self_check_passed: bool,
    packaged_smoke_passed: bool,
    live_health_status: str,
    lifecycle_contract_digest: str,
    lifecycle_transcript_digest: str,
    authenticode_state: str,
) -> dict[str, Any]:
    reasons: list[str] = []
    if build_commit != SOURCE_CHECKPOINT_COMMIT and len(build_commit) != 40:
        reasons.append("build_commit_invalid")
    if not artifact_manifest_valid:
        reasons.append("artifact_manifest_invalid")
    if not packaged_identity_passed:
        reasons.append("packaged_identity_failed")
    if not packaged_self_check_passed:
        reasons.append("packaged_self_check_failed")
    if not packaged_smoke_passed:
        reasons.append("packaged_smoke_failed")
    if live_health_status != health.READY:
        reasons.append("live_health_not_ready")
    if lifecycle_contract_digest != SOURCE_B118_CONTRACT_DIGEST:
        reasons.append("lifecycle_contract_digest_mismatch")
    if lifecycle_transcript_digest != SOURCE_B118_TRANSCRIPT_DIGEST:
        reasons.append("lifecycle_transcript_digest_mismatch")
    if authenticode_state not in {"UNSIGNED", "SIGNED_VERIFIED"}:
        reasons.append("authenticode_state_not_acceptable")

    candidate_ready = not reasons
    signed_release_ready = candidate_ready and authenticode_state == "SIGNED_VERIFIED"
    return {
        "candidate_ready": candidate_ready,
        "signed_release_ready": signed_release_ready,
        "authenticode_state": authenticode_state,
        "release_publication_performed": False,
        "artifact_signing_performed": False,
        "reasons": sorted(set(reasons)),
    }


def self_check() -> dict[str, Any]:
    first = contract()
    second = contract()
    failures = list(validate_contract(first))
    deterministic = first == second and _digest(first) == _digest(second)
    if not deterministic:
        failures.append("b119:contract_not_deterministic")

    unsigned_sample = evaluate_candidate_evidence(
        build_commit=SOURCE_CHECKPOINT_COMMIT,
        artifact_manifest_valid=True,
        packaged_identity_passed=True,
        packaged_self_check_passed=True,
        packaged_smoke_passed=True,
        live_health_status=health.READY,
        lifecycle_contract_digest=SOURCE_B118_CONTRACT_DIGEST,
        lifecycle_transcript_digest=SOURCE_B118_TRANSCRIPT_DIGEST,
        authenticode_state="UNSIGNED",
    )
    if not unsigned_sample["candidate_ready"] or unsigned_sample["signed_release_ready"]:
        failures.append("b119:unsigned_rc_policy_invalid")

    invalid_signed = evaluate_candidate_evidence(
        build_commit=SOURCE_CHECKPOINT_COMMIT,
        artifact_manifest_valid=True,
        packaged_identity_passed=True,
        packaged_self_check_passed=True,
        packaged_smoke_passed=True,
        live_health_status=health.READY,
        lifecycle_contract_digest=SOURCE_B118_CONTRACT_DIGEST,
        lifecycle_transcript_digest=SOURCE_B118_TRANSCRIPT_DIGEST,
        authenticode_state="SIGNED_UNVERIFIED",
    )
    if invalid_signed["candidate_ready"]:
        failures.append("b119:unverified_signature_not_failed_closed")

    return {
        "passed": not failures,
        "failures": failures,
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "source_coverage": dict(SOURCE_COVERAGE),
        "verified_scenarios": list(VERIFIED_SCENARIOS),
        "contract_digest": _digest(first),
        "deterministic_contract": deterministic,
        "accepted_checkpoint_count": len(ACCEPTED_BETA11_CHECKPOINTS),
        "required_evidence_count": len(REQUIRED_FINAL_EVIDENCE),
        "source_b118_contract_digest": SOURCE_B118_CONTRACT_DIGEST,
        "source_b118_transcript_digest": SOURCE_B118_TRANSCRIPT_DIGEST,
        "unsigned_release_candidate_allowed": True,
        "unverified_signature_fails_closed": True,
        "release_publication_execution_available": False,
        "artifact_signing_execution_available": False,
        "network_required": False,
        "cloud_required": False,
        "coverage_promoted": False,
        "authority_expanded": False,
    }


def main() -> int:
    report = self_check()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

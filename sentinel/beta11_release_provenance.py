from __future__ import annotations

"""B11-7 deterministic release provenance and signing-readiness contract.

This milestone records factual release evidence without signing, publishing, or
mutating artifacts. A signature is never inferred from filenames, hashes,
certificate metadata, or user intent. Verified signing requires explicit,
caller-supplied Authenticode verification evidence; otherwise the state remains
UNSIGNED or SIGNED_UNVERIFIED.

The contract is intentionally reusable by later Beta11 lifecycle milestones:
the accepted B11-6 checkpoint anchors this policy, while each release record
binds its own build commit to matching CI and local acceptance evidence.
"""

import hashlib
import json
import re
from typing import Any, Final

from sentinel import beta11_artifact_manifest as artifact_manifest
from sentinel import beta11_upgrade_migration_contract as migration

SCHEMA: Final[str] = "bc-sentinel-beta11-release-provenance-contract-v1"
PROFILE: Final[str] = "v0.11.0-beta.11-b117-release-provenance-signing-readiness"
SOURCE_CHECKPOINT: Final[str] = "checkpoint/v011-beta11-b116-pass"
SOURCE_CHECKPOINT_COMMIT: Final[str] = "25fc9b50b17d9deb65d61a8e8994334259bb5042"
SOURCE_B116_CONTRACT_DIGEST: Final[str] = "d2aa15228ba6d7e84b8cef074f132718549373d51b35d93da6f12aac54c700d9"
SOURCE_COVERAGE: Final[dict[str, int]] = {"PARTIAL": 4, "GAP": 0, "VERIFIED": 2}
VERIFIED_SCENARIOS: Final[tuple[str, ...]] = (
    "B7-POWERSHELL-001",
    "B7-RANSOMWARE-001",
)
ARTIFACT_NAME: Final[str] = artifact_manifest.ARTIFACT_NAME
ARTIFACT_MANIFEST_SCHEMA: Final[str] = artifact_manifest.SCHEMA

SIGNING_STATES: Final[tuple[str, ...]] = (
    "UNSIGNED",
    "SIGNED_UNVERIFIED",
    "SIGNED_VERIFIED",
)
AUTHENTICODE_VERIFICATION_METHOD: Final[str] = "WINDOWS_AUTHENTICODE_VERIFY"

SIGNING_POLICY: Final[dict[str, Any]] = {
    "state_is_derived_from_evidence": True,
    "signature_presence_required_for_signed_state": True,
    "verified_signature_required_for_signed_verified_state": True,
    "signer_subject_required_for_verified_state": True,
    "certificate_thumbprint_sha256_required_for_verified_state": True,
    "verification_method_required_for_verified_state": True,
    "unsigned_is_default_when_signature_absent": True,
    "hashes_do_not_imply_signature": True,
    "filename_does_not_imply_signature": True,
    "signing_execution_available_in_b117": False,
    "signature_verification_execution_available_in_b117": False,
    "private_key_access_available_in_b117": False,
    "certificate_enrollment_available_in_b117": False,
    "timestamp_service_execution_available_in_b117": False,
}

RELEASE_EVIDENCE_POLICY: Final[dict[str, Any]] = {
    "artifact_sha256_required": True,
    "artifact_tree_digest_required": True,
    "artifact_manifest_digest_required": True,
    "exact_build_commit_required": True,
    "ci_acceptance_required": True,
    "local_acceptance_required": True,
    "ci_and_local_commit_must_equal_build_commit": True,
    "provenance_record_digest_required": True,
    "release_publication_execution_available_in_b117": False,
    "artifact_mutation_available_in_b117": False,
}

IMPLEMENTATION_STATE: Final[dict[str, bool]] = {
    "artifact_signing_execution_available": False,
    "signature_verification_execution_available": False,
    "private_key_access_available": False,
    "certificate_enrollment_available": False,
    "timestamp_service_execution_available": False,
    "release_publication_execution_available": False,
    "artifact_mutation_available": False,
    "installer_execution_available": False,
    "uninstaller_execution_available": False,
    "automatic_update_execution_available": False,
    "privilege_elevation_available": False,
    "service_registration_available": False,
    "driver_registration_available": False,
    "autostart_registration_available": False,
    "network_required": False,
    "cloud_required": False,
    "coverage_promoted": False,
    "authority_expanded": False,
}

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and _SHA256_RE.fullmatch(value) is not None


def _is_commit(value: object) -> bool:
    return isinstance(value, str) and _COMMIT_RE.fullmatch(value) is not None


def contract() -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "source_b116_contract_digest": migration.self_check()["contract_digest"],
        "artifact_name": ARTIFACT_NAME,
        "artifact_manifest_schema": ARTIFACT_MANIFEST_SCHEMA,
        "source_coverage": dict(SOURCE_COVERAGE),
        "verified_scenarios": list(VERIFIED_SCENARIOS),
        "signing_states": list(SIGNING_STATES),
        "signing_policy": dict(SIGNING_POLICY),
        "release_evidence_policy": dict(RELEASE_EVIDENCE_POLICY),
        "implementation_state": dict(IMPLEMENTATION_STATE),
        "contract_only": True,
    }


def validate_contract(data: object) -> tuple[str, ...]:
    if not isinstance(data, dict):
        return ("b117:not_object",)

    failures: list[str] = []
    expected_keys = {
        "schema",
        "profile",
        "source_checkpoint",
        "source_checkpoint_commit",
        "source_b116_contract_digest",
        "artifact_name",
        "artifact_manifest_schema",
        "source_coverage",
        "verified_scenarios",
        "signing_states",
        "signing_policy",
        "release_evidence_policy",
        "implementation_state",
        "contract_only",
    }
    if set(data) != expected_keys:
        failures.append("b117:unexpected_or_missing_fields")

    if data.get("schema") != SCHEMA or data.get("profile") != PROFILE:
        failures.append("b117:identity_invalid")
    if (
        data.get("source_checkpoint") != SOURCE_CHECKPOINT
        or data.get("source_checkpoint_commit") != SOURCE_CHECKPOINT_COMMIT
    ):
        failures.append("b117:source_checkpoint_invalid")
    if data.get("source_b116_contract_digest") != SOURCE_B116_CONTRACT_DIGEST:
        failures.append("b117:b116_contract_binding_invalid")
    if migration.self_check()["contract_digest"] != SOURCE_B116_CONTRACT_DIGEST:
        failures.append("b117:live_b116_contract_digest_mismatch")
    if data.get("artifact_name") != ARTIFACT_NAME or data.get("artifact_manifest_schema") != ARTIFACT_MANIFEST_SCHEMA:
        failures.append("b117:artifact_manifest_binding_invalid")
    if data.get("source_coverage") != SOURCE_COVERAGE:
        failures.append("b117:coverage_changed")
    if tuple(data.get("verified_scenarios") or ()) != VERIFIED_SCENARIOS:
        failures.append("b117:verified_scenarios_changed")
    if tuple(data.get("signing_states") or ()) != SIGNING_STATES:
        failures.append("b117:signing_states_changed")
    if data.get("signing_policy") != SIGNING_POLICY:
        failures.append("b117:signing_policy_changed")
    if data.get("release_evidence_policy") != RELEASE_EVIDENCE_POLICY:
        failures.append("b117:release_evidence_policy_changed")
    if data.get("implementation_state") != IMPLEMENTATION_STATE:
        failures.append("b117:implementation_state_changed")
    elif any(data["implementation_state"].values()):
        failures.append("b117:execution_authority_or_claim_enabled")
    if data.get("contract_only") is not True:
        failures.append("b117:contract_boundary_changed")

    return tuple(dict.fromkeys(failures))


def derive_signing_evidence(
    *,
    signature_present: bool,
    signature_verified: bool = False,
    signer_subject: str | None = None,
    certificate_thumbprint_sha256: str | None = None,
    verification_method: str | None = None,
    timestamp_present: bool = False,
) -> dict[str, Any]:
    """Derive a factual signing state from caller-supplied evidence.

    No signature verification is executed here. B11-7 only validates the shape
    and internal consistency of evidence produced elsewhere.
    """

    reasons: list[str] = []
    subject = signer_subject.strip() if isinstance(signer_subject, str) else None
    method = verification_method.strip() if isinstance(verification_method, str) else None
    thumbprint = (
        certificate_thumbprint_sha256.casefold()
        if isinstance(certificate_thumbprint_sha256, str)
        else None
    )

    if not isinstance(signature_present, bool) or not isinstance(signature_verified, bool):
        reasons.append("signing_flags_must_be_boolean")
        signature_present = bool(signature_present)
        signature_verified = bool(signature_verified)
    if not isinstance(timestamp_present, bool):
        reasons.append("timestamp_flag_must_be_boolean")
        timestamp_present = bool(timestamp_present)

    if not signature_present:
        state = "UNSIGNED"
        if signature_verified:
            reasons.append("verified_signature_without_signature")
        if subject:
            reasons.append("signer_subject_without_signature")
        if thumbprint:
            reasons.append("certificate_thumbprint_without_signature")
        if method:
            reasons.append("verification_method_without_signature")
        if timestamp_present:
            reasons.append("timestamp_without_signature")
    elif signature_verified:
        state = "SIGNED_VERIFIED"
        if not subject:
            reasons.append("verified_signer_subject_missing")
        if not _is_sha256(thumbprint):
            reasons.append("verified_certificate_thumbprint_invalid")
        if method != AUTHENTICODE_VERIFICATION_METHOD:
            reasons.append("verified_signature_method_invalid")
    else:
        state = "SIGNED_UNVERIFIED"
        if method == AUTHENTICODE_VERIFICATION_METHOD:
            reasons.append("authenticode_method_without_verified_result")

    return {
        "accepted": not reasons,
        "state": state,
        "signature_present": signature_present,
        "signature_verified": signature_verified,
        "signer_subject": subject,
        "certificate_thumbprint_sha256": thumbprint,
        "verification_method": method,
        "timestamp_present": timestamp_present,
        "verification_executed_by_b117": False,
        "signing_executed_by_b117": False,
        "reasons": sorted(set(reasons)),
    }


def validate_signing_evidence(data: object) -> tuple[str, ...]:
    if not isinstance(data, dict):
        return ("b117:signing_evidence_not_object",)
    expected_keys = {
        "accepted",
        "state",
        "signature_present",
        "signature_verified",
        "signer_subject",
        "certificate_thumbprint_sha256",
        "verification_method",
        "timestamp_present",
        "verification_executed_by_b117",
        "signing_executed_by_b117",
        "reasons",
    }
    if set(data) != expected_keys:
        return ("b117:signing_evidence_fields_invalid",)

    rebuilt = derive_signing_evidence(
        signature_present=data.get("signature_present"),
        signature_verified=data.get("signature_verified"),
        signer_subject=data.get("signer_subject"),
        certificate_thumbprint_sha256=data.get("certificate_thumbprint_sha256"),
        verification_method=data.get("verification_method"),
        timestamp_present=data.get("timestamp_present"),
    )
    if data != rebuilt:
        return ("b117:signing_evidence_inconsistent",)
    return ()


def build_release_record(
    *,
    artifact_name: str,
    artifact_sha256: str,
    artifact_tree_digest: str,
    artifact_manifest_digest: str,
    build_commit: str,
    ci_run_id: int,
    ci_commit: str,
    ci_passed: bool,
    local_commit: str,
    local_passed: bool,
    signing_evidence: dict[str, Any],
) -> dict[str, Any]:
    """Build a deterministic, non-publishing release-provenance record."""

    reasons: list[str] = []

    if artifact_name != ARTIFACT_NAME:
        reasons.append("artifact_name_mismatch")
    for value, reason in (
        (artifact_sha256, "artifact_sha256_invalid"),
        (artifact_tree_digest, "artifact_tree_digest_invalid"),
        (artifact_manifest_digest, "artifact_manifest_digest_invalid"),
    ):
        if not _is_sha256(value):
            reasons.append(reason)

    if not _is_commit(build_commit):
        reasons.append("build_commit_invalid")
    if not isinstance(ci_run_id, int) or isinstance(ci_run_id, bool) or ci_run_id <= 0:
        reasons.append("ci_run_id_invalid")
    if not isinstance(ci_passed, bool) or ci_passed is not True:
        reasons.append("ci_acceptance_not_passed")
    if not isinstance(local_passed, bool) or local_passed is not True:
        reasons.append("local_acceptance_not_passed")
    if ci_commit != build_commit:
        reasons.append("ci_commit_mismatch")
    if local_commit != build_commit:
        reasons.append("local_commit_mismatch")
    if validate_signing_evidence(signing_evidence):
        reasons.append("signing_evidence_invalid")
    elif signing_evidence.get("accepted") is not True:
        reasons.append("signing_evidence_rejected")

    signing_state = (
        signing_evidence.get("state")
        if isinstance(signing_evidence, dict) and signing_evidence.get("state") in SIGNING_STATES
        else "UNSIGNED"
    )
    provenance_ready = not reasons
    signed_release_ready = provenance_ready and signing_state == "SIGNED_VERIFIED"

    body = {
        "schema": "bc-sentinel-beta11-release-provenance-record-v1",
        "profile": PROFILE,
        "policy_source_checkpoint": SOURCE_CHECKPOINT,
        "policy_source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "policy_contract_digest": _digest(contract()),
        "artifact_name": artifact_name,
        "artifact_sha256": artifact_sha256.casefold() if isinstance(artifact_sha256, str) else artifact_sha256,
        "artifact_tree_digest": artifact_tree_digest.casefold() if isinstance(artifact_tree_digest, str) else artifact_tree_digest,
        "artifact_manifest_digest": artifact_manifest_digest.casefold() if isinstance(artifact_manifest_digest, str) else artifact_manifest_digest,
        "build_commit": build_commit,
        "ci_evidence": {
            "run_id": ci_run_id,
            "commit": ci_commit,
            "passed": ci_passed,
        },
        "local_evidence": {
            "commit": local_commit,
            "passed": local_passed,
        },
        "signing_evidence": dict(signing_evidence),
        "signing_state": signing_state,
        "provenance_ready": provenance_ready,
        "signed_release_ready": signed_release_ready,
        "release_publication_execution_available_in_b117": False,
        "artifact_signing_execution_available_in_b117": False,
        "artifact_mutation_available_in_b117": False,
        "reasons": sorted(set(reasons)),
    }
    return {**body, "record_digest": _digest(body)}


def validate_release_record(data: object) -> tuple[str, ...]:
    if not isinstance(data, dict):
        return ("b117:release_record_not_object",)

    failures: list[str] = []
    expected_keys = {
        "schema",
        "profile",
        "policy_source_checkpoint",
        "policy_source_checkpoint_commit",
        "policy_contract_digest",
        "artifact_name",
        "artifact_sha256",
        "artifact_tree_digest",
        "artifact_manifest_digest",
        "build_commit",
        "ci_evidence",
        "local_evidence",
        "signing_evidence",
        "signing_state",
        "provenance_ready",
        "signed_release_ready",
        "release_publication_execution_available_in_b117",
        "artifact_signing_execution_available_in_b117",
        "artifact_mutation_available_in_b117",
        "reasons",
        "record_digest",
    }
    if set(data) != expected_keys:
        failures.append("b117:release_record_fields_invalid")

    body = dict(data)
    record_digest = body.pop("record_digest", None)
    if not _is_sha256(record_digest) or record_digest != _digest(body):
        failures.append("b117:release_record_digest_invalid")

    signing = data.get("signing_evidence")
    if validate_signing_evidence(signing):
        failures.append("b117:release_record_signing_invalid")

    ci = data.get("ci_evidence")
    local = data.get("local_evidence")
    if not isinstance(ci, dict) or set(ci) != {"run_id", "commit", "passed"}:
        failures.append("b117:ci_evidence_invalid")
        ci = {}
    if not isinstance(local, dict) or set(local) != {"commit", "passed"}:
        failures.append("b117:local_evidence_invalid")
        local = {}

    if (
        data.get("schema") != "bc-sentinel-beta11-release-provenance-record-v1"
        or data.get("profile") != PROFILE
        or data.get("policy_source_checkpoint") != SOURCE_CHECKPOINT
        or data.get("policy_source_checkpoint_commit") != SOURCE_CHECKPOINT_COMMIT
        or data.get("policy_contract_digest") != _digest(contract())
    ):
        failures.append("b117:release_record_policy_binding_invalid")

    if data.get("artifact_name") != ARTIFACT_NAME:
        failures.append("b117:release_record_artifact_name_invalid")
    for key in ("artifact_sha256", "artifact_tree_digest", "artifact_manifest_digest"):
        if not _is_sha256(data.get(key)):
            failures.append(f"b117:{key}_invalid")

    build_commit = data.get("build_commit")
    if not _is_commit(build_commit):
        failures.append("b117:release_record_build_commit_invalid")
    if ci.get("commit") != build_commit or local.get("commit") != build_commit:
        failures.append("b117:release_record_acceptance_commit_mismatch")
    if ci.get("passed") is not True or local.get("passed") is not True:
        failures.append("b117:release_record_acceptance_not_passed")
    if not isinstance(ci.get("run_id"), int) or isinstance(ci.get("run_id"), bool) or ci.get("run_id", 0) <= 0:
        failures.append("b117:release_record_ci_run_id_invalid")

    signing_state = signing.get("state") if isinstance(signing, dict) else None
    if data.get("signing_state") != signing_state:
        failures.append("b117:release_record_signing_state_inconsistent")

    raw_reasons = data.get("reasons")
    if not isinstance(raw_reasons, list) or raw_reasons != sorted(set(raw_reasons)):
        failures.append("b117:release_record_reasons_invalid")
        raw_reasons = ["invalid"]
    expected_provenance_ready = not raw_reasons
    if data.get("provenance_ready") is not expected_provenance_ready:
        failures.append("b117:release_record_provenance_state_invalid")
    expected_signed_ready = expected_provenance_ready and signing_state == "SIGNED_VERIFIED"
    if data.get("signed_release_ready") is not expected_signed_ready:
        failures.append("b117:release_record_signed_state_invalid")

    for key in (
        "release_publication_execution_available_in_b117",
        "artifact_signing_execution_available_in_b117",
        "artifact_mutation_available_in_b117",
    ):
        if data.get(key) is not False:
            failures.append(f"b117:{key}_enabled")

    return tuple(dict.fromkeys(failures))


def self_check() -> dict[str, Any]:
    first = contract()
    second = contract()
    failures = list(validate_contract(first))
    deterministic = first == second and _digest(first) == _digest(second)
    if not deterministic:
        failures.append("b117:contract_not_deterministic")

    unsigned = derive_signing_evidence(signature_present=False)
    if unsigned["state"] != "UNSIGNED" or unsigned["accepted"] is not True:
        failures.append("b117:unsigned_default_failed")

    sample_record = build_release_record(
        artifact_name=ARTIFACT_NAME,
        artifact_sha256=hashlib.sha256(b"b117-sample-artifact").hexdigest(),
        artifact_tree_digest=hashlib.sha256(b"b117-sample-tree").hexdigest(),
        artifact_manifest_digest=hashlib.sha256(b"b117-sample-manifest").hexdigest(),
        build_commit=SOURCE_CHECKPOINT_COMMIT,
        ci_run_id=35255724334,
        ci_commit=SOURCE_CHECKPOINT_COMMIT,
        ci_passed=True,
        local_commit=SOURCE_CHECKPOINT_COMMIT,
        local_passed=True,
        signing_evidence=unsigned,
    )
    if validate_release_record(sample_record):
        failures.append("b117:sample_release_record_invalid")
    if not sample_record["provenance_ready"] or sample_record["signed_release_ready"]:
        failures.append("b117:unsigned_release_readiness_incorrect")

    verified = derive_signing_evidence(
        signature_present=True,
        signature_verified=True,
        signer_subject="CN=BC Sentinel Sample",
        certificate_thumbprint_sha256="a" * 64,
        verification_method=AUTHENTICODE_VERIFICATION_METHOD,
        timestamp_present=True,
    )
    signed_sample = build_release_record(
        artifact_name=ARTIFACT_NAME,
        artifact_sha256="b" * 64,
        artifact_tree_digest="c" * 64,
        artifact_manifest_digest="d" * 64,
        build_commit=SOURCE_CHECKPOINT_COMMIT,
        ci_run_id=35255724334,
        ci_commit=SOURCE_CHECKPOINT_COMMIT,
        ci_passed=True,
        local_commit=SOURCE_CHECKPOINT_COMMIT,
        local_passed=True,
        signing_evidence=verified,
    )
    if not signed_sample["signed_release_ready"]:
        failures.append("b117:verified_signing_state_not_supported")

    contradictory = derive_signing_evidence(
        signature_present=False,
        signature_verified=True,
        signer_subject="CN=Impossible",
        certificate_thumbprint_sha256="e" * 64,
        verification_method=AUTHENTICODE_VERIFICATION_METHOD,
        timestamp_present=True,
    )
    if contradictory["accepted"] or contradictory["state"] != "UNSIGNED":
        failures.append("b117:contradictory_signing_evidence_not_failed_closed")

    return {
        "passed": not failures,
        "failures": failures,
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "source_b116_contract_digest": migration.self_check()["contract_digest"],
        "artifact_name": ARTIFACT_NAME,
        "artifact_manifest_schema": ARTIFACT_MANIFEST_SCHEMA,
        "source_coverage": dict(SOURCE_COVERAGE),
        "verified_scenarios": list(VERIFIED_SCENARIOS),
        "contract_digest": _digest(first),
        "deterministic_contract": deterministic,
        "signing_states": list(SIGNING_STATES),
        "sample_release_record_only": True,
        "release_artifact_observed": False,
        "sample_release_record_digest": sample_record["record_digest"],
        "sample_signing_state": sample_record["signing_state"],
        "sample_provenance_ready": sample_record["provenance_ready"],
        "sample_signed_release_ready": sample_record["signed_release_ready"],
        "verified_signing_state_supported": signed_sample["signed_release_ready"],
        "artifact_signing_execution_available": False,
        "signature_verification_execution_available": False,
        "private_key_access_available": False,
        "certificate_enrollment_available": False,
        "timestamp_service_execution_available": False,
        "release_publication_execution_available": False,
        "artifact_mutation_available": False,
        "network_required": False,
        "cloud_required": False,
        "authority_expanded": False,
        "coverage_promoted": False,
    }


def main() -> int:
    report = self_check()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

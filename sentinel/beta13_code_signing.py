from __future__ import annotations

"""B13-4 Authenticode signing and SmartScreen-readiness evidence.

B13-4 separates three facts that must never be conflated:

1. the signing pipeline works;
2. Windows validates the Authenticode signature and RFC3161 timestamp;
3. the signer is a publicly trusted release identity.

Engineering/self-signed evidence may prove (1), but it can never promote the
CODE_SIGNING release blocker. SmartScreen reputation itself is not predictable
or asserted by this module.
"""

import hashlib
import json
import re
from typing import Any, Final

from sentinel import beta13_installer as b133

SCHEMA: Final[str] = "bc-sentinel-beta13-code-signing-v1"
PROFILE: Final[str] = "v0.13.0-b134-code-signing-smartscreen-readiness"
SOURCE_CHECKPOINT: Final[str] = "checkpoint/v013-b133-pass"
SOURCE_CHECKPOINT_COMMIT: Final[str] = "b6014ef74ffc77814f489532c8f2d09fb92fe17f"

PROVIDER_CERTIFICATE_STORE: Final[str] = "CERTIFICATE_STORE"
PROVIDER_ARTIFACT_SIGNING: Final[str] = "MICROSOFT_ARTIFACT_SIGNING"
PROVIDERS: Final[tuple[str, ...]] = (
    PROVIDER_CERTIFICATE_STORE,
    PROVIDER_ARTIFACT_SIGNING,
)

TRUST_ENGINEERING: Final[str] = "ENGINEERING_TEST"
TRUST_PUBLIC: Final[str] = "PUBLIC_TRUST"
TRUST_LEVELS: Final[tuple[str, ...]] = (TRUST_ENGINEERING, TRUST_PUBLIC)

SIGNATURE_ALGORITHM: Final[str] = "AUTHENTICODE"
FILE_DIGEST: Final[str] = "SHA256"
TIMESTAMP_PROTOCOL: Final[str] = "RFC3161"
TIMESTAMP_DIGEST: Final[str] = "SHA256"
DEFAULT_TIMESTAMP_URL: Final[str] = "http://timestamp.acs.microsoft.com"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_THUMBPRINT_RE = re.compile(r"^[0-9a-f]{40,64}$", re.IGNORECASE)
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")

BOUNDARIES: Final[dict[str, bool]] = {
    "private_key_embedded": False,
    "certificate_secret_embedded": False,
    "self_signed_counts_as_public_trust": False,
    "signature_required_for_public_release": True,
    "rfc3161_timestamp_required_for_public_release": True,
    "sha256_file_digest_required": True,
    "sha256_timestamp_digest_required": True,
    "publisher_identity_consistency_required": True,
    "signature_post_build_only": True,
    "signed_artifact_may_be_modified_after_signing": False,
    "smartscreen_reputation_guaranteed": False,
    "smartscreen_threshold_claimed": False,
    "coverage_promoted": False,
    "authority_expanded": False,
}


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _normalized_thumbprint(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("b134:thumbprint_not_string")
    cleaned = value.replace(" ", "").lower()
    if not _THUMBPRINT_RE.fullmatch(cleaned):
        raise ValueError("b134:thumbprint_invalid")
    return cleaned


def _artifact_record_failures(record: object, *, release: bool) -> list[str]:
    if not isinstance(record, dict):
        return ["b134:artifact_not_object"]
    failures: list[str] = []
    required = {
        "name",
        "path_role",
        "pre_sign_sha256",
        "post_sign_sha256",
        "authenticode_present",
        "windows_signature_status",
        "signer_subject",
        "signer_thumbprint",
        "timestamp_present",
        "timestamp_subject",
        "signtool_verify_passed",
        "modified_after_signing",
    }
    if set(record) != required:
        failures.append("b134:artifact_fields_invalid")

    if record.get("path_role") not in {"APPLICATION_EXE", "INSTALLER_EXE", "UNINSTALLER_EXE"}:
        failures.append("b134:artifact_role_invalid")
    for key in ("pre_sign_sha256", "post_sign_sha256"):
        value = record.get(key)
        if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
            failures.append(f"b134:{key}_invalid")
    if (
        isinstance(record.get("pre_sign_sha256"), str)
        and isinstance(record.get("post_sign_sha256"), str)
        and record["pre_sign_sha256"] == record["post_sign_sha256"]
    ):
        failures.append("b134:signature_did_not_change_artifact_hash")
    if record.get("authenticode_present") is not True:
        failures.append("b134:authenticode_missing")
    if not isinstance(record.get("signer_subject"), str) or not record["signer_subject"].strip():
        failures.append("b134:signer_subject_missing")
    try:
        _normalized_thumbprint(record.get("signer_thumbprint"))
    except ValueError as exc:
        failures.append(str(exc))
    if record.get("timestamp_present") is not True:
        failures.append("b134:rfc3161_timestamp_missing")
    if not isinstance(record.get("timestamp_subject"), str) or not record["timestamp_subject"].strip():
        failures.append("b134:timestamp_subject_missing")
    if record.get("modified_after_signing") is not False:
        failures.append("b134:artifact_modified_after_signing")
    if release:
        if record.get("windows_signature_status") != "Valid":
            failures.append("b134:release_signature_not_valid")
        if record.get("signtool_verify_passed") is not True:
            failures.append("b134:release_signtool_verify_failed")
    return failures


def build_signing_evidence(
    *,
    build_commit: str,
    provider: str,
    trust_level: str,
    expected_publisher: str,
    artifacts: list[dict[str, Any]],
    timestamp_url: str,
) -> dict[str, Any]:
    if not _COMMIT_RE.fullmatch(str(build_commit)):
        raise ValueError("b134:build_commit_invalid")
    if provider not in PROVIDERS:
        raise ValueError("b134:provider_invalid")
    if trust_level not in TRUST_LEVELS:
        raise ValueError("b134:trust_level_invalid")
    if not isinstance(expected_publisher, str) or not expected_publisher.strip():
        raise ValueError("b134:publisher_required")
    if not isinstance(timestamp_url, str) or not timestamp_url.lower().startswith(("http://", "https://")):
        raise ValueError("b134:timestamp_url_invalid")
    if not isinstance(artifacts, list) or len(artifacts) != 3:
        raise ValueError("b134:three_signed_artifacts_required")

    release = trust_level == TRUST_PUBLIC
    failures: list[str] = []
    roles: list[str] = []
    signer_subjects: list[str] = []
    signer_thumbprints: list[str] = []
    for artifact in artifacts:
        failures.extend(_artifact_record_failures(artifact, release=release))
        if isinstance(artifact, dict):
            roles.append(str(artifact.get("path_role")))
            signer_subjects.append(str(artifact.get("signer_subject", "")))
            try:
                signer_thumbprints.append(_normalized_thumbprint(artifact.get("signer_thumbprint")))
            except ValueError:
                pass

    if sorted(roles) != ["APPLICATION_EXE", "INSTALLER_EXE", "UNINSTALLER_EXE"]:
        failures.append("b134:required_artifact_roles_missing")
    if len(set(signer_subjects)) != 1:
        failures.append("b134:publisher_identity_drift")
    if len(set(signer_thumbprints)) != 1:
        failures.append("b134:signer_thumbprint_drift")
    if signer_subjects and expected_publisher.casefold() not in signer_subjects[0].casefold():
        failures.append("b134:publisher_subject_mismatch")

    public_trust_verified = release and not failures
    body = {
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "build_commit": build_commit,
        "provider": provider,
        "trust_level": trust_level,
        "expected_publisher": expected_publisher,
        "signature_algorithm": SIGNATURE_ALGORITHM,
        "file_digest": FILE_DIGEST,
        "timestamp_protocol": TIMESTAMP_PROTOCOL,
        "timestamp_digest": TIMESTAMP_DIGEST,
        "timestamp_url": timestamp_url,
        "artifact_count": len(artifacts),
        "artifacts": artifacts,
        "pipeline_evidence_valid": not failures,
        "public_trust_signature_verified": public_trust_verified,
        "code_signing_release_blocker_resolved": public_trust_verified,
        "smartscreen_reputation_guaranteed": False,
        "smartscreen_reputation_observed": False,
        "coverage_promoted": False,
        "authority_expanded": False,
        "failures": list(dict.fromkeys(failures)),
    }
    return {**body, "evidence_digest": _digest(body)}


def validate_signing_evidence(data: object, *, expected_build_commit: str | None = None) -> tuple[str, ...]:
    if not isinstance(data, dict):
        return ("b134:evidence_not_object",)
    failures: list[str] = []
    body = dict(data)
    digest = body.pop("evidence_digest", None)
    if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest) or digest != _digest(body):
        failures.append("b134:evidence_digest_invalid")

    fixed = {
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "signature_algorithm": SIGNATURE_ALGORITHM,
        "file_digest": FILE_DIGEST,
        "timestamp_protocol": TIMESTAMP_PROTOCOL,
        "timestamp_digest": TIMESTAMP_DIGEST,
        "smartscreen_reputation_guaranteed": False,
        "smartscreen_reputation_observed": False,
        "coverage_promoted": False,
        "authority_expanded": False,
    }
    for key, expected in fixed.items():
        if data.get(key) != expected:
            failures.append(f"b134:evidence_{key}_invalid")

    build_commit = data.get("build_commit")
    if not isinstance(build_commit, str) or not _COMMIT_RE.fullmatch(build_commit):
        failures.append("b134:evidence_build_commit_invalid")
    if expected_build_commit is not None and build_commit != expected_build_commit:
        failures.append("b134:evidence_build_commit_mismatch")

    provider = data.get("provider")
    if provider not in PROVIDERS:
        failures.append("b134:evidence_provider_invalid")
    trust_level = data.get("trust_level")
    if trust_level not in TRUST_LEVELS:
        failures.append("b134:evidence_trust_level_invalid")

    expected_publisher = data.get("expected_publisher")
    if not isinstance(expected_publisher, str) or not expected_publisher.strip():
        failures.append("b134:evidence_publisher_invalid")

    artifacts = data.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) != 3:
        failures.append("b134:evidence_artifacts_invalid")
        artifacts = []
    release = trust_level == TRUST_PUBLIC
    for artifact in artifacts:
        failures.extend(_artifact_record_failures(artifact, release=release))

    if isinstance(artifacts, list) and len(artifacts) == 3:
        roles = sorted(str(item.get("path_role")) for item in artifacts if isinstance(item, dict))
        if roles != ["APPLICATION_EXE", "INSTALLER_EXE", "UNINSTALLER_EXE"]:
            failures.append("b134:evidence_roles_invalid")
        subjects = {str(item.get("signer_subject", "")) for item in artifacts if isinstance(item, dict)}
        if len(subjects) != 1:
            failures.append("b134:evidence_publisher_identity_drift")
        thumbprints: set[str] = set()
        for item in artifacts:
            if not isinstance(item, dict):
                continue
            try:
                thumbprints.add(_normalized_thumbprint(item.get("signer_thumbprint")))
            except ValueError:
                pass
        if len(thumbprints) != 1:
            failures.append("b134:evidence_signer_thumbprint_drift")

    pipeline_valid = not any(
        item.startswith("b134:artifact_")
        or item.startswith("b134:authenticode_")
        or item.startswith("b134:rfc3161_")
        or item.startswith("b134:signer_")
        or item.startswith("b134:publisher_")
        or item.startswith("b134:signature_")
        or item.startswith("b134:required_")
        for item in failures
    )
    if data.get("pipeline_evidence_valid") != pipeline_valid:
        failures.append("b134:evidence_pipeline_validity_mismatch")

    expected_public = trust_level == TRUST_PUBLIC and pipeline_valid
    if data.get("public_trust_signature_verified") != expected_public:
        failures.append("b134:evidence_public_trust_state_invalid")
    if data.get("code_signing_release_blocker_resolved") != expected_public:
        failures.append("b134:evidence_release_blocker_state_invalid")

    return tuple(dict.fromkeys(failures))


def projected_readiness(*, public_trust_signature_verified: bool) -> dict[str, Any]:
    baseline = b133.projected_readiness()
    counts = dict(baseline["pillar_counts"])
    blockers = list(baseline["release_blockers"])
    resolved: list[str] = []
    if public_trust_signature_verified and "CODE_SIGNING" in blockers:
        blockers.remove("CODE_SIGNING")
        counts["READY"] += 1
        counts["BLOCKED"] -= 1
        resolved.append("CODE_SIGNING")
    return {
        "schema": "bc-sentinel-beta13-readiness-projection-v4",
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "pillar_counts": counts,
        "release_blockers": blockers,
        "release_blocker_count": len(blockers),
        "ready_for_public_launch": not blockers,
        "ready_for_paid_launch": not blockers,
        "resolved_by_b134": resolved,
        "public_trust_signature_verified": bool(public_trust_signature_verified),
        "coverage_promoted": False,
        "authority_expanded": False,
    }


def contract() -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "providers": list(PROVIDERS),
        "trust_levels": list(TRUST_LEVELS),
        "signature_algorithm": SIGNATURE_ALGORITHM,
        "file_digest": FILE_DIGEST,
        "timestamp_protocol": TIMESTAMP_PROTOCOL,
        "timestamp_digest": TIMESTAMP_DIGEST,
        "default_timestamp_url": DEFAULT_TIMESTAMP_URL,
        "boundaries": dict(BOUNDARIES),
        "engineering_readiness_projection": projected_readiness(public_trust_signature_verified=False),
        "public_trust_readiness_projection": projected_readiness(public_trust_signature_verified=True),
    }


def self_check() -> dict[str, Any]:
    first = contract()
    second = contract()
    failures: list[str] = []
    engineering = projected_readiness(public_trust_signature_verified=False)
    public = projected_readiness(public_trust_signature_verified=True)

    if first != second:
        failures.append("b134:contract_not_deterministic")
    if engineering["pillar_counts"] != {"READY": 7, "PARTIAL": 1, "BLOCKED": 2}:
        failures.append("b134:engineering_readiness_counts_invalid")
    if engineering["release_blockers"] != ["CODE_SIGNING", "LICENSING_TRIAL", "PRIVACY_SUPPORT"]:
        failures.append("b134:engineering_blockers_invalid")
    if engineering["release_blocker_count"] != 3:
        failures.append("b134:engineering_blocker_count_invalid")
    if public["pillar_counts"] != {"READY": 8, "PARTIAL": 1, "BLOCKED": 1}:
        failures.append("b134:public_readiness_counts_invalid")
    if public["release_blockers"] != ["LICENSING_TRIAL", "PRIVACY_SUPPORT"]:
        failures.append("b134:public_blockers_invalid")
    if public["release_blocker_count"] != 2:
        failures.append("b134:public_blocker_count_invalid")
    if BOUNDARIES["self_signed_counts_as_public_trust"]:
        failures.append("b134:self_signed_boundary_invalid")
    if BOUNDARIES["private_key_embedded"] or BOUNDARIES["certificate_secret_embedded"]:
        failures.append("b134:secret_embedding_boundary_invalid")
    if BOUNDARIES["smartscreen_reputation_guaranteed"] or BOUNDARIES["smartscreen_threshold_claimed"]:
        failures.append("b134:smartscreen_claim_boundary_invalid")

    return {
        "passed": not failures,
        "failures": failures,
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "contract_digest": _digest(first),
        "deterministic_contract": first == second,
        "engineering_readiness_projection": engineering,
        "public_trust_readiness_projection": public,
        "signing_pipeline_can_be_engineering_verified": True,
        "public_trust_signature_required_to_resolve_blocker": True,
        "self_signed_counts_as_public_trust": False,
        "smartscreen_reputation_guaranteed": False,
        "private_key_embedded": False,
        "coverage_promoted": False,
        "authority_expanded": False,
    }


def main() -> int:
    report = self_check()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

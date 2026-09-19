from __future__ import annotations

"""B13-7 distribution package and engineering release-candidate freeze.

B13-7 freezes a distributable *engineering* release candidate. It does not turn
an engineering/self-signed Authenticode certificate into Public Trust and it
does not claim SmartScreen reputation. Public/paid release remains blocked until
CODE_SIGNING is resolved with a trusted publisher identity.
"""

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Final, Mapping

from sentinel import beta13_code_signing as b134
from sentinel import beta13_commercial_readiness as b136

SCHEMA: Final[str] = "bc-sentinel-beta13-release-candidate-v1"
MANIFEST_SCHEMA: Final[str] = "bc-sentinel-beta13-distribution-manifest-v1"
PROVENANCE_SCHEMA: Final[str] = "bc-sentinel-beta13-release-provenance-v1"
EVIDENCE_SCHEMA: Final[str] = "bc-sentinel-beta13-rc-freeze-evidence-v1"
PROFILE: Final[str] = "v0.13.0-b137-distribution-package-rc-freeze"

SOURCE_CHECKPOINT: Final[str] = "checkpoint/v013-b136-pass"
SOURCE_CHECKPOINT_COMMIT: Final[str] = "b981afa453e6540e18e5ec1fac7da74ce9344829"
SOURCE_COVERAGE: Final[dict[str, int]] = {"PARTIAL": 4, "GAP": 0, "VERIFIED": 7}

PRODUCT_NAME: Final[str] = "BC Sentinel"
PRODUCT_VERSION: Final[str] = "0.13.0"
RC_LABEL: Final[str] = "0.13.0-rc1-engineering"
ARCHIVE_FILENAME: Final[str] = "BC-Sentinel-v0.13.0-RC1-Engineering.zip"
INSTALLER_FILENAME: Final[str] = "BC-Sentinel-Setup-v0.13.0-RC1-Engineering.exe"
MANIFEST_FILENAME: Final[str] = "distribution-manifest.json"
PROVENANCE_FILENAME: Final[str] = "release-provenance.json"
HASHES_FILENAME: Final[str] = "SHA256SUMS.txt"
SIGNING_EVIDENCE_FILENAME: Final[str] = "signing-evidence.json"
NOTICE_FILENAME: Final[str] = "RC-NOTICE.txt"

B135_CLEAN_PC_CI_RUN: Final[int] = 35446297278
B135_CLEAN_PC_CI_EVIDENCE_DIGEST: Final[str] = (
    "7f94aaaf996944d05fa0d0e49a65f65eb3a0d9628511bcb7e8735259babb7cf8"
)
B136_COMMERCIAL_CI_RUN: Final[int] = 35447930415
B136_CONTRACT_DIGEST: Final[str] = (
    "5b4a2d43aff8c4e085d615cf9d285c3cdcbf35c4e0954d10a0557a1b71f2ff1f"
)

ACCEPTED_CHECKPOINTS: Final[dict[str, str]] = {
    "checkpoint/v013-b130-pass": "6c1a3dedd48d2b26b716c199f74ea45d827ee01a",
    "checkpoint/v013-b131-pass": "cfb94fb65f90327504296809270bf3c573f083d0",
    "checkpoint/v013-b132-pass": "3e64155858d9b8c7efebc28aecc9689795159ae9",
    "checkpoint/v013-b133-pass": "b6014ef74ffc77814f489532c8f2d09fb92fe17f",
    "checkpoint/v013-b134-pass": "c2dc1b0df4becc18afa56915bb47b29b533a9a55",
    "checkpoint/v013-b135-pass": "cbead4c4e01818f5764ebeb82f85eb69f64e1f67",
    "checkpoint/v013-b136-pass": SOURCE_CHECKPOINT_COMMIT,
}

BOUNDARIES: Final[dict[str, bool]] = {
    "engineering_release_candidate": True,
    "public_release_ready": False,
    "paid_release_ready": False,
    "public_trust_signature_verified": False,
    "smartscreen_reputation_guaranteed": False,
    "release_publication_allowed": False,
    "private_signing_key_embedded": False,
    "automatic_quarantine": False,
    "automatic_repair": False,
    "automatic_restore": False,
    "terminate_process_authority": False,
    "privileged_system_mutation": False,
    "mandatory_network_for_core_protection": False,
    "mandatory_cloud_for_core_protection": False,
    "coverage_promoted": False,
    "authority_expanded": False,
}

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def projected_readiness() -> dict[str, Any]:
    baseline = b136.projected_readiness()
    return {
        "schema": "bc-sentinel-beta13-readiness-projection-v7",
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "pillar_counts": dict(baseline["pillar_counts"]),
        "release_blockers": list(baseline["release_blockers"]),
        "release_blocker_count": int(baseline["release_blocker_count"]),
        "engineering_release_candidate_ready": True,
        "ready_for_public_launch": False,
        "ready_for_paid_launch": False,
        "resolved_by_b137": [],
        "coverage_promoted": False,
        "authority_expanded": False,
    }


def contract() -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "source_coverage": dict(SOURCE_COVERAGE),
        "product": PRODUCT_NAME,
        "product_version": PRODUCT_VERSION,
        "rc_label": RC_LABEL,
        "archive_filename": ARCHIVE_FILENAME,
        "installer_filename": INSTALLER_FILENAME,
        "accepted_checkpoints": dict(ACCEPTED_CHECKPOINTS),
        "clean_pc_ci_run": B135_CLEAN_PC_CI_RUN,
        "clean_pc_ci_evidence_digest": B135_CLEAN_PC_CI_EVIDENCE_DIGEST,
        "commercial_ci_run": B136_COMMERCIAL_CI_RUN,
        "commercial_contract_digest": B136_CONTRACT_DIGEST,
        "readiness_projection": projected_readiness(),
        "boundaries": dict(BOUNDARIES),
    }


def self_check() -> dict[str, Any]:
    first = contract()
    second = contract()
    failures: list[str] = []
    readiness = projected_readiness()

    if first != second:
        failures.append("b137:contract_not_deterministic")
    if len(ACCEPTED_CHECKPOINTS) != 7:
        failures.append("b137:accepted_checkpoint_count_invalid")
    if ACCEPTED_CHECKPOINTS.get(SOURCE_CHECKPOINT) != SOURCE_CHECKPOINT_COMMIT:
        failures.append("b137:source_checkpoint_binding_invalid")
    if readiness["pillar_counts"] != {"READY": 9, "PARTIAL": 0, "BLOCKED": 1}:
        failures.append("b137:readiness_counts_invalid")
    if readiness["release_blockers"] != ["CODE_SIGNING"]:
        failures.append("b137:release_blockers_invalid")
    if readiness["engineering_release_candidate_ready"] is not True:
        failures.append("b137:engineering_rc_not_ready")
    if readiness["ready_for_public_launch"] is not False:
        failures.append("b137:public_launch_incorrectly_ready")
    if readiness["ready_for_paid_launch"] is not False:
        failures.append("b137:paid_launch_incorrectly_ready")

    expected_true = {"engineering_release_candidate"}
    for key, value in BOUNDARIES.items():
        if key in expected_true:
            if value is not True:
                failures.append(f"b137:{key}_invalid")
        elif value is not False:
            failures.append(f"b137:{key}_unexpectedly_enabled")

    return {
        "passed": not failures,
        "failures": list(dict.fromkeys(failures)),
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "source_coverage": dict(SOURCE_COVERAGE),
        "accepted_checkpoint_count": len(ACCEPTED_CHECKPOINTS),
        "contract_digest": _digest(first),
        "deterministic_contract": first == second,
        "readiness_projection": readiness,
        "engineering_release_candidate_ready": True,
        "public_release_ready": False,
        "paid_release_ready": False,
        "public_trust_signature_verified": False,
        "smartscreen_reputation_guaranteed": False,
        "coverage_promoted": False,
        "authority_expanded": False,
    }


def _artifact_by_role(signing_evidence: Mapping[str, Any], role: str) -> Mapping[str, Any]:
    artifacts = signing_evidence.get("artifacts")
    if not isinstance(artifacts, list):
        raise ValueError("b137:signing_artifacts_invalid")
    matches = [
        item for item in artifacts
        if isinstance(item, dict) and item.get("path_role") == role
    ]
    if len(matches) != 1:
        raise ValueError(f"b137:signing_role_invalid:{role}")
    return matches[0]


def build_distribution_manifest(
    *,
    build_commit: str,
    installer_path: str | Path,
    signing_evidence: Mapping[str, Any],
) -> dict[str, Any]:
    if not _COMMIT_RE.fullmatch(str(build_commit)):
        raise ValueError("b137:build_commit_invalid")
    installer = Path(installer_path)
    if not installer.is_file():
        raise ValueError("b137:installer_missing")

    signing_failures = b134.validate_signing_evidence(
        signing_evidence,
        expected_build_commit=build_commit,
    )
    if signing_failures:
        raise ValueError("b137:signing_evidence_invalid:" + ",".join(signing_failures))
    if signing_evidence.get("trust_level") != b134.TRUST_ENGINEERING:
        raise ValueError("b137:engineering_trust_required")
    if signing_evidence.get("public_trust_signature_verified") is not False:
        raise ValueError("b137:public_trust_must_remain_false")

    installer_record = _artifact_by_role(signing_evidence, "INSTALLER_EXE")
    installer_sha = sha256_file(installer)
    if installer_record.get("post_sign_sha256") != installer_sha:
        raise ValueError("b137:installer_hash_not_bound_to_signing_evidence")

    body = {
        "schema": MANIFEST_SCHEMA,
        "profile": PROFILE,
        "product": PRODUCT_NAME,
        "product_version": PRODUCT_VERSION,
        "rc_label": RC_LABEL,
        "build_commit": build_commit,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "installer_filename": INSTALLER_FILENAME,
        "installer_sha256": installer_sha,
        "installer_bytes": installer.stat().st_size,
        "signing_evidence_filename": SIGNING_EVIDENCE_FILENAME,
        "signing_evidence_digest": signing_evidence.get("evidence_digest"),
        "signer_subject": installer_record.get("signer_subject"),
        "signer_thumbprint": installer_record.get("signer_thumbprint"),
        "timestamp_present": installer_record.get("timestamp_present"),
        "trust_level": signing_evidence.get("trust_level"),
        "public_trust_signature_verified": False,
        "smartscreen_reputation_guaranteed": False,
        "engineering_release_candidate": True,
        "public_release_ready": False,
        "coverage": dict(SOURCE_COVERAGE),
    }
    return {**body, "manifest_digest": _digest(body)}


def validate_distribution_manifest(
    data: object,
    *,
    installer_path: str | Path | None = None,
    expected_build_commit: str | None = None,
) -> tuple[str, ...]:
    if not isinstance(data, dict):
        return ("b137:manifest_not_object",)
    failures: list[str] = []
    body = dict(data)
    digest = body.pop("manifest_digest", None)
    if (
        not isinstance(digest, str)
        or not _SHA256_RE.fullmatch(digest)
        or digest != _digest(body)
    ):
        failures.append("b137:manifest_digest_invalid")

    fixed = {
        "schema": MANIFEST_SCHEMA,
        "profile": PROFILE,
        "product": PRODUCT_NAME,
        "product_version": PRODUCT_VERSION,
        "rc_label": RC_LABEL,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "installer_filename": INSTALLER_FILENAME,
        "signing_evidence_filename": SIGNING_EVIDENCE_FILENAME,
        "public_trust_signature_verified": False,
        "smartscreen_reputation_guaranteed": False,
        "engineering_release_candidate": True,
        "public_release_ready": False,
        "coverage": SOURCE_COVERAGE,
    }
    for key, value in fixed.items():
        if data.get(key) != value:
            failures.append(f"b137:manifest_fixed_field:{key}")

    build_commit = data.get("build_commit")
    if not isinstance(build_commit, str) or not _COMMIT_RE.fullmatch(build_commit):
        failures.append("b137:manifest_build_commit_invalid")
    elif expected_build_commit is not None and build_commit != expected_build_commit:
        failures.append("b137:manifest_build_commit_mismatch")

    for key in ("installer_sha256", "signing_evidence_digest"):
        value = data.get(key)
        if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
            failures.append(f"b137:manifest_{key}_invalid")
    if not isinstance(data.get("installer_bytes"), int) or data["installer_bytes"] <= 0:
        failures.append("b137:manifest_installer_bytes_invalid")
    if data.get("timestamp_present") is not True:
        failures.append("b137:manifest_timestamp_missing")
    if data.get("trust_level") != b134.TRUST_ENGINEERING:
        failures.append("b137:manifest_trust_level_invalid")
    if not isinstance(data.get("signer_subject"), str) or not data["signer_subject"].strip():
        failures.append("b137:manifest_signer_subject_missing")
    if not isinstance(data.get("signer_thumbprint"), str) or not data["signer_thumbprint"].strip():
        failures.append("b137:manifest_signer_thumbprint_missing")

    if installer_path is not None:
        installer = Path(installer_path)
        if not installer.is_file():
            failures.append("b137:manifest_installer_missing")
        else:
            if data.get("installer_sha256") != sha256_file(installer):
                failures.append("b137:manifest_installer_hash_mismatch")
            if data.get("installer_bytes") != installer.stat().st_size:
                failures.append("b137:manifest_installer_size_mismatch")
    return tuple(dict.fromkeys(failures))


def build_release_provenance(
    *,
    build_commit: str,
    distribution_manifest: Mapping[str, Any],
) -> dict[str, Any]:
    if not _COMMIT_RE.fullmatch(str(build_commit)):
        raise ValueError("b137:provenance_build_commit_invalid")
    manifest_failures = validate_distribution_manifest(
        distribution_manifest,
        expected_build_commit=build_commit,
    )
    if manifest_failures:
        raise ValueError("b137:provenance_manifest_invalid:" + ",".join(manifest_failures))
    body = {
        "schema": PROVENANCE_SCHEMA,
        "profile": PROFILE,
        "build_commit": build_commit,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "accepted_checkpoints": dict(ACCEPTED_CHECKPOINTS),
        "accepted_checkpoint_count": len(ACCEPTED_CHECKPOINTS),
        "b135_clean_pc_ci_run": B135_CLEAN_PC_CI_RUN,
        "b135_clean_pc_ci_evidence_digest": B135_CLEAN_PC_CI_EVIDENCE_DIGEST,
        "b136_commercial_ci_run": B136_COMMERCIAL_CI_RUN,
        "b136_contract_digest": B136_CONTRACT_DIGEST,
        "distribution_manifest_digest": distribution_manifest["manifest_digest"],
        "coverage": dict(SOURCE_COVERAGE),
        "readiness": projected_readiness(),
        "engineering_release_candidate": True,
        "public_release_ready": False,
        "paid_release_ready": False,
        "remaining_release_blockers": ["CODE_SIGNING"],
        "public_trust_signature_verified": False,
        "smartscreen_reputation_guaranteed": False,
    }
    return {**body, "provenance_digest": _digest(body)}


def validate_release_provenance(
    data: object,
    *,
    expected_build_commit: str | None = None,
    expected_manifest_digest: str | None = None,
) -> tuple[str, ...]:
    if not isinstance(data, dict):
        return ("b137:provenance_not_object",)
    failures: list[str] = []
    body = dict(data)
    digest = body.pop("provenance_digest", None)
    if (
        not isinstance(digest, str)
        or not _SHA256_RE.fullmatch(digest)
        or digest != _digest(body)
    ):
        failures.append("b137:provenance_digest_invalid")

    fixed = {
        "schema": PROVENANCE_SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "accepted_checkpoints": ACCEPTED_CHECKPOINTS,
        "accepted_checkpoint_count": len(ACCEPTED_CHECKPOINTS),
        "b135_clean_pc_ci_run": B135_CLEAN_PC_CI_RUN,
        "b135_clean_pc_ci_evidence_digest": B135_CLEAN_PC_CI_EVIDENCE_DIGEST,
        "b136_commercial_ci_run": B136_COMMERCIAL_CI_RUN,
        "b136_contract_digest": B136_CONTRACT_DIGEST,
        "coverage": SOURCE_COVERAGE,
        "engineering_release_candidate": True,
        "public_release_ready": False,
        "paid_release_ready": False,
        "remaining_release_blockers": ["CODE_SIGNING"],
        "public_trust_signature_verified": False,
        "smartscreen_reputation_guaranteed": False,
    }
    for key, value in fixed.items():
        if data.get(key) != value:
            failures.append(f"b137:provenance_fixed_field:{key}")

    build_commit = data.get("build_commit")
    if not isinstance(build_commit, str) or not _COMMIT_RE.fullmatch(build_commit):
        failures.append("b137:provenance_build_commit_invalid")
    elif expected_build_commit is not None and build_commit != expected_build_commit:
        failures.append("b137:provenance_build_commit_mismatch")

    manifest_digest = data.get("distribution_manifest_digest")
    if not isinstance(manifest_digest, str) or not _SHA256_RE.fullmatch(manifest_digest):
        failures.append("b137:provenance_manifest_digest_invalid")
    elif expected_manifest_digest is not None and manifest_digest != expected_manifest_digest:
        failures.append("b137:provenance_manifest_digest_mismatch")

    readiness = data.get("readiness")
    if not isinstance(readiness, dict):
        failures.append("b137:provenance_readiness_invalid")
    else:
        if readiness.get("pillar_counts") != {"READY": 9, "PARTIAL": 0, "BLOCKED": 1}:
            failures.append("b137:provenance_readiness_counts_invalid")
        if readiness.get("release_blockers") != ["CODE_SIGNING"]:
            failures.append("b137:provenance_release_blockers_invalid")
    return tuple(dict.fromkeys(failures))


def rc_notice() -> str:
    return (
        "BC Sentinel v0.13.0 RC1 — ENGINEERING RELEASE CANDIDATE\n"
        "\n"
        "This package is for final engineering acceptance. It is Authenticode-signed "
        "with an engineering/self-signed certificate and therefore does NOT establish "
        "Public Trust. SmartScreen reputation is not guaranteed. Public/paid release "
        "remains blocked by CODE_SIGNING until a trusted publisher certificate is used.\n"
        "\n"
        "Accepted detection coverage remains scenario-specific: "
        "PARTIAL=4 / GAP=0 / VERIFIED=7.\n"
    )


def write_distribution_metadata(
    *,
    root: str | Path,
    build_commit: str,
    signing_evidence_path: str | Path,
) -> dict[str, Any]:
    root_path = Path(root)
    installer = root_path / INSTALLER_FILENAME
    signing_source = Path(signing_evidence_path)
    if not installer.is_file():
        raise ValueError("b137:distribution_installer_missing")
    if not signing_source.is_file():
        raise ValueError("b137:distribution_signing_evidence_missing")

    signing_evidence = json.loads(signing_source.read_text(encoding="utf-8-sig"))
    manifest = build_distribution_manifest(
        build_commit=build_commit,
        installer_path=installer,
        signing_evidence=signing_evidence,
    )
    provenance = build_release_provenance(
        build_commit=build_commit,
        distribution_manifest=manifest,
    )

    (root_path / SIGNING_EVIDENCE_FILENAME).write_text(
        json.dumps(signing_evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (root_path / MANIFEST_FILENAME).write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (root_path / PROVENANCE_FILENAME).write_text(
        json.dumps(provenance, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (root_path / NOTICE_FILENAME).write_text(rc_notice(), encoding="utf-8")

    hash_targets = (
        INSTALLER_FILENAME,
        SIGNING_EVIDENCE_FILENAME,
        MANIFEST_FILENAME,
        PROVENANCE_FILENAME,
        NOTICE_FILENAME,
    )
    hash_lines = [f"{sha256_file(root_path / name)}  {name}" for name in hash_targets]
    (root_path / HASHES_FILENAME).write_text(
        "\n".join(hash_lines) + "\n",
        encoding="utf-8",
    )
    return {
        "passed": True,
        "manifest": manifest,
        "provenance": provenance,
        "hash_file": HASHES_FILENAME,
        "hash_entry_count": len(hash_targets),
    }


def validate_distribution_root(
    root: str | Path,
    *,
    expected_build_commit: str | None = None,
) -> tuple[str, ...]:
    root_path = Path(root)
    failures: list[str] = []
    required = {
        INSTALLER_FILENAME,
        SIGNING_EVIDENCE_FILENAME,
        MANIFEST_FILENAME,
        PROVENANCE_FILENAME,
        HASHES_FILENAME,
        NOTICE_FILENAME,
    }
    present = {item.name for item in root_path.iterdir()} if root_path.is_dir() else set()
    if present != required:
        failures.append("b137:distribution_file_inventory_invalid")
        return tuple(failures)

    try:
        manifest = json.loads((root_path / MANIFEST_FILENAME).read_text(encoding="utf-8"))
        provenance = json.loads((root_path / PROVENANCE_FILENAME).read_text(encoding="utf-8"))
        signing = json.loads((root_path / SIGNING_EVIDENCE_FILENAME).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ("b137:distribution_json_unreadable",)

    failures.extend(
        validate_distribution_manifest(
            manifest,
            installer_path=root_path / INSTALLER_FILENAME,
            expected_build_commit=expected_build_commit,
        )
    )
    failures.extend(
        validate_release_provenance(
            provenance,
            expected_build_commit=expected_build_commit,
            expected_manifest_digest=manifest.get("manifest_digest"),
        )
    )
    signing_failures = b134.validate_signing_evidence(
        signing,
        expected_build_commit=expected_build_commit,
    )
    failures.extend("b137:signing:" + item for item in signing_failures)
    if signing.get("trust_level") != b134.TRUST_ENGINEERING:
        failures.append("b137:distribution_signing_not_engineering")
    if signing.get("public_trust_signature_verified") is not False:
        failures.append("b137:distribution_public_trust_incorrect")

    hash_lines = (root_path / HASHES_FILENAME).read_text(encoding="utf-8").splitlines()
    parsed: dict[str, str] = {}
    for line in hash_lines:
        parts = line.split("  ", 1)
        if len(parts) != 2:
            failures.append("b137:hash_line_invalid")
            continue
        parsed[parts[1]] = parts[0].lower()
    expected_hash_names = required - {HASHES_FILENAME}
    if set(parsed) != expected_hash_names:
        failures.append("b137:hash_inventory_invalid")
    else:
        for name, expected_hash in parsed.items():
            if not _SHA256_RE.fullmatch(expected_hash):
                failures.append(f"b137:hash_invalid:{name}")
            elif sha256_file(root_path / name) != expected_hash:
                failures.append(f"b137:hash_mismatch:{name}")

    notice = (root_path / NOTICE_FILENAME).read_text(encoding="utf-8")
    for required_text in (
        "ENGINEERING RELEASE CANDIDATE",
        "does NOT establish Public Trust",
        "CODE_SIGNING",
        "PARTIAL=4 / GAP=0 / VERIFIED=7",
    ):
        if required_text not in notice:
            failures.append("b137:notice_missing_boundary")
    return tuple(dict.fromkeys(failures))


def build_freeze_evidence(
    *,
    build_commit: str,
    environment_classification: str,
    authoritative_clean_pc_evidence: bool,
    archive_sha256: str,
    installer_sha256: str,
    manifest_digest: str,
    provenance_digest: str,
    install_passed: bool,
    self_check_passed: bool,
    ui_smoke_passed: bool,
    diagnostics_passed: bool,
    uninstall_passed: bool,
) -> dict[str, Any]:
    if not _COMMIT_RE.fullmatch(str(build_commit)):
        raise ValueError("b137:evidence_build_commit_invalid")
    for key, value in {
        "archive_sha256": archive_sha256,
        "installer_sha256": installer_sha256,
        "manifest_digest": manifest_digest,
        "provenance_digest": provenance_digest,
    }.items():
        if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
            raise ValueError(f"b137:evidence_{key}_invalid")

    allowed_env = {"DISPOSABLE_WINDOWS_CI_RUNNER", "LOCAL_GUARDED_REHEARSAL"}
    if environment_classification not in allowed_env:
        raise ValueError("b137:evidence_environment_invalid")
    expected_authority = environment_classification == "DISPOSABLE_WINDOWS_CI_RUNNER"
    if authoritative_clean_pc_evidence is not expected_authority:
        raise ValueError("b137:evidence_clean_pc_authority_invalid")

    body = {
        "schema": EVIDENCE_SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "build_commit": build_commit,
        "environment_classification": environment_classification,
        "authoritative_clean_pc_evidence": authoritative_clean_pc_evidence,
        "archive_sha256": archive_sha256,
        "installer_sha256": installer_sha256,
        "manifest_digest": manifest_digest,
        "provenance_digest": provenance_digest,
        "install_passed": bool(install_passed),
        "self_check_passed": bool(self_check_passed),
        "ui_smoke_passed": bool(ui_smoke_passed),
        "diagnostics_passed": bool(diagnostics_passed),
        "uninstall_passed": bool(uninstall_passed),
        "engineering_release_candidate_ready": True,
        "public_release_ready": False,
        "paid_release_ready": False,
        "public_trust_signature_verified": False,
        "remaining_release_blockers": ["CODE_SIGNING"],
        "coverage": dict(SOURCE_COVERAGE),
        "coverage_promoted": False,
        "authority_expanded": False,
    }
    return {**body, "evidence_digest": _digest(body)}


def validate_freeze_evidence(
    data: object,
    *,
    expected_build_commit: str | None = None,
) -> tuple[str, ...]:
    if not isinstance(data, dict):
        return ("b137:evidence_not_object",)
    failures: list[str] = []
    body = dict(data)
    digest = body.pop("evidence_digest", None)
    if (
        not isinstance(digest, str)
        or not _SHA256_RE.fullmatch(digest)
        or digest != _digest(body)
    ):
        failures.append("b137:evidence_digest_invalid")

    if data.get("schema") != EVIDENCE_SCHEMA or data.get("profile") != PROFILE:
        failures.append("b137:evidence_identity_invalid")
    if data.get("source_checkpoint") != SOURCE_CHECKPOINT:
        failures.append("b137:evidence_source_checkpoint_invalid")
    if data.get("source_checkpoint_commit") != SOURCE_CHECKPOINT_COMMIT:
        failures.append("b137:evidence_source_commit_invalid")
    if expected_build_commit is not None and data.get("build_commit") != expected_build_commit:
        failures.append("b137:evidence_build_commit_mismatch")

    environment = data.get("environment_classification")
    expected_authority = environment == "DISPOSABLE_WINDOWS_CI_RUNNER"
    if environment not in {"DISPOSABLE_WINDOWS_CI_RUNNER", "LOCAL_GUARDED_REHEARSAL"}:
        failures.append("b137:evidence_environment_invalid")
    if data.get("authoritative_clean_pc_evidence") is not expected_authority:
        failures.append("b137:evidence_clean_pc_authority_invalid")

    for key in (
        "archive_sha256",
        "installer_sha256",
        "manifest_digest",
        "provenance_digest",
    ):
        value = data.get(key)
        if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
            failures.append(f"b137:evidence_{key}_invalid")

    for key in (
        "install_passed",
        "self_check_passed",
        "ui_smoke_passed",
        "diagnostics_passed",
        "uninstall_passed",
        "engineering_release_candidate_ready",
    ):
        if data.get(key) is not True:
            failures.append(f"b137:evidence_{key}_false")

    fixed_false = (
        "public_release_ready",
        "paid_release_ready",
        "public_trust_signature_verified",
        "coverage_promoted",
        "authority_expanded",
    )
    for key in fixed_false:
        if data.get(key) is not False:
            failures.append(f"b137:evidence_{key}_invalid")
    if data.get("remaining_release_blockers") != ["CODE_SIGNING"]:
        failures.append("b137:evidence_release_blockers_invalid")
    if data.get("coverage") != SOURCE_COVERAGE:
        failures.append("b137:evidence_coverage_invalid")
    return tuple(dict.fromkeys(failures))


def _read_json(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("b137:json_object_required")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write-metadata", action="store_true")
    parser.add_argument("--validate-root", action="store_true")
    parser.add_argument("--root")
    parser.add_argument("--build-commit")
    parser.add_argument("--signing-evidence")
    args = parser.parse_args()

    if args.write_metadata:
        if not args.root or not args.build_commit or not args.signing_evidence:
            raise SystemExit("--write-metadata requires --root --build-commit --signing-evidence")
        result = write_distribution_metadata(
            root=args.root,
            build_commit=args.build_commit,
            signing_evidence_path=args.signing_evidence,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0

    if args.validate_root:
        if not args.root:
            raise SystemExit("--validate-root requires --root")
        failures = validate_distribution_root(
            args.root,
            expected_build_commit=args.build_commit,
        )
        print(json.dumps({"passed": not failures, "failures": list(failures)}, indent=2, sort_keys=True))
        return 0 if not failures else 1

    result = self_check()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

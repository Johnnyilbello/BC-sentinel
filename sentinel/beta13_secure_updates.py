from __future__ import annotations

"""B13-2 Secure Update Channel & Rule Delivery.

Transport-agnostic update verification for BC Sentinel. Update metadata must be
Ed25519-signed by an explicitly pinned public key, payloads are SHA-256/size
bound, metadata is time-bounded, sequence numbers are monotonic, source version
ranges are enforced, and rollback is restricted to the immediately previous
verified state.

This module does not download, execute, install, elevate, register services or
mutate system protection. It verifies and stages payloads only. Production key
provisioning is deliberately external to the source tree so no private signing
key is ever embedded in the product.
"""

import base64
import binascii
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
from typing import Any, Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from sentinel import beta13_safe_response as b131

SCHEMA: Final[str] = "bc-sentinel-beta13-update-manifest-v1"
PROFILE: Final[str] = "v0.13.0-b132-secure-update-channel-rule-delivery"
STATE_SCHEMA: Final[str] = "bc-sentinel-beta13-update-state-v1"
RULE_BUNDLE_SCHEMA: Final[str] = "bc-sentinel-beta13-rule-bundle-v1"
SOURCE_CHECKPOINT: Final[str] = "checkpoint/v013-b131-pass"
SOURCE_CHECKPOINT_COMMIT: Final[str] = "cfb94fb65f90327504296809270bf3c573f083d0"

PRODUCT: Final[str] = "BC Sentinel"
CHANNEL: Final[str] = "stable"
APPLICATION: Final[str] = "APPLICATION"
RULE_BUNDLE: Final[str] = "RULE_BUNDLE"
UPDATE_TYPES: Final[tuple[str, ...]] = (APPLICATION, RULE_BUNDLE)
SIGNATURE_ALGORITHM: Final[str] = "ED25519"
MAX_MANIFEST_VALIDITY_SECONDS: Final[int] = 14 * 24 * 60 * 60
MAX_APPLICATION_BYTES: Final[int] = 512 * 1024 * 1024
MAX_RULE_BUNDLE_BYTES: Final[int] = 16 * 1024 * 1024

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_VERSION_RE = re.compile(r"^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")

BOUNDARIES: Final[dict[str, bool]] = {
    "transport_agnostic": True,
    "pinned_public_key_required": True,
    "ed25519_signature_required": True,
    "sha256_payload_binding_required": True,
    "payload_size_binding_required": True,
    "expiry_required": True,
    "monotonic_sequence_required": True,
    "source_version_range_required": True,
    "rollback_only_to_previous_verified_state": True,
    "explicit_rollback_confirmation_required": True,
    "private_key_embedded": False,
    "network_fetch_implemented": False,
    "payload_execution": False,
    "installer_execution": False,
    "privilege_elevation": False,
    "service_registration": False,
    "driver_registration": False,
    "automatic_restart": False,
    "coverage_promoted": False,
    "authority_expanded": False,
}


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_version(value: object) -> tuple[int, int, int]:
    if not isinstance(value, str):
        raise ValueError("b132:version_not_string")
    match = _VERSION_RE.fullmatch(value.strip())
    if match is None:
        raise ValueError("b132:version_invalid")
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def normalize_version(value: object) -> str:
    major, minor, patch = parse_version(value)
    return f"v{major}.{minor}.{patch}"


def key_id_for_public_key(public_key_raw: bytes) -> str:
    if not isinstance(public_key_raw, bytes) or len(public_key_raw) != 32:
        raise ValueError("b132:ed25519_public_key_invalid")
    return hashlib.sha256(public_key_raw).hexdigest()[:24]


@dataclass(frozen=True)
class TrustedUpdateRoot:
    key_id: str
    public_key_b64: str
    algorithm: str = SIGNATURE_ALGORITHM

    def public_key_raw(self) -> bytes:
        if self.algorithm != SIGNATURE_ALGORITHM:
            raise ValueError("b132:trusted_root_algorithm_invalid")
        try:
            raw = base64.b64decode(self.public_key_b64, validate=True)
        except (ValueError, TypeError, binascii.Error) as exc:
            raise ValueError("b132:trusted_root_key_encoding_invalid") from exc
        if len(raw) != 32:
            raise ValueError("b132:trusted_root_key_length_invalid")
        if self.key_id != key_id_for_public_key(raw):
            raise ValueError("b132:trusted_root_key_id_mismatch")
        return raw

    def validate(self) -> None:
        self.public_key_raw()


@dataclass(frozen=True)
class UpdateState:
    update_type: str
    current_version: str
    highest_sequence: int
    current_sha256: str
    previous_version: str | None = None
    previous_sequence: int | None = None
    previous_sha256: str | None = None

    def validate(self) -> None:
        if self.update_type not in UPDATE_TYPES:
            raise ValueError("b132:state_update_type_invalid")
        normalize_version(self.current_version)
        if not isinstance(self.highest_sequence, int) or isinstance(self.highest_sequence, bool) or self.highest_sequence < 0:
            raise ValueError("b132:state_sequence_invalid")
        if not _SHA256_RE.fullmatch(self.current_sha256):
            raise ValueError("b132:state_current_sha256_invalid")
        previous_fields = (self.previous_version, self.previous_sequence, self.previous_sha256)
        if any(item is not None for item in previous_fields):
            if not all(item is not None for item in previous_fields):
                raise ValueError("b132:state_previous_fields_incomplete")
            normalize_version(self.previous_version)
            if (
                not isinstance(self.previous_sequence, int)
                or isinstance(self.previous_sequence, bool)
                or self.previous_sequence < 0
                or self.previous_sequence >= self.highest_sequence
            ):
                raise ValueError("b132:state_previous_sequence_invalid")
            if not isinstance(self.previous_sha256, str) or not _SHA256_RE.fullmatch(self.previous_sha256):
                raise ValueError("b132:state_previous_sha256_invalid")

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "schema": STATE_SCHEMA,
            "update_type": self.update_type,
            "current_version": normalize_version(self.current_version),
            "highest_sequence": self.highest_sequence,
            "current_sha256": self.current_sha256,
            "previous_version": normalize_version(self.previous_version) if self.previous_version is not None else None,
            "previous_sequence": self.previous_sequence,
            "previous_sha256": self.previous_sha256,
        }


def initial_state(*, update_type: str, current_version: str, current_sha256: str = "0" * 64) -> UpdateState:
    state = UpdateState(
        update_type=update_type,
        current_version=normalize_version(current_version),
        highest_sequence=0,
        current_sha256=current_sha256,
    )
    state.validate()
    return state


_MANIFEST_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "schema",
        "profile",
        "product",
        "channel",
        "update_type",
        "target_version",
        "sequence",
        "artifact_name",
        "artifact_sha256",
        "artifact_bytes",
        "issued_at",
        "expires_at",
        "min_source_version",
        "max_source_version",
        "key_id",
        "signature_algorithm",
        "signature_b64",
    }
)


def manifest_body(manifest: dict[str, Any]) -> dict[str, Any]:
    return {key: manifest[key] for key in sorted(_MANIFEST_FIELDS - {"signature_b64"}) if key in manifest}


def manifest_signing_bytes(manifest: dict[str, Any]) -> bytes:
    return _canonical(manifest_body(manifest))


def _validate_manifest_shape(manifest: object) -> list[str]:
    if not isinstance(manifest, dict):
        return ["b132:manifest_not_object"]
    failures: list[str] = []
    if set(manifest) != _MANIFEST_FIELDS:
        failures.append("b132:manifest_fields_invalid")
    if manifest.get("schema") != SCHEMA or manifest.get("profile") != PROFILE:
        failures.append("b132:manifest_identity_invalid")
    if manifest.get("product") != PRODUCT or manifest.get("channel") != CHANNEL:
        failures.append("b132:manifest_product_channel_invalid")
    if manifest.get("update_type") not in UPDATE_TYPES:
        failures.append("b132:manifest_update_type_invalid")
    try:
        normalize_version(manifest.get("target_version"))
        normalize_version(manifest.get("min_source_version"))
        normalize_version(manifest.get("max_source_version"))
    except ValueError:
        failures.append("b132:manifest_version_invalid")

    sequence = manifest.get("sequence")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence <= 0:
        failures.append("b132:manifest_sequence_invalid")

    artifact_name = manifest.get("artifact_name")
    if (
        not isinstance(artifact_name, str)
        or not artifact_name
        or artifact_name in {".", ".."}
        or "/" in artifact_name
        or "\\" in artifact_name
        or Path(artifact_name).name != artifact_name
    ):
        failures.append("b132:manifest_artifact_name_invalid")

    artifact_sha256 = manifest.get("artifact_sha256")
    if not isinstance(artifact_sha256, str) or not _SHA256_RE.fullmatch(artifact_sha256):
        failures.append("b132:manifest_artifact_sha256_invalid")

    artifact_bytes = manifest.get("artifact_bytes")
    max_bytes = MAX_RULE_BUNDLE_BYTES if manifest.get("update_type") == RULE_BUNDLE else MAX_APPLICATION_BYTES
    if (
        not isinstance(artifact_bytes, int)
        or isinstance(artifact_bytes, bool)
        or artifact_bytes <= 0
        or artifact_bytes > max_bytes
    ):
        failures.append("b132:manifest_artifact_bytes_invalid")

    issued_at = manifest.get("issued_at")
    expires_at = manifest.get("expires_at")
    if not isinstance(issued_at, int) or isinstance(issued_at, bool) or issued_at < 0:
        failures.append("b132:manifest_issued_at_invalid")
    if not isinstance(expires_at, int) or isinstance(expires_at, bool) or expires_at <= 0:
        failures.append("b132:manifest_expires_at_invalid")
    if isinstance(issued_at, int) and isinstance(expires_at, int):
        if expires_at <= issued_at:
            failures.append("b132:manifest_time_order_invalid")
        elif expires_at - issued_at > MAX_MANIFEST_VALIDITY_SECONDS:
            failures.append("b132:manifest_validity_too_long")

    if not isinstance(manifest.get("key_id"), str) or not re.fullmatch(r"[0-9a-f]{24}", str(manifest.get("key_id"))):
        failures.append("b132:manifest_key_id_invalid")
    if manifest.get("signature_algorithm") != SIGNATURE_ALGORITHM:
        failures.append("b132:manifest_signature_algorithm_invalid")
    signature = manifest.get("signature_b64")
    if not isinstance(signature, str):
        failures.append("b132:manifest_signature_invalid")
    else:
        try:
            raw_signature = base64.b64decode(signature, validate=True)
        except (ValueError, binascii.Error):
            failures.append("b132:manifest_signature_invalid")
        else:
            if len(raw_signature) != 64:
                failures.append("b132:manifest_signature_invalid")
    return list(dict.fromkeys(failures))


def verify_manifest(
    manifest: object,
    *,
    trusted_root: TrustedUpdateRoot,
    state: UpdateState,
    now: int,
) -> dict[str, Any]:
    failures = _validate_manifest_shape(manifest)
    try:
        trusted_root.validate()
    except ValueError as exc:
        failures.append(str(exc))
    try:
        state.validate()
    except ValueError as exc:
        failures.append(str(exc))

    if not isinstance(now, int) or isinstance(now, bool) or now < 0:
        failures.append("b132:now_invalid")

    if not isinstance(manifest, dict):
        return {"passed": False, "failures": list(dict.fromkeys(failures)), "eligible": False}

    if manifest.get("key_id") != trusted_root.key_id:
        failures.append("b132:manifest_untrusted_key")
    if manifest.get("update_type") != state.update_type:
        failures.append("b132:manifest_state_type_mismatch")

    if isinstance(now, int):
        issued_at = manifest.get("issued_at")
        expires_at = manifest.get("expires_at")
        if isinstance(issued_at, int) and now < issued_at:
            failures.append("b132:manifest_not_yet_valid")
        if isinstance(expires_at, int) and now > expires_at:
            failures.append("b132:manifest_expired")

    try:
        current_version = parse_version(state.current_version)
        target_version = parse_version(manifest.get("target_version"))
        min_source = parse_version(manifest.get("min_source_version"))
        max_source = parse_version(manifest.get("max_source_version"))
    except ValueError:
        pass
    else:
        if not (min_source <= current_version <= max_source):
            failures.append("b132:source_version_outside_pinned_range")
        if target_version <= current_version:
            failures.append("b132:target_version_not_newer")

    sequence = manifest.get("sequence")
    if isinstance(sequence, int) and sequence <= state.highest_sequence:
        failures.append("b132:sequence_replay_or_rollback")

    if not failures:
        try:
            signature = base64.b64decode(manifest["signature_b64"], validate=True)
            Ed25519PublicKey.from_public_bytes(trusted_root.public_key_raw()).verify(
                signature,
                manifest_signing_bytes(manifest),
            )
        except (InvalidSignature, ValueError, TypeError):
            failures.append("b132:signature_verification_failed")

    digest = _digest(manifest_body(manifest)) if isinstance(manifest, dict) else None
    return {
        "passed": not failures,
        "eligible": not failures,
        "failures": list(dict.fromkeys(failures)),
        "manifest_digest": digest,
        "update_type": manifest.get("update_type"),
        "target_version": manifest.get("target_version"),
        "sequence": manifest.get("sequence"),
        "signature_verified": not failures,
        "payload_verified": False,
        "execution_available": False,
    }


def verify_payload(path: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    failures: list[str] = []
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        return {"passed": False, "failures": ["b132:payload_missing"]}
    if path.is_symlink() or not resolved.is_file():
        failures.append("b132:payload_regular_file_required")
    try:
        size = resolved.stat().st_size
    except OSError:
        failures.append("b132:payload_metadata_unavailable")
        size = -1
    if size != manifest.get("artifact_bytes"):
        failures.append("b132:payload_size_mismatch")
    try:
        digest = sha256_file(resolved)
    except OSError:
        failures.append("b132:payload_unreadable")
        digest = ""
    if digest != manifest.get("artifact_sha256"):
        failures.append("b132:payload_sha256_mismatch")
    return {
        "passed": not failures,
        "failures": list(dict.fromkeys(failures)),
        "payload_sha256": digest,
        "payload_bytes": size,
        "execution_available": False,
    }


def validate_rule_bundle(path: Path, *, expected_version: str) -> dict[str, Any]:
    failures: list[str] = []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {"passed": False, "failures": ["b132:rule_bundle_unreadable"], "rule_count": 0}
    if not isinstance(payload, dict) or set(payload) != {"schema", "bundle_version", "rules"}:
        failures.append("b132:rule_bundle_fields_invalid")
        return {"passed": False, "failures": failures, "rule_count": 0}
    if payload.get("schema") != RULE_BUNDLE_SCHEMA:
        failures.append("b132:rule_bundle_schema_invalid")
    try:
        if normalize_version(payload.get("bundle_version")) != normalize_version(expected_version):
            failures.append("b132:rule_bundle_version_mismatch")
    except ValueError:
        failures.append("b132:rule_bundle_version_invalid")

    rules = payload.get("rules")
    if not isinstance(rules, list) or not rules:
        failures.append("b132:rule_bundle_rules_invalid")
        rules = []
    seen: set[str] = set()
    for index, rule in enumerate(rules):
        prefix = f"b132:rule[{index}]"
        if not isinstance(rule, dict) or set(rule) != {"rule_id", "indicator_sha256", "severity", "disposition"}:
            failures.append(prefix + "_fields_invalid")
            continue
        rule_id = rule.get("rule_id")
        if not isinstance(rule_id, str) or not re.fullmatch(r"[A-Z0-9][A-Z0-9._-]{2,63}", rule_id):
            failures.append(prefix + "_id_invalid")
        elif rule_id in seen:
            failures.append(prefix + "_duplicate")
        else:
            seen.add(rule_id)
        indicator = rule.get("indicator_sha256")
        if not isinstance(indicator, str) or not _SHA256_RE.fullmatch(indicator):
            failures.append(prefix + "_indicator_invalid")
        if rule.get("severity") not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            failures.append(prefix + "_severity_invalid")
        if rule.get("disposition") != "DETECT_ONLY":
            failures.append(prefix + "_disposition_invalid")
    return {
        "passed": not failures,
        "failures": list(dict.fromkeys(failures)),
        "bundle_version": payload.get("bundle_version"),
        "rule_count": len(rules),
        "detect_only": all(isinstance(rule, dict) and rule.get("disposition") == "DETECT_ONLY" for rule in rules),
    }


def stage_verified_payload(
    source: Path,
    *,
    staging_root: Path,
    manifest: dict[str, Any],
    trusted_root: TrustedUpdateRoot,
    state: UpdateState,
    now: int,
) -> dict[str, Any]:
    manifest_report = verify_manifest(manifest, trusted_root=trusted_root, state=state, now=now)
    if not manifest_report["passed"]:
        return {
            "passed": False,
            "failures": ["b132:manifest_not_eligible", *manifest_report["failures"]],
            "staged_path": None,
        }
    payload_report = verify_payload(source, manifest)
    if not payload_report["passed"]:
        return {
            "passed": False,
            "failures": ["b132:payload_not_verified", *payload_report["failures"]],
            "staged_path": None,
        }

    root = staging_root.resolve(strict=False)
    root.mkdir(parents=True, exist_ok=True)
    if root.is_symlink():
        return {"passed": False, "failures": ["b132:staging_root_symlink_refused"], "staged_path": None}

    digest = str(manifest["artifact_sha256"])
    suffix = Path(str(manifest["artifact_name"])).suffix or ".pkg"
    destination = root / f"{digest}{suffix}"
    metadata_path = root / f"{digest}.manifest.json"

    fd, tmp_name = tempfile.mkstemp(prefix=".bcs-update-", suffix=".tmp", dir=str(root))
    os.close(fd)
    tmp = Path(tmp_name)
    try:
        shutil.copyfile(source, tmp)
        if sha256_file(tmp) != digest or tmp.stat().st_size != int(manifest["artifact_bytes"]):
            return {"passed": False, "failures": ["b132:staged_payload_revalidation_failed"], "staged_path": None}
        os.replace(tmp, destination)
        metadata = {
            "schema": "bc-sentinel-beta13-staged-update-v1",
            "manifest_digest": manifest_report["manifest_digest"],
            "artifact_sha256": digest,
            "artifact_bytes": int(manifest["artifact_bytes"]),
            "update_type": manifest["update_type"],
            "target_version": normalize_version(manifest["target_version"]),
            "sequence": int(manifest["sequence"]),
            "execution_available": False,
        }
        metadata_path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    finally:
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass

    if manifest["update_type"] == RULE_BUNDLE:
        rule_report = validate_rule_bundle(destination, expected_version=str(manifest["target_version"]))
        if not rule_report["passed"]:
            try:
                destination.unlink(missing_ok=True)
                metadata_path.unlink(missing_ok=True)
            except OSError:
                pass
            return {
                "passed": False,
                "failures": ["b132:rule_bundle_validation_failed", *rule_report["failures"]],
                "staged_path": None,
            }
    else:
        rule_report = None

    return {
        "passed": True,
        "failures": [],
        "staged_path": str(destination),
        "metadata_path": str(metadata_path),
        "manifest_digest": manifest_report["manifest_digest"],
        "payload_sha256": digest,
        "payload_bytes": int(manifest["artifact_bytes"]),
        "rule_bundle": rule_report,
        "execution_available": False,
    }


def advance_state(state: UpdateState, manifest: dict[str, Any], *, staged_sha256: str) -> UpdateState:
    state.validate()
    if staged_sha256 != manifest.get("artifact_sha256") or not _SHA256_RE.fullmatch(staged_sha256):
        raise ValueError("b132:advance_state_payload_binding_invalid")
    target_version = normalize_version(manifest.get("target_version"))
    sequence = manifest.get("sequence")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence <= state.highest_sequence:
        raise ValueError("b132:advance_state_sequence_invalid")
    if parse_version(target_version) <= parse_version(state.current_version):
        raise ValueError("b132:advance_state_version_invalid")
    next_state = UpdateState(
        update_type=state.update_type,
        current_version=target_version,
        highest_sequence=sequence,
        current_sha256=staged_sha256,
        previous_version=normalize_version(state.current_version),
        previous_sequence=state.highest_sequence,
        previous_sha256=state.current_sha256,
    )
    next_state.validate()
    return next_state


def build_rollback_plan(
    state: UpdateState,
    *,
    requested_version: str,
    explicit_user_confirmation: bool,
) -> dict[str, Any]:
    state.validate()
    failures: list[str] = []
    try:
        requested = normalize_version(requested_version)
    except ValueError:
        requested = ""
        failures.append("b132:rollback_version_invalid")

    if state.previous_version is None or state.previous_sequence is None or state.previous_sha256 is None:
        failures.append("b132:rollback_previous_state_missing")
    elif requested != normalize_version(state.previous_version):
        failures.append("b132:rollback_only_previous_verified_version_allowed")
    if explicit_user_confirmation is not True:
        failures.append("b132:rollback_explicit_confirmation_required")

    return {
        "eligible": not failures,
        "failures": list(dict.fromkeys(failures)),
        "update_type": state.update_type,
        "current_version": normalize_version(state.current_version),
        "requested_version": requested,
        "previous_version": normalize_version(state.previous_version) if state.previous_version is not None else None,
        "previous_sha256": state.previous_sha256,
        "rollback_execution_available_in_b132": False,
        "automatic_rollback": False,
        "explicit_user_confirmation_required": True,
    }


def projected_readiness() -> dict[str, Any]:
    baseline = b131.projected_readiness()
    counts = dict(baseline["pillar_counts"])
    blockers = list(baseline["release_blockers"])
    if "SECURE_UPDATES" in blockers:
        blockers.remove("SECURE_UPDATES")
        counts["READY"] += 1
        counts["BLOCKED"] -= 1
    return {
        "schema": "bc-sentinel-beta13-readiness-projection-v2",
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "pillar_counts": counts,
        "release_blockers": blockers,
        "release_blocker_count": len(blockers),
        "ready_for_public_launch": not blockers,
        "ready_for_paid_launch": not blockers,
        "resolved_by_b132": ["SECURE_UPDATES"],
        "coverage_promoted": False,
        "authority_expanded": False,
    }


def contract() -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "product": PRODUCT,
        "channel": CHANNEL,
        "update_types": list(UPDATE_TYPES),
        "signature_algorithm": SIGNATURE_ALGORITHM,
        "max_manifest_validity_seconds": MAX_MANIFEST_VALIDITY_SECONDS,
        "boundaries": dict(BOUNDARIES),
        "readiness_projection": projected_readiness(),
    }


def self_check() -> dict[str, Any]:
    first = contract()
    second = contract()
    readiness = projected_readiness()
    failures: list[str] = []
    if first != second:
        failures.append("b132:contract_not_deterministic")
    if readiness["pillar_counts"] != {"READY": 6, "PARTIAL": 1, "BLOCKED": 3}:
        failures.append("b132:readiness_counts_invalid")
    if readiness["release_blockers"] != [
        "INSTALLER_LIFECYCLE",
        "CODE_SIGNING",
        "LICENSING_TRIAL",
        "PRIVACY_SUPPORT",
    ]:
        failures.append("b132:readiness_blockers_invalid")
    if readiness["release_blocker_count"] != 4:
        failures.append("b132:readiness_blocker_count_invalid")
    if BOUNDARIES["private_key_embedded"]:
        failures.append("b132:private_key_boundary_invalid")
    for field in (
        "network_fetch_implemented",
        "payload_execution",
        "installer_execution",
        "privilege_elevation",
        "service_registration",
        "driver_registration",
        "automatic_restart",
        "coverage_promoted",
        "authority_expanded",
    ):
        if BOUNDARIES[field]:
            failures.append(f"b132:{field}_unexpectedly_enabled")

    return {
        "passed": not failures,
        "failures": failures,
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_checkpoint": SOURCE_CHECKPOINT,
        "source_checkpoint_commit": SOURCE_CHECKPOINT_COMMIT,
        "contract_digest": _digest(first),
        "deterministic_contract": first == second,
        "boundaries": dict(BOUNDARIES),
        "readiness_projection": readiness,
        "secure_updates_ready": True,
        "private_key_embedded": False,
        "network_required": False,
        "cloud_required": False,
        "payload_execution_available": False,
        "installer_execution_available": False,
        "coverage_promoted": False,
        "authority_expanded": False,
    }


def main() -> int:
    report = self_check()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel import beta13_secure_updates as b132


def _keypair():
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    root = b132.TrustedUpdateRoot(
        key_id=b132.key_id_for_public_key(public),
        public_key_b64=base64.b64encode(public).decode("ascii"),
    )
    return private, root


def _signed_manifest(
    private: Ed25519PrivateKey,
    root: b132.TrustedUpdateRoot,
    *,
    update_type: str,
    target_version: str,
    sequence: int,
    artifact_name: str,
    artifact_bytes: bytes,
    issued_at: int = 1000,
    expires_at: int = 2000,
    min_source_version: str = "v0.0.0",
    max_source_version: str = "v99.99.99",
) -> dict:
    manifest = {
        "schema": b132.SCHEMA,
        "profile": b132.PROFILE,
        "product": b132.PRODUCT,
        "channel": b132.CHANNEL,
        "update_type": update_type,
        "target_version": target_version,
        "sequence": sequence,
        "artifact_name": artifact_name,
        "artifact_sha256": hashlib.sha256(artifact_bytes).hexdigest(),
        "artifact_bytes": len(artifact_bytes),
        "issued_at": issued_at,
        "expires_at": expires_at,
        "min_source_version": min_source_version,
        "max_source_version": max_source_version,
        "key_id": root.key_id,
        "signature_algorithm": b132.SIGNATURE_ALGORITHM,
        "signature_b64": "",
    }
    manifest["signature_b64"] = base64.b64encode(
        private.sign(b132.manifest_signing_bytes(manifest))
    ).decode("ascii")
    return manifest


def test_self_check_binds_exact_b131_checkpoint_and_reduces_blockers():
    report = b132.self_check()
    assert report["passed"] is True
    assert report["source_checkpoint"] == "checkpoint/v013-b131-pass"
    assert report["source_checkpoint_commit"] == "cfb94fb65f90327504296809270bf3c573f083d0"
    projection = report["readiness_projection"]
    assert projection["pillar_counts"] == {"READY": 6, "PARTIAL": 1, "BLOCKED": 3}
    assert projection["release_blocker_count"] == 4
    assert projection["release_blockers"] == [
        "INSTALLER_LIFECYCLE",
        "CODE_SIGNING",
        "LICENSING_TRIAL",
        "PRIVACY_SUPPORT",
    ]


def test_valid_signed_application_manifest_verifies():
    private, root = _keypair()
    payload = b"BC Sentinel controlled application update"
    manifest = _signed_manifest(
        private,
        root,
        update_type=b132.APPLICATION,
        target_version="v0.13.1",
        sequence=1,
        artifact_name="bc-sentinel-v0131.zip",
        artifact_bytes=payload,
        min_source_version="v0.13.0",
        max_source_version="v0.13.0",
    )
    state = b132.initial_state(update_type=b132.APPLICATION, current_version="v0.13.0")

    report = b132.verify_manifest(manifest, trusted_root=root, state=state, now=1500)

    assert report["passed"] is True
    assert report["eligible"] is True
    assert report["signature_verified"] is True
    assert len(report["manifest_digest"]) == 64
    assert report["execution_available"] is False


def test_manifest_tampering_breaks_signature():
    private, root = _keypair()
    payload = b"payload"
    manifest = _signed_manifest(
        private,
        root,
        update_type=b132.APPLICATION,
        target_version="v0.13.1",
        sequence=1,
        artifact_name="update.zip",
        artifact_bytes=payload,
    )
    manifest["artifact_sha256"] = "f" * 64
    state = b132.initial_state(update_type=b132.APPLICATION, current_version="v0.13.0")

    report = b132.verify_manifest(manifest, trusted_root=root, state=state, now=1500)

    assert report["passed"] is False
    assert "b132:signature_verification_failed" in report["failures"]


@pytest.mark.parametrize(
    ("mutation", "expected_failure"),
    [
        ({"expires_at": 1200}, "b132:manifest_expired"),
        ({"issued_at": 1600}, "b132:manifest_not_yet_valid"),
        ({"sequence": 0}, "b132:manifest_sequence_invalid"),
        ({"target_version": "v0.13.0"}, "b132:target_version_not_newer"),
        ({"min_source_version": "v0.14.0"}, "b132:source_version_outside_pinned_range"),
        ({"artifact_name": "../evil.zip"}, "b132:manifest_artifact_name_invalid"),
    ],
)
def test_manifest_policy_fails_closed(mutation, expected_failure):
    private, root = _keypair()
    payload = b"policy fixture"
    manifest = _signed_manifest(
        private,
        root,
        update_type=b132.APPLICATION,
        target_version="v0.13.1",
        sequence=1,
        artifact_name="update.zip",
        artifact_bytes=payload,
    )
    manifest.update(mutation)
    manifest["signature_b64"] = base64.b64encode(
        private.sign(b132.manifest_signing_bytes(manifest))
    ).decode("ascii")
    state = b132.initial_state(update_type=b132.APPLICATION, current_version="v0.13.0")

    report = b132.verify_manifest(manifest, trusted_root=root, state=state, now=1500)

    assert report["passed"] is False
    assert expected_failure in report["failures"]


def test_sequence_replay_is_rejected():
    private, root = _keypair()
    payload = b"sequence"
    manifest = _signed_manifest(
        private,
        root,
        update_type=b132.APPLICATION,
        target_version="v0.13.2",
        sequence=2,
        artifact_name="update.zip",
        artifact_bytes=payload,
    )
    state = b132.UpdateState(
        update_type=b132.APPLICATION,
        current_version="v0.13.1",
        highest_sequence=2,
        current_sha256="1" * 64,
    )

    report = b132.verify_manifest(manifest, trusted_root=root, state=state, now=1500)

    assert report["passed"] is False
    assert "b132:sequence_replay_or_rollback" in report["failures"]


def test_wrong_pinned_key_is_rejected():
    private, root = _keypair()
    _, wrong_root = _keypair()
    payload = b"wrong root"
    manifest = _signed_manifest(
        private,
        root,
        update_type=b132.APPLICATION,
        target_version="v0.13.1",
        sequence=1,
        artifact_name="update.zip",
        artifact_bytes=payload,
    )
    state = b132.initial_state(update_type=b132.APPLICATION, current_version="v0.13.0")

    report = b132.verify_manifest(manifest, trusted_root=wrong_root, state=state, now=1500)

    assert report["passed"] is False
    assert "b132:manifest_untrusted_key" in report["failures"]


def test_payload_hash_and_size_are_both_required(tmp_path: Path):
    path = tmp_path / "update.zip"
    path.write_bytes(b"expected")
    manifest = {
        "artifact_bytes": len(b"expected"),
        "artifact_sha256": hashlib.sha256(b"expected").hexdigest(),
    }

    good = b132.verify_payload(path, manifest)
    assert good["passed"] is True

    path.write_bytes(b"tampered")
    bad = b132.verify_payload(path, manifest)
    assert bad["passed"] is False
    assert "b132:payload_sha256_mismatch" in bad["failures"]


def test_verified_application_payload_stages_without_execution(tmp_path: Path):
    private, root = _keypair()
    payload = b"controlled staged application"
    source = tmp_path / "app.zip"
    source.write_bytes(payload)
    manifest = _signed_manifest(
        private,
        root,
        update_type=b132.APPLICATION,
        target_version="v0.13.1",
        sequence=1,
        artifact_name="app.zip",
        artifact_bytes=payload,
        min_source_version="v0.13.0",
        max_source_version="v0.13.0",
    )
    state = b132.initial_state(update_type=b132.APPLICATION, current_version="v0.13.0")
    staging = tmp_path / "staging"

    report = b132.stage_verified_payload(
        source,
        staging_root=staging,
        manifest=manifest,
        trusted_root=root,
        state=state,
        now=1500,
    )

    assert report["passed"] is True
    assert report["execution_available"] is False
    staged = Path(report["staged_path"])
    assert staged.is_file()
    assert staged.read_bytes() == payload
    assert b132.sha256_file(staged) == manifest["artifact_sha256"]


def _rule_bundle_bytes(version: str = "v1.0.1", disposition: str = "DETECT_ONLY") -> bytes:
    payload = {
        "schema": b132.RULE_BUNDLE_SCHEMA,
        "bundle_version": version,
        "rules": [
            {
                "rule_id": "BCS.HASH.001",
                "indicator_sha256": "a" * 64,
                "severity": "HIGH",
                "disposition": disposition,
            },
            {
                "rule_id": "BCS.HASH.002",
                "indicator_sha256": "b" * 64,
                "severity": "CRITICAL",
                "disposition": "DETECT_ONLY",
            },
        ],
    }
    return (json.dumps(payload, sort_keys=True) + "\n").encode("utf-8")


def test_signed_rule_bundle_stages_and_is_detect_only(tmp_path: Path):
    private, root = _keypair()
    payload = _rule_bundle_bytes()
    source = tmp_path / "rules.json"
    source.write_bytes(payload)
    manifest = _signed_manifest(
        private,
        root,
        update_type=b132.RULE_BUNDLE,
        target_version="v1.0.1",
        sequence=1,
        artifact_name="rules.json",
        artifact_bytes=payload,
        min_source_version="v1.0.0",
        max_source_version="v1.0.0",
    )
    state = b132.initial_state(update_type=b132.RULE_BUNDLE, current_version="v1.0.0")

    report = b132.stage_verified_payload(
        source,
        staging_root=tmp_path / "rule-stage",
        manifest=manifest,
        trusted_root=root,
        state=state,
        now=1500,
    )

    assert report["passed"] is True
    assert report["rule_bundle"]["passed"] is True
    assert report["rule_bundle"]["detect_only"] is True
    assert report["rule_bundle"]["rule_count"] == 2


def test_rule_bundle_cannot_smuggle_non_detect_action(tmp_path: Path):
    private, root = _keypair()
    payload = _rule_bundle_bytes(disposition="DELETE")
    source = tmp_path / "rules.json"
    source.write_bytes(payload)
    manifest = _signed_manifest(
        private,
        root,
        update_type=b132.RULE_BUNDLE,
        target_version="v1.0.1",
        sequence=1,
        artifact_name="rules.json",
        artifact_bytes=payload,
        min_source_version="v1.0.0",
        max_source_version="v1.0.0",
    )
    state = b132.initial_state(update_type=b132.RULE_BUNDLE, current_version="v1.0.0")

    report = b132.stage_verified_payload(
        source,
        staging_root=tmp_path / "rule-stage",
        manifest=manifest,
        trusted_root=root,
        state=state,
        now=1500,
    )

    assert report["passed"] is False
    assert "b132:rule_bundle_validation_failed" in report["failures"]
    assert any("disposition_invalid" in item for item in report["failures"])


def test_state_advance_records_immediately_previous_verified_state():
    state = b132.initial_state(
        update_type=b132.APPLICATION,
        current_version="v0.13.0",
        current_sha256="1" * 64,
    )
    manifest = {
        "target_version": "v0.13.1",
        "sequence": 1,
        "artifact_sha256": "2" * 64,
    }

    next_state = b132.advance_state(state, manifest, staged_sha256="2" * 64)

    assert next_state.current_version == "v0.13.1"
    assert next_state.highest_sequence == 1
    assert next_state.current_sha256 == "2" * 64
    assert next_state.previous_version == "v0.13.0"
    assert next_state.previous_sequence == 0
    assert next_state.previous_sha256 == "1" * 64


def test_rollback_requires_previous_verified_version_and_explicit_confirmation():
    state = b132.UpdateState(
        update_type=b132.APPLICATION,
        current_version="v0.13.1",
        highest_sequence=1,
        current_sha256="2" * 64,
        previous_version="v0.13.0",
        previous_sequence=0,
        previous_sha256="1" * 64,
    )
    denied = b132.build_rollback_plan(
        state,
        requested_version="v0.13.0",
        explicit_user_confirmation=False,
    )
    assert denied["eligible"] is False
    assert "b132:rollback_explicit_confirmation_required" in denied["failures"]

    wrong = b132.build_rollback_plan(
        state,
        requested_version="v0.12.9",
        explicit_user_confirmation=True,
    )
    assert wrong["eligible"] is False
    assert "b132:rollback_only_previous_verified_version_allowed" in wrong["failures"]

    allowed = b132.build_rollback_plan(
        state,
        requested_version="v0.13.0",
        explicit_user_confirmation=True,
    )
    assert allowed["eligible"] is True
    assert allowed["rollback_execution_available_in_b132"] is False
    assert allowed["automatic_rollback"] is False


def test_private_key_network_and_execution_are_not_embedded_or_enabled():
    report = b132.self_check()
    assert report["private_key_embedded"] is False
    assert report["network_required"] is False
    assert report["cloud_required"] is False
    assert report["payload_execution_available"] is False
    assert report["installer_execution_available"] is False
    assert report["coverage_promoted"] is False
    assert report["authority_expanded"] is False

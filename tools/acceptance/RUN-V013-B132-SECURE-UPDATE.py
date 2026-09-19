from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel import beta13_secure_updates as b132


def _signed_manifest(
    private: Ed25519PrivateKey,
    root: b132.TrustedUpdateRoot,
    *,
    update_type: str,
    target_version: str,
    sequence: int,
    artifact_name: str,
    payload: bytes,
    min_source_version: str,
    max_source_version: str,
    issued_at: int = 1000,
    expires_at: int = 2000,
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
        "artifact_sha256": hashlib.sha256(payload).hexdigest(),
        "artifact_bytes": len(payload),
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


def main() -> int:
    private = Ed25519PrivateKey.generate()
    public_raw = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    root = b132.TrustedUpdateRoot(
        key_id=b132.key_id_for_public_key(public_raw),
        public_key_b64=base64.b64encode(public_raw).decode("ascii"),
    )

    with tempfile.TemporaryDirectory(prefix="bcs-b132-") as temp:
        workspace = Path(temp)
        app_payload = b"BC Sentinel B13-2 controlled application payload\n"
        app_source = workspace / "bc-sentinel-v0131.zip"
        app_source.write_bytes(app_payload)
        app_manifest = _signed_manifest(
            private,
            root,
            update_type=b132.APPLICATION,
            target_version="v0.13.1",
            sequence=1,
            artifact_name=app_source.name,
            payload=app_payload,
            min_source_version="v0.13.0",
            max_source_version="v0.13.0",
        )
        app_state = b132.initial_state(
            update_type=b132.APPLICATION,
            current_version="v0.13.0",
            current_sha256="1" * 64,
        )

        app_manifest_report = b132.verify_manifest(
            app_manifest,
            trusted_root=root,
            state=app_state,
            now=1500,
        )
        app_stage = b132.stage_verified_payload(
            app_source,
            staging_root=workspace / "app-stage",
            manifest=app_manifest,
            trusted_root=root,
            state=app_state,
            now=1500,
        )
        advanced = b132.advance_state(
            app_state,
            app_manifest,
            staged_sha256=app_manifest["artifact_sha256"],
        )
        replay = b132.verify_manifest(
            app_manifest,
            trusted_root=root,
            state=advanced,
            now=1500,
        )
        rollback = b132.build_rollback_plan(
            advanced,
            requested_version="v0.13.0",
            explicit_user_confirmation=True,
        )

        tampered = workspace / "tampered.zip"
        tampered.write_bytes(app_payload + b"tamper")
        tampered_payload = b132.verify_payload(tampered, app_manifest)

        rule_bundle = {
            "schema": b132.RULE_BUNDLE_SCHEMA,
            "bundle_version": "v1.0.1",
            "rules": [
                {
                    "rule_id": "BCS.HASH.ACCEPTANCE.001",
                    "indicator_sha256": "a" * 64,
                    "severity": "HIGH",
                    "disposition": "DETECT_ONLY",
                },
                {
                    "rule_id": "BCS.HASH.ACCEPTANCE.002",
                    "indicator_sha256": "b" * 64,
                    "severity": "CRITICAL",
                    "disposition": "DETECT_ONLY",
                },
            ],
        }
        rule_payload = (json.dumps(rule_bundle, sort_keys=True) + "\n").encode("utf-8")
        rule_source = workspace / "rules.json"
        rule_source.write_bytes(rule_payload)
        rule_manifest = _signed_manifest(
            private,
            root,
            update_type=b132.RULE_BUNDLE,
            target_version="v1.0.1",
            sequence=1,
            artifact_name=rule_source.name,
            payload=rule_payload,
            min_source_version="v1.0.0",
            max_source_version="v1.0.0",
        )
        rule_state = b132.initial_state(
            update_type=b132.RULE_BUNDLE,
            current_version="v1.0.0",
            current_sha256="2" * 64,
        )
        rule_stage = b132.stage_verified_payload(
            rule_source,
            staging_root=workspace / "rule-stage",
            manifest=rule_manifest,
            trusted_root=root,
            state=rule_state,
            now=1500,
        )

        expired_manifest = _signed_manifest(
            private,
            root,
            update_type=b132.APPLICATION,
            target_version="v0.13.2",
            sequence=2,
            artifact_name="expired.zip",
            payload=b"expired",
            min_source_version="v0.13.0",
            max_source_version="v0.13.1",
            issued_at=100,
            expires_at=200,
        )
        expired = b132.verify_manifest(
            expired_manifest,
            trusted_root=root,
            state=app_state,
            now=1500,
        )

        wrong_private = Ed25519PrivateKey.generate()
        wrong_public = wrong_private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        wrong_root = b132.TrustedUpdateRoot(
            key_id=b132.key_id_for_public_key(wrong_public),
            public_key_b64=base64.b64encode(wrong_public).decode("ascii"),
        )
        wrong_root_report = b132.verify_manifest(
            app_manifest,
            trusted_root=wrong_root,
            state=app_state,
            now=1500,
        )

        readiness = b132.projected_readiness()
        passed = (
            app_manifest_report["passed"] is True
            and app_stage["passed"] is True
            and app_stage["execution_available"] is False
            and replay["passed"] is False
            and "b132:sequence_replay_or_rollback" in replay["failures"]
            and rollback["eligible"] is True
            and rollback["rollback_execution_available_in_b132"] is False
            and tampered_payload["passed"] is False
            and rule_stage["passed"] is True
            and rule_stage["rule_bundle"]["detect_only"] is True
            and rule_stage["rule_bundle"]["rule_count"] == 2
            and expired["passed"] is False
            and "b132:manifest_expired" in expired["failures"]
            and wrong_root_report["passed"] is False
            and "b132:manifest_untrusted_key" in wrong_root_report["failures"]
            and readiness["release_blocker_count"] == 4
        )

        report = {
            "passed": passed,
            "ephemeral_private_key_persisted": False,
            "application_manifest_verified": app_manifest_report["passed"],
            "application_payload_staged": app_stage["passed"],
            "application_payload_executed": False,
            "replay_rejected": not replay["passed"],
            "tampered_payload_rejected": not tampered_payload["passed"],
            "expired_manifest_rejected": not expired["passed"],
            "wrong_root_rejected": not wrong_root_report["passed"],
            "rollback_previous_verified_only": rollback["eligible"],
            "rollback_execution_available": rollback["rollback_execution_available_in_b132"],
            "rule_bundle_staged": rule_stage["passed"],
            "rule_count": rule_stage["rule_bundle"]["rule_count"] if rule_stage["passed"] else 0,
            "rule_bundle_detect_only": rule_stage["rule_bundle"]["detect_only"] if rule_stage["passed"] else False,
            "readiness_projection": readiness,
        }
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())

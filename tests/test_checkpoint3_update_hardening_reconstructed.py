from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import sentinel.service_update as service_update
from sentinel.service_hardening import IntegrityVerifier, write_integrity_manifest
from sentinel.service_update import UpdateError, apply_update_transaction, manifest_version, rollback_transaction


def _version_manifest(root: Path, version: str) -> None:
    path = write_integrity_manifest(root)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["product_version"] = version
    path.write_text(json.dumps(data, sort_keys=True, separators=(",", ":")), encoding="utf-8")


def _make_install(root: Path, version: str, key: Path, sig: Path) -> None:
    root.mkdir(parents=True)
    (root / "BC-Sentinel-Protection.exe").write_bytes(("svc-" + version).encode())
    _version_manifest(root, version)
    assert IntegrityVerifier(root, key_path=key, signature_path=sig).seal().ok


def _make_source(root: Path, version: str) -> None:
    root.mkdir(parents=True)
    (root / "BC-Sentinel-Protection.exe").write_bytes(("svc-" + version).encode())
    (root / "BC-Sentinel-Broker.exe").write_bytes(("broker-" + version).encode())
    _version_manifest(root, version)


def _rehash_manifest_file(root: Path, rel: str) -> None:
    manifest_path = root / "protection-integrity.json"
    obj = json.loads(manifest_path.read_text(encoding="utf-8"))
    target = root / rel
    payload = target.read_bytes()
    obj["files"][rel]["sha256"] = hashlib.sha256(payload).hexdigest()
    obj["files"][rel]["size"] = len(payload)
    manifest_path.write_text(json.dumps(obj, sort_keys=True, separators=(",", ":")), encoding="utf-8")


def test_checkpoint3_rejects_overlapping_backup_and_deployment_roots(tmp_path, monkeypatch):
    key, sig = tmp_path / "key", tmp_path / "sig"
    target, source = tmp_path / "target", tmp_path / "source"
    _make_install(target, "0.9.0-beta.3", key, sig)
    _make_source(source, "0.9.0-rc.1")
    monkeypatch.setattr(service_update, "INTEGRITY_KEY_PATH", key)
    with pytest.raises(UpdateError, match="overlap"):
        apply_update_transaction(source, target, target / "Updates", current_key_path=key, current_signature_path=sig)


def test_checkpoint3_source_manifest_replacement_after_approval_is_rejected(tmp_path, monkeypatch):
    key, sig = tmp_path / "key", tmp_path / "sig"
    target, source, backups = tmp_path / "target", tmp_path / "source", tmp_path / "updates"
    _make_install(target, "0.9.0-beta.3", key, sig)
    _make_source(source, "0.9.0-rc.1")
    monkeypatch.setattr(service_update, "INTEGRITY_KEY_PATH", key)
    real_validate = service_update.validate_update_source

    def validate_then_replace(*args, **kwargs):
        plan = real_validate(*args, **kwargs)
        payload = source / "BC-Sentinel-Broker.exe"
        payload.write_bytes(b"replacement-after-approval")
        _rehash_manifest_file(source, "BC-Sentinel-Broker.exe")
        return plan

    monkeypatch.setattr(service_update, "validate_update_source", validate_then_replace)
    with pytest.raises(UpdateError, match="manifest changed after approval"):
        apply_update_transaction(source, target, backups, current_key_path=key, current_signature_path=sig)
    assert manifest_version(target) == "0.9.0-beta.3"


def test_checkpoint3_failed_promotion_restores_original_tree(tmp_path, monkeypatch):
    key, sig = tmp_path / "key", tmp_path / "sig"
    target, source, backups = tmp_path / "target", tmp_path / "source", tmp_path / "updates"
    _make_install(target, "0.9.0-beta.3", key, sig)
    _make_source(source, "0.9.0-rc.1")
    monkeypatch.setattr(service_update, "INTEGRITY_KEY_PATH", key)
    real_replace = service_update.os.replace
    fired = {"value": False}

    def fail_new_tree_promotion(src, dst):
        srcp, dstp = Path(src), Path(dst)
        if ".update-" in srcp.name and dstp == target and not fired["value"]:
            fired["value"] = True
            raise OSError("synthetic promotion failure")
        return real_replace(src, dst)

    monkeypatch.setattr(service_update.os, "replace", fail_new_tree_promotion)
    with pytest.raises(OSError, match="synthetic promotion failure"):
        apply_update_transaction(source, target, backups, current_key_path=key, current_signature_path=sig)
    assert fired["value"] is True
    assert target.is_dir()
    assert manifest_version(target) == "0.9.0-beta.3"


def test_checkpoint3_modified_and_rehashed_backup_is_not_accepted(tmp_path, monkeypatch):
    key, sig = tmp_path / "key", tmp_path / "sig"
    target, source, backups = tmp_path / "target", tmp_path / "source", tmp_path / "updates"
    _make_install(target, "0.9.0-beta.3", key, sig)
    _make_source(source, "0.9.0-rc.1")
    monkeypatch.setattr(service_update, "INTEGRITY_KEY_PATH", key)
    applied = apply_update_transaction(source, target, backups, current_key_path=key, current_signature_path=sig)
    backup = Path(applied["backup"])
    changed = backup / "BC-Sentinel-Protection.exe"
    changed.write_bytes(b"tampered-old-release")
    _rehash_manifest_file(backup, "BC-Sentinel-Protection.exe")
    with pytest.raises(UpdateError, match="backup manifest identity"):
        rollback_transaction(applied["journal"])
    assert manifest_version(target) == "0.9.0-rc.1"


def test_checkpoint3_schema2_rollback_is_idempotent(tmp_path, monkeypatch):
    key, sig = tmp_path / "key", tmp_path / "sig"
    target, source, backups = tmp_path / "target", tmp_path / "source", tmp_path / "updates"
    _make_install(target, "0.9.0-beta.3", key, sig)
    _make_source(source, "0.9.0-rc.1")
    monkeypatch.setattr(service_update, "INTEGRITY_KEY_PATH", key)
    applied = apply_update_transaction(source, target, backups, current_key_path=key, current_signature_path=sig)
    first = rollback_transaction(applied["journal"])
    second = rollback_transaction(applied["journal"])
    assert first["status"] == second["status"] == "rolled_back"
    assert manifest_version(target) == "0.9.0-beta.3"


def test_checkpoint3_legacy_schema1_journal_refused_for_automatic_rollback(tmp_path, monkeypatch):
    key, sig = tmp_path / "key", tmp_path / "sig"
    target, source, backups = tmp_path / "target", tmp_path / "source", tmp_path / "updates"
    _make_install(target, "0.9.0-beta.3", key, sig)
    _make_source(source, "0.9.0-rc.1")
    monkeypatch.setattr(service_update, "INTEGRITY_KEY_PATH", key)
    applied = apply_update_transaction(source, target, backups, current_key_path=key, current_signature_path=sig)
    journal = Path(applied["journal"])
    body = service_update.verify_signed_journal(journal)
    body.pop("hmac", None)
    body["schema"] = 1
    service_update._signed_journal_write(journal, body)
    with pytest.raises(UpdateError, match="legacy update journal"):
        rollback_transaction(journal)

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from sentinel import guided_resolution_provider_loader as provider_loader
from sentinel import home_guided_resolution as guided
from sentinel import home_quarantine as b658
from sentinel import home_quarantine_integrity as b659
from sentinel import home_threat_cards as threat


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def _profile(tmp_path: Path) -> Path:
    root = tmp_path / "User"
    for name in ("Desktop", "Documents", "Downloads"):
        (root / name).mkdir(parents=True, exist_ok=True)
    return root


def _card(path: Path, finding_id: str) -> threat.ThreatCardModel:
    digest = _sha256(path)
    severity = "HIGH"
    card = threat.ThreatCardModel(
        finding_id=finding_id,
        title="B6-5.9 quarantine integrity finding",
        severity=severity,
        severity_label=threat.SEVERITY_LABELS[severity],
        severity_role=threat.SEVERITY_ROLES[severity],
        category="fixture",
        reason="Controlled B6-5.9 integrity visibility test",
        source_check_id="files",
        location=str(path),
        confidence=None,
        confidence_label="Non disponibile",
        recommendation="Review before action.",
        advanced_details={
            "finding": {
                "finding_id": finding_id,
                "severity": severity,
                "confidence": None,
                "path": str(path),
                "evidence": {"sha256": digest},
            }
        },
    )
    card.validate()
    return card


def _quarantine(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    finding_id: str,
    filename: str = "integrity.txt",
) -> tuple[Path, Path, str, b659.HomeQuarantineController]:
    local = tmp_path / "LocalAppData"
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    profile = _profile(tmp_path)
    target = profile / "Documents" / filename
    target.write_text(f"BC Sentinel B6-5.9 {finding_id}\n", encoding="utf-8")
    original_hash = _sha256(target)
    controller = b659.HomeQuarantineController(
        provider_loader.load_default_provider(),
        user_profile=profile,
    )
    card = _card(target, finding_id)
    resolution = guided.build_guided_resolution(card)
    session = controller.prepare_confirmation(card, resolution)
    result = controller.confirm_and_execute(session)
    assert result.state == "QUARANTINED_VERIFIED"
    assert not target.exists()
    return profile, target, original_hash, controller


def _storage_snapshot(storage: Path) -> dict[str, bytes]:
    return {
        str(path.relative_to(storage)): path.read_bytes()
        for path in storage.rglob("*")
        if path.is_file()
    }


def test_b659_contract_adds_visibility_without_new_authority() -> None:
    contract = b659.validate_b659_contract()
    assert contract["passed"] is True
    assert contract["degraded_persistent_state_visible"] is True
    assert contract["integrity_audit_read_only"] is True
    assert contract["blocked_rows_have_no_restore_key"] is True
    assert contract["verified_rows_keep_explicit_restore"] is True
    assert contract["automatic_cleanup"] is False
    assert contract["general_home_execution_authorized"] is False
    assert contract["delete_authorized"] is False
    assert contract["repair_authorized"] is False


def test_verified_quarantine_keeps_normal_restore_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    finding_id = "b659-valid"
    profile, target, original_hash, _ = _quarantine(
        monkeypatch,
        tmp_path,
        finding_id=finding_id,
    )
    restarted = b659.HomeQuarantineController(
        provider_loader.load_default_provider(),
        user_profile=profile,
    )
    rows = restarted.quarantine_rows()
    assert len(rows) == 1
    assert rows[0]["integrity_state"] == b659.INTEGRITY_VERIFIED
    assert rows[0]["restore_key"] == finding_id
    assert rows[0]["action"] == "Ripristina file"
    rollback = restarted.rollback(finding_id)
    assert rollback.state == "RESTORED_VERIFIED"
    assert target.is_file()
    assert _sha256(target) == original_hash


def test_tampered_recovery_record_is_visible_but_not_actionable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    finding_id = "b659-tampered-record"
    profile, target, _, _ = _quarantine(
        monkeypatch,
        tmp_path,
        finding_id=finding_id,
    )
    storage = tmp_path / "LocalAppData" / "BCSentinel" / "B656"
    record = next((storage / "home-restore").glob("*.json"))
    payload = json.loads(record.read_text(encoding="utf-8"))
    payload["display"]["reason"] = "tampered"
    record.write_text(json.dumps(payload), encoding="utf-8")
    before = _storage_snapshot(storage)

    restarted = b659.HomeQuarantineController(
        provider_loader.load_default_provider(),
        user_profile=profile,
    )
    rows = restarted.quarantine_rows()
    after = _storage_snapshot(storage)

    assert after == before
    assert restarted.has_active_quarantine(finding_id) is False
    assert len(rows) == 1
    assert rows[0]["integrity_state"] == b659.INTEGRITY_BLOCKED
    assert rows[0]["integrity_issue_code"] == "record_integrity"
    assert rows[0]["status"] == "Verifica richiesta"
    assert rows[0]["action"] == "Ripristino bloccato"
    assert rows[0]["restore_key"] == ""
    with pytest.raises(ValueError, match="b658_no_verified_persistent_quarantine"):
        restarted.rollback(finding_id)
    assert not target.exists()


def test_missing_snapshot_is_visible_and_restore_remains_blocked(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    finding_id = "b659-missing-snapshot"
    profile, target, _, _ = _quarantine(
        monkeypatch,
        tmp_path,
        finding_id=finding_id,
    )
    storage = tmp_path / "LocalAppData" / "BCSentinel" / "B656"
    record = next((storage / "home-restore").glob("*.json"))
    payload = json.loads(record.read_text(encoding="utf-8"))
    snapshot = Path(payload["result"]["snapshot_path"])
    snapshot.unlink()

    restarted = b659.HomeQuarantineController(
        provider_loader.load_default_provider(),
        user_profile=profile,
    )
    rows = restarted.quarantine_rows()
    assert len(rows) == 1
    assert rows[0]["integrity_state"] == b659.INTEGRITY_BLOCKED
    assert rows[0]["integrity_issue_code"] == "artifact_missing"
    assert rows[0]["restore_key"] == ""
    with pytest.raises(ValueError, match="b658_no_verified_persistent_quarantine"):
        restarted.rollback(finding_id)
    assert not target.exists()


def test_original_target_collision_is_visible_and_never_overwritten(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    finding_id = "b659-target-collision"
    profile, target, original_hash, _ = _quarantine(
        monkeypatch,
        tmp_path,
        finding_id=finding_id,
    )
    target.write_text("do not overwrite this collision", encoding="utf-8")
    collision_hash = _sha256(target)
    assert collision_hash != original_hash

    restarted = b659.HomeQuarantineController(
        provider_loader.load_default_provider(),
        user_profile=profile,
    )
    rows = restarted.quarantine_rows()
    assert len(rows) == 1
    assert rows[0]["integrity_state"] == b659.INTEGRITY_BLOCKED
    assert rows[0]["integrity_issue_code"] == "target_collision"
    assert rows[0]["restore_key"] == ""
    with pytest.raises(ValueError, match="b658_no_verified_persistent_quarantine"):
        restarted.rollback(finding_id)
    assert target.read_text(encoding="utf-8") == "do not overwrite this collision"


def test_integrity_audit_does_not_create_storage(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    local = tmp_path / "LocalAppData"
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    profile = _profile(tmp_path)
    controller = b659.HomeQuarantineController(
        provider_loader.load_default_provider(),
        user_profile=profile,
    )
    assert controller.quarantine_rows() == []
    assert controller.integrity_issues() == []
    assert not (local / "BCSentinel" / "B656").exists()
    summary = b659.integrity_summary()
    assert summary["read_only"] is True
    assert summary["issue_count"] == 0

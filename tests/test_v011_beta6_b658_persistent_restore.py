from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from sentinel import guided_resolution_provider_loader as provider_loader
from sentinel import home_guided_resolution as guided
from sentinel import home_quarantine as b658
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


def _card(path: Path, finding_id: str = "b658-fixture-finding") -> threat.ThreatCardModel:
    digest = _sha256(path)
    severity = "HIGH"
    card = threat.ThreatCardModel(
        finding_id=finding_id,
        title="B6-5.8 persistent restore finding",
        severity=severity,
        severity_label=threat.SEVERITY_LABELS[severity],
        severity_role=threat.SEVERITY_ROLES[severity],
        category="fixture",
        reason="Controlled B6-5.8 restart-safe restore test",
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
    finding_id: str = "b658-fixture-finding",
) -> tuple[Path, Path, str]:
    local = tmp_path / "LocalAppData"
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    profile = _profile(tmp_path)
    target = profile / "Documents" / "persistent.txt"
    target.write_text("BC Sentinel B6-5.8 persistent restore\n", encoding="utf-8")
    original_hash = _sha256(target)

    controller = b658.HomeQuarantineController(
        provider_loader.load_default_provider(),
        user_profile=profile,
    )
    card = _card(target, finding_id)
    resolution = guided.build_guided_resolution(card)
    session = controller.prepare_confirmation(card, resolution)
    result = controller.confirm_and_execute(session)
    assert result.state == "QUARANTINED_VERIFIED"
    assert not target.exists()
    return profile, target, original_hash


def test_b658_contract_opens_only_restart_safe_restore() -> None:
    contract = b658.validate_b658_contract()
    assert contract["passed"] is True
    assert contract["persistent_restore_after_restart"] is True
    assert contract["restart_discovery_read_only"] is True
    assert contract["recovery_metadata_written_before_move"] is True
    assert contract["journal_anchor_required"] is True
    assert contract["quarantine_page_restore_action_available"] is True
    assert contract["general_home_execution_authorized"] is False
    assert contract["automatic_quarantine"] is False
    assert contract["delete_authorized"] is False
    assert contract["repair_authorized"] is False


def test_restart_reconstructs_quarantine_and_restores_identical_sha256(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    finding_id = "b658-restart-restore"
    profile, target, original_hash = _quarantine(
        monkeypatch,
        tmp_path,
        finding_id=finding_id,
    )

    # Fresh controller: no session-bound _active object survives.
    restarted = b658.HomeQuarantineController(
        provider_loader.load_default_provider(),
        user_profile=profile,
    )
    assert restarted.has_active_quarantine(finding_id) is True
    rows = restarted.quarantine_rows()
    assert len(rows) == 1
    assert rows[0]["restore_key"] == finding_id
    assert rows[0]["action"] == "Ripristina file"

    rollback = restarted.rollback(finding_id)
    assert rollback.state == "RESTORED_VERIFIED"
    assert target.is_file()
    assert _sha256(target) == original_hash
    assert restarted.has_active_quarantine(finding_id) is False
    assert restarted.quarantine_rows() == []


def test_restart_discovery_is_read_only(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    finding_id = "b658-read-only-restart"
    profile, _, _ = _quarantine(monkeypatch, tmp_path, finding_id=finding_id)

    storage = tmp_path / "LocalAppData" / "BCSentinel" / "B656"
    before = {
        str(path.relative_to(storage)): path.read_bytes()
        for path in storage.rglob("*")
        if path.is_file()
    }

    restarted = b658.HomeQuarantineController(
        provider_loader.load_default_provider(),
        user_profile=profile,
    )
    assert restarted.has_active_quarantine(finding_id) is True
    assert len(restarted.quarantine_rows()) == 1

    after = {
        str(path.relative_to(storage)): path.read_bytes()
        for path in storage.rglob("*")
        if path.is_file()
    }
    assert after == before


def test_tampered_recovery_record_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    finding_id = "b658-tamper-record"
    profile, target, _ = _quarantine(monkeypatch, tmp_path, finding_id=finding_id)

    recovery_root = tmp_path / "LocalAppData" / "BCSentinel" / "B656" / "home-restore"
    record = next(recovery_root.glob("*.json"))
    payload = json.loads(record.read_text(encoding="utf-8"))
    payload["display"]["reason"] = "tampered"
    # Deliberately keep the original record_sha256.
    record.write_text(json.dumps(payload), encoding="utf-8")

    restarted = b658.HomeQuarantineController(
        provider_loader.load_default_provider(),
        user_profile=profile,
    )
    assert restarted.has_active_quarantine(finding_id) is False
    assert restarted.quarantine_rows() == []
    with pytest.raises(ValueError, match="b658_no_verified_persistent_quarantine"):
        restarted.rollback(finding_id)
    assert not target.exists()


def test_restart_restore_refuses_existing_target_collision(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    finding_id = "b658-target-collision"
    profile, target, original_hash = _quarantine(
        monkeypatch,
        tmp_path,
        finding_id=finding_id,
    )
    target.write_text("collision must never be overwritten", encoding="utf-8")
    collision_hash = _sha256(target)
    assert collision_hash != original_hash

    restarted = b658.HomeQuarantineController(
        provider_loader.load_default_provider(),
        user_profile=profile,
    )
    # Discovery itself fails closed because the original location is occupied.
    assert restarted.has_active_quarantine(finding_id) is False
    with pytest.raises(ValueError, match="b658_no_verified_persistent_quarantine"):
        restarted.rollback(finding_id)
    assert target.read_text(encoding="utf-8") == "collision must never be overwritten"

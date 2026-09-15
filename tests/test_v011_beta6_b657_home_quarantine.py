from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from sentinel import guided_resolution_provider_loader as provider_loader
from sentinel import home_guided_resolution as guided
from sentinel import home_quarantine as b657
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


def _card(path: Path, severity: str = "HIGH") -> threat.ThreatCardModel:
    digest = _sha256(path)
    card = threat.ThreatCardModel(
        finding_id="b657-fixture-finding",
        title="B6-5.7 controlled finding",
        severity=severity,
        severity_label=threat.SEVERITY_LABELS[severity],
        severity_role=threat.SEVERITY_ROLES[severity],
        category="fixture",
        reason="Controlled B6-5.7 test finding",
        source_check_id="files",
        location=str(path),
        confidence=None,
        confidence_label="Non disponibile",
        recommendation="Review the finding.",
        advanced_details={
            "finding": {
                "finding_id": "b657-fixture-finding",
                "severity": severity,
                "confidence": None,
                "path": str(path),
                "evidence": {"sha256": digest},
            }
        },
    )
    card.validate()
    return card


def test_b657_contract_keeps_general_home_authority_closed() -> None:
    contract = b657.validate_b657_contract()
    assert contract["passed"] is True
    assert contract["home_quarantine_action_available"] is True
    assert contract["explicit_user_click_required"] is True
    assert contract["second_confirmation_required"] is True
    assert contract["lazy_execution_provider"] is True
    assert contract["general_home_execution_authorized"] is False
    assert contract["automatic_quarantine"] is False
    assert contract["delete_authorized"] is False
    assert contract["repair_authorized"] is False


def test_low_severity_is_not_eligible_for_home_quarantine(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    local = tmp_path / "LocalAppData"
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    profile = _profile(tmp_path)
    target = profile / "Documents" / "low.txt"
    target.write_text("safe", encoding="utf-8")
    controller = b657.HomeQuarantineController(provider_loader.load_default_provider(), user_profile=profile)
    card = _card(target, severity="LOW")
    availability = controller.assess(card, guided.build_guided_resolution(card))
    assert availability.ready is False
    assert availability.state == "BLOCKED"


def test_prepare_confirmation_is_read_only_and_lazy(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    local = tmp_path / "LocalAppData"
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    profile = _profile(tmp_path)
    target = profile / "Documents" / "sample.txt"
    target.write_text("controlled b657", encoding="utf-8")
    original_hash = _sha256(target)
    controller = b657.HomeQuarantineController(provider_loader.load_default_provider(), user_profile=profile)
    card = _card(target)
    resolution = guided.build_guided_resolution(card)

    availability = controller.assess(card, resolution)
    assert availability.ready is True
    session = controller.prepare_confirmation(card, resolution)

    assert target.is_file()
    assert _sha256(target) == original_hash
    assert not (local / "BCSentinel" / "B656").exists()
    assert session.request.explicit_decision_required is True
    assert session.request.execution_authorized is False


def test_confirmed_home_quarantine_and_session_rollback(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    local = tmp_path / "LocalAppData"
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    profile = _profile(tmp_path)
    target = profile / "Documents" / "sample.txt"
    target.write_text("controlled b657 execution", encoding="utf-8")
    original_hash = _sha256(target)

    controller = b657.HomeQuarantineController(provider_loader.load_default_provider(), user_profile=profile)
    card = _card(target)
    resolution = guided.build_guided_resolution(card)
    session = controller.prepare_confirmation(card, resolution)
    result = controller.confirm_and_execute(session)

    assert result.state == "QUARANTINED_VERIFIED"
    assert not target.exists()
    assert controller.has_active_quarantine(card.finding_id) is True
    rows = controller.quarantine_rows()
    assert len(rows) == 1
    assert rows[0]["status"] == "In quarantena"

    rollback = controller.rollback(card.finding_id)
    assert rollback.state == "RESTORED_VERIFIED"
    assert target.is_file()
    assert _sha256(target) == original_hash
    assert controller.has_active_quarantine(card.finding_id) is False
    assert controller.quarantine_rows() == []

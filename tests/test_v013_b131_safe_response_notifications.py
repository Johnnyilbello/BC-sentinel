from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from sentinel import beta12_product_integration as b128
from sentinel import beta13_response_ui as ui
from sentinel import beta13_safe_response as b131
from sentinel import guided_resolution_provider_loader as provider_loader
from sentinel import home_guided_resolution as guided
from sentinel import home_quarantine
from sentinel import home_threat_cards as threat


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def _profile(tmp_path: Path) -> Path:
    root = tmp_path / "User"
    for name in ("Desktop", "Documents", "Downloads"):
        (root / name).mkdir(parents=True, exist_ok=True)
    return root


def _card(path: Path, *, finding_id: str = "b131-finding", severity: str = "HIGH", confidence=0.97):
    digest = _sha256(path)
    card = threat.ThreatCardModel(
        finding_id=finding_id,
        title="B13-1 controlled finding",
        severity=severity,
        severity_label=threat.SEVERITY_LABELS[severity],
        severity_role=threat.SEVERITY_ROLES[severity],
        category="fixture",
        reason="Controlled B13-1 response fixture",
        source_check_id="files",
        location=str(path),
        confidence=confidence,
        confidence_label="97%" if confidence is not None else "Non disponibile",
        recommendation="Review the controlled finding.",
        advanced_details={
            "finding": {
                "finding_id": finding_id,
                "severity": severity,
                "confidence": confidence,
                "path": str(path),
                "evidence": {"sha256": digest},
            }
        },
    )
    card.validate()
    return card


def _controller(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    local = tmp_path / "LocalAppData"
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    profile = _profile(tmp_path)
    return (
        profile,
        home_quarantine.HomeQuarantineController(
            provider_loader.load_default_provider(),
            user_profile=profile,
        ),
    )


def test_self_check_binds_exact_b130_checkpoint_and_reduces_blockers():
    report = b131.self_check()
    assert report["passed"] is True
    assert report["source_checkpoint"] == "checkpoint/v013-b130-pass"
    assert report["source_checkpoint_commit"] == "6c1a3dedd48d2b26b716c199f74ea45d827ee01a"
    projection = report["readiness_projection"]
    assert projection["pillar_counts"] == {"READY": 5, "PARTIAL": 1, "BLOCKED": 4}
    assert projection["release_blocker_count"] == 5
    assert projection["release_blockers"] == [
        "SECURE_UPDATES",
        "INSTALLER_LIFECYCLE",
        "CODE_SIGNING",
        "LICENSING_TRIAL",
        "PRIVACY_SUPPORT",
    ]


def test_low_severity_is_notification_only(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    profile, controller = _controller(monkeypatch, tmp_path)
    target = profile / "Documents" / "medium.txt"
    target.write_text("medium", encoding="utf-8")
    card = _card(target, severity="MEDIUM", confidence=0.6)
    resolution = guided.build_guided_resolution(card)

    plan = b131.plan_response(card, resolution, controller)

    assert plan.state == b131.STATE_NOTIFY_ONLY
    assert plan.recommended_action == b131.ACTION_NONE
    assert plan.quarantine_ready is False
    assert target.is_file()


def test_high_eligible_finding_requires_explicit_confirmation(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    profile, controller = _controller(monkeypatch, tmp_path)
    target = profile / "Documents" / "high.txt"
    target.write_text("controlled high response", encoding="utf-8")
    original_hash = _sha256(target)
    card = _card(target)
    resolution = guided.build_guided_resolution(card)

    plan = b131.plan_response(card, resolution, controller)

    assert plan.state == b131.STATE_ACTION_REQUIRED
    assert plan.recommended_action == b131.ACTION_QUARANTINE
    assert plan.explicit_user_confirmation_required is True
    assert plan.reversible is True
    assert plan.target_sha256 == original_hash
    assert target.is_file()

    with pytest.raises(PermissionError, match="explicit_user_confirmation_required"):
        b131.execute_reversible_quarantine(
            plan=plan,
            card=card,
            resolution=resolution,
            controller=controller,
            user_confirmed=False,
        )

    assert target.is_file()
    assert _sha256(target) == original_hash


def test_confirmed_quarantine_and_restore_are_verified_and_reversible(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    profile, controller = _controller(monkeypatch, tmp_path)
    target = profile / "Downloads" / "quarantine.txt"
    target.write_text("controlled reversible response", encoding="utf-8")
    original_hash = _sha256(target)
    card = _card(target, finding_id="b131-reversible")
    resolution = guided.build_guided_resolution(card)
    plan = b131.plan_response(card, resolution, controller)

    result = b131.execute_reversible_quarantine(
        plan=plan,
        card=card,
        resolution=resolution,
        controller=controller,
        user_confirmed=True,
    )
    assert result.state == "QUARANTINED_VERIFIED"
    assert not target.exists()
    assert controller.has_active_quarantine(card.finding_id) is True

    with pytest.raises(PermissionError, match="explicit_restore_confirmation_required"):
        b131.restore_quarantined(
            controller=controller,
            finding_id=card.finding_id,
            user_confirmed=False,
        )
    assert not target.exists()

    restored = b131.restore_quarantined(
        controller=controller,
        finding_id=card.finding_id,
        user_confirmed=True,
    )
    assert restored.state == "RESTORED_VERIFIED"
    assert target.is_file()
    assert _sha256(target) == original_hash


def test_high_finding_outside_safe_quarantine_boundary_requires_review(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    profile, controller = _controller(monkeypatch, tmp_path)
    target = profile / "AppData" / "unsafe.txt"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("outside eligible roots", encoding="utf-8")
    card = _card(target, finding_id="b131-review")
    resolution = guided.build_guided_resolution(card)

    plan = b131.plan_response(card, resolution, controller)

    assert plan.state == b131.STATE_REVIEW_REQUIRED
    assert plan.recommended_action == b131.ACTION_REVIEW
    assert plan.quarantine_ready is False
    assert target.is_file()


def test_notification_contains_no_raw_path_or_command_line(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    profile, controller = _controller(monkeypatch, tmp_path)
    target = profile / "Documents" / "private-name.txt"
    target.write_text("private fixture", encoding="utf-8")
    card = _card(target)
    plan = b131.plan_response(card, guided.build_guided_resolution(card), controller)
    notice = b131.notification_from_plan(plan, now=123.0)
    payload = json.dumps(notice.__dict__, sort_keys=True)

    assert str(target) not in payload
    assert "command_line" not in payload
    assert notice.response_state == b131.STATE_ACTION_REQUIRED
    assert notice.recommended_action == b131.ACTION_QUARANTINE


def test_notification_center_persists_privacy_minimal_deduped_state(tmp_path: Path):
    store = tmp_path / "notifications.json"
    plan = b131.SafeResponsePlan(
        "b131-dedupe",
        "Controlled alert",
        "HIGH",
        0.9,
        b131.STATE_ACTION_REQUIRED,
        b131.ACTION_QUARANTINE,
        "Reversible.",
        True,
        True,
        True,
        "a" * 64,
    )
    notice = b131.notification_from_plan(plan, now=10.0)

    center = b131.NotificationCenter(store)
    center.publish(notice)
    center.publish(notice)

    assert len(center.items()) == 1
    assert center.unread_count() == 1
    raw = store.read_text(encoding="utf-8")
    assert "raw_path" not in raw
    assert "command_line" not in raw
    assert "file_content" not in raw

    restarted = b131.NotificationCenter(store)
    assert len(restarted.items()) == 1
    restarted.mark_read(notice.notification_id)
    assert restarted.unread_count() == 0


class _FakeTray:
    def __init__(self) -> None:
        self.shown = False
        self.messages: list[tuple] = []

    def show(self) -> None:
        self.shown = True

    def showMessage(self, *args) -> None:
        self.messages.append(args)


def test_tray_adapter_surfaces_sanitized_local_notification():
    plan = b131.SafeResponsePlan(
        "b131-tray",
        "Tray alert",
        "CRITICAL",
        0.99,
        b131.STATE_ACTION_REQUIRED,
        b131.ACTION_QUARANTINE,
        "Reversible.",
        True,
        True,
        True,
        "b" * 64,
    )
    notice = b131.notification_from_plan(plan, now=20.0)
    fake = _FakeTray()
    adapter = ui.TrayNotificationAdapter(fake)

    result = adapter.show(notice)

    assert result["available"] is True
    assert result["shown"] is True
    assert result["raw_path_exposed"] is False
    assert result["command_line_exposed"] is False
    assert fake.shown is True
    assert len(fake.messages) == 1


def test_response_center_ui_is_responsive_and_non_destructive():
    snapshot = b128.build_product_snapshot()
    assert snapshot["passed"] is True

    report = ui.smoke_test_window(snapshot)

    assert report["passed"] is True
    assert report["page_count"] == 8
    assert report["alerts_selected"] is True
    assert report["alert_card_count"] == 3
    assert report["review_button_count"] == 3
    assert report["unread_count"] == 3
    assert report["nav_enabled"] is True
    assert report["automatic_quarantine"] is False
    assert report["destructive_ui_action"] is False
    assert all(value == 0 for value in report["horizontal_overflow"].values())


def test_b131_does_not_expand_automatic_or_process_authority():
    report = b131.self_check()
    assert report["automatic_quarantine"] is False
    assert report["automatic_repair"] is False
    assert report["terminate_process_authority"] is False
    assert report["coverage_promoted"] is False
    assert report["authority_expanded"] is False
    assert report["network_required"] is False
    assert report["cloud_required"] is False


def test_plan_binding_prevents_wrong_finding_execution(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    profile, controller = _controller(monkeypatch, tmp_path)
    target_a = profile / "Documents" / "a.txt"
    target_b = profile / "Documents" / "b.txt"
    target_a.write_text("a", encoding="utf-8")
    target_b.write_text("b", encoding="utf-8")
    card_a = _card(target_a, finding_id="b131-a")
    card_b = _card(target_b, finding_id="b131-b")
    resolution_a = guided.build_guided_resolution(card_a)
    resolution_b = guided.build_guided_resolution(card_b)
    plan_a = b131.plan_response(card_a, resolution_a, controller)

    with pytest.raises(ValueError, match="plan_finding_binding_mismatch"):
        b131.execute_reversible_quarantine(
            plan=plan_a,
            card=card_b,
            resolution=resolution_b,
            controller=controller,
            user_confirmed=True,
        )
    assert target_a.is_file()
    assert target_b.is_file()

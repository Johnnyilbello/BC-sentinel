from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("BC_SENTINEL_REDUCED_MOTION", "1")

from PySide6.QtWidgets import QApplication, QSizePolicy, QWidget

from sentinel import home_security_model as model
from sentinel import home_security_ui as ui


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


def _evidence(
    *,
    malware: str = model.STATUS_ENGINE_AVAILABLE,
    behavior: str = model.STATUS_ENGINE_AVAILABLE,
    web: str = model.STATUS_ENGINE_AVAILABLE,
    recovery: str = model.STATUS_READY,
    verified_runtime: bool = False,
) -> dict:
    def item(layer_id: str, status: str, verified: bool) -> model.LayerEvidence:
        return model.LayerEvidence(
            layer_id=layer_id,
            status=status,
            runtime_verified=verified,
            summary=f"fixture:{layer_id}:{status}",
            raw={"fixture": True, "status": status},
            provenance="b62_test_fixture",
        )

    return {
        model.LAYER_MALWARE: item(model.LAYER_MALWARE, malware, verified_runtime),
        model.LAYER_BEHAVIOR: item(model.LAYER_BEHAVIOR, behavior, verified_runtime),
        model.LAYER_WEB: item(model.LAYER_WEB, web, verified_runtime),
        model.LAYER_RECOVERY: item(model.LAYER_RECOVERY, recovery, recovery == model.STATUS_READY),
    }


def test_profile_schema_and_parent_safety_contract() -> None:
    assert model.PROFILE == "v0.11.0-beta.6-b62"
    assert model.SCHEMA == "bc-sentinel-beta6-home-security-overview-v1"
    contract = model.validate_b62_safety_contract()
    assert contract["passed"] is True
    assert contract["startup_scan_dispatch"] is False
    assert contract["startup_rescue_dispatch"] is False
    assert contract["automatic_repair"] is False
    assert contract["automatic_quarantine"] is False
    assert contract["destructive_authority_added"] is False
    assert contract["smart_scan_enabled"] is False


def test_active_status_requires_explicit_runtime_verification() -> None:
    with pytest.raises(ValueError, match="active_requires_runtime_verification"):
        model.LayerEvidence(
            layer_id=model.LAYER_MALWARE,
            status=model.STATUS_ACTIVE,
            runtime_verified=False,
            summary="invalid optimistic fixture",
        ).validate()


def test_source_availability_alone_never_becomes_protected() -> None:
    snapshot = model.build_snapshot()
    assert snapshot.posture != model.POSTURE_PROTECTED
    assert snapshot.posture == model.POSTURE_UNVERIFIED
    runtime_cards = [card for card in snapshot.cards if card.card_id in model.REQUIRED_RUNTIME_LAYERS]
    assert runtime_cards
    assert all(card.status != model.STATUS_ACTIVE for card in runtime_cards)
    assert all(card.runtime_verified is False for card in runtime_cards)


def test_unverified_fixture_stays_neutral_even_when_all_engines_exist() -> None:
    snapshot = model.build_snapshot(lambda: _evidence())
    assert snapshot.posture == model.POSTURE_UNVERIFIED
    assert snapshot.posture_label == "Status not fully verified"
    assert "not fully verified" in snapshot.headline.lower()


def test_explicit_verified_active_fixture_can_be_protected() -> None:
    snapshot = model.build_snapshot(
        lambda: _evidence(
            malware=model.STATUS_ACTIVE,
            behavior=model.STATUS_ACTIVE,
            web=model.STATUS_ACTIVE,
            verified_runtime=True,
        )
    )
    assert snapshot.posture == model.POSTURE_PROTECTED
    assert snapshot.posture_label == "Protection verified"
    for card in snapshot.cards:
        if card.card_id in model.REQUIRED_RUNTIME_LAYERS:
            assert card.status == model.STATUS_ACTIVE
            assert card.runtime_verified is True


def test_verified_off_or_attention_forces_attention_posture() -> None:
    snapshot = model.build_snapshot(
        lambda: _evidence(
            malware=model.STATUS_ACTIVE,
            behavior=model.STATUS_OFF,
            web=model.STATUS_ACTIVE,
            verified_runtime=True,
        )
    )
    assert snapshot.posture == model.POSTURE_ATTENTION
    assert snapshot.posture_label == "Attention needed"


def test_missing_required_runtime_proof_prevents_positive_posture() -> None:
    payload = _evidence(
        malware=model.STATUS_ACTIVE,
        behavior=model.STATUS_ACTIVE,
        web=model.STATUS_ACTIVE,
        verified_runtime=True,
    )
    payload[model.LAYER_WEB] = model.LayerEvidence(
        layer_id=model.LAYER_WEB,
        status=model.STATUS_UNAVAILABLE,
        runtime_verified=False,
        summary="missing live web proof",
        raw={"reason": "fixture_missing"},
        provenance="test",
    )
    snapshot = model.build_snapshot(lambda: payload)
    assert snapshot.posture == model.POSTURE_UNVERIFIED


def test_advanced_details_preserve_raw_evidence_and_provenance() -> None:
    payload = _evidence()
    payload[model.LAYER_MALWARE] = model.LayerEvidence(
        layer_id=model.LAYER_MALWARE,
        status=model.STATUS_ENGINE_AVAILABLE,
        runtime_verified=False,
        summary="engine present",
        raw={"deep": {"hash": "ABC", "source": "fixture"}},
        provenance="unit_test_probe",
    )
    snapshot = model.build_snapshot(lambda: payload)
    card = next(card for card in snapshot.cards if card.card_id == model.LAYER_MALWARE)
    assert card.advanced_details["raw_evidence"] == {"deep": {"hash": "ABC", "source": "fixture"}}
    assert card.advanced_details["provenance"] == "unit_test_probe"
    assert card.provenance == "unit_test_probe"


def test_smart_scan_is_visible_in_model_but_disabled_until_b63() -> None:
    snapshot = model.build_snapshot(lambda: _evidence())
    assert snapshot.smart_scan_enabled is False
    assert "B6-3" in snapshot.smart_scan_label


def test_only_recovery_action_is_enabled_in_b62() -> None:
    snapshot = model.build_snapshot(lambda: _evidence())
    cards = {card.card_id: card for card in snapshot.cards}
    assert cards[model.LAYER_RECOVERY].action_enabled is True
    assert cards[model.LAYER_RECOVERY].action_label == "Open System & Recovery"
    for layer_id in model.REQUIRED_RUNTIME_LAYERS:
        assert cards[layer_id].action_enabled is False


def test_window_startup_is_passive_and_smart_scan_is_disabled() -> None:
    calls: list[str] = []

    def provider() -> dict:
        calls.append("status")
        return _evidence()

    _app()
    window = ui.SecurityOverviewWindow(status_provider=provider)
    try:
        assert calls == ["status"]
        assert window.windowTitle() == ui.WINDOW_TITLE
        assert window.smart_scan_button.isEnabled() is False
        assert window.full_scan_button.isEnabled() is False
        assert len(window.card_widgets) == 4
        assert window.recovery_window is None
    finally:
        window.close()


def test_unverified_cards_use_neutral_visual_role_not_positive() -> None:
    _app()
    window = ui.SecurityOverviewWindow(status_provider=lambda: _evidence())
    try:
        for layer_id in model.REQUIRED_RUNTIME_LAYERS:
            card = window.card_widgets[layer_id]
            assert card.property("statusRole") == "neutral"
            assert card.runtime_switch.on is False
        assert window.hero.property("posture") == model.POSTURE_UNVERIFIED
    finally:
        window.close()


def test_recovery_navigation_opens_b61_without_discovery(monkeypatch: pytest.MonkeyPatch) -> None:
    from sentinel import rescue_home_ui_model as b61_model

    invoked: list[str] = []

    def forbidden(*args, **kwargs):
        invoked.append("discover")
        raise AssertionError("B6-1 discovery dispatched while opening System & Recovery")

    monkeypatch.setattr(b61_model, "run_operator_discovery", forbidden)
    app = _app()
    window = ui.SecurityOverviewWindow(status_provider=lambda: _evidence())
    try:
        recovery = window.card_widgets[model.LAYER_RECOVERY]
        assert recovery.action_button.isEnabled() is True
        recovery.action_button.click()
        app.processEvents()
        assert invoked == []
        assert window.recovery_window is not None
        assert window.recovery_window.ui_state.state == "IDLE"
        assert window.recovery_window.discovery_view is None
    finally:
        if window.recovery_window is not None:
            window.recovery_window.close()
        window.close()


def test_refresh_is_passive_status_refresh_only() -> None:
    calls: list[str] = []

    def provider() -> dict:
        calls.append("status")
        return _evidence()

    app = _app()
    window = ui.SecurityOverviewWindow(status_provider=provider)
    try:
        assert calls == ["status"]
        window.refresh_button.click()
        app.processEvents()
        assert calls == ["status", "status"]
        assert window.smart_scan_button.isEnabled() is False
        assert window.recovery_window is None
    finally:
        window.close()


def test_visual_tokens_match_stitch_sentinel_elite_contract() -> None:
    assert ui.SPACING_TOKENS == {
        "xs": 4,
        "sm": 8,
        "md": 16,
        "lg": 24,
        "xl": 32,
        "xxl": 48,
    }
    assert 120 <= ui.MOTION_TOKENS["micro"] <= 160
    assert 180 <= ui.MOTION_TOKENS["state"] <= 220
    assert 220 <= ui.MOTION_TOKENS["panel"] <= 280
    assert ui.MOTION_TOKENS["page"] <= 320
    assert ui.COLOR_TOKENS["canvas"].lower() == "#0f1412"
    assert ui.COLOR_TOKENS["accent"].lower() == "#10b981"
    assert ui.COLOR_TOKENS["text_primary"].lower() == "#dde4dd"


def test_all_page_and_viewport_surfaces_own_dark_theme() -> None:
    _app()
    window = ui.SecurityOverviewWindow(status_provider=lambda: _evidence())
    try:
        style = window.styleSheet()
        for selector in ("#SecurityOverviewWindow", "#PageViewport", "#SecurityRoot", "#AppShell", "#MainColumn"):
            assert selector in style
        assert ui.COLOR_TOKENS["canvas"] in style
    finally:
        window.close()


def test_original_sentinel_identity_contract_is_preserved() -> None:
    _app()
    window = ui.SecurityOverviewWindow(status_provider=lambda: _evidence())
    try:
        assert tuple(label for _, label in ui.NAV_ITEMS) == (
            "Dashboard",
            "Scansione",
            "Quarantena",
            "Cronologia",
            "Protezione",
            "Impostazioni",
        )
        assert set(window.nav_buttons) == set(label for _, label in ui.NAV_ITEMS)
        assert window.nav_buttons["Dashboard"].isEnabled() is True
        assert all(not button.isEnabled() for name, button in window.nav_buttons.items() if name != "Dashboard")
        assert all(not button.icon().isNull() for button in window.nav_buttons.values())
        assert window.sidebar.width() == 260
        assert window.sidebar_scan_button.isEnabled() is False
        assert window.modules_panel.objectName() == "ModulesPanel"
        assert "#ModulesPanel" in window.styleSheet()
        assert "#RecoveryButton" in window.styleSheet()
    finally:
        window.close()


def test_stitch_1600_layout_has_no_horizontal_clipping() -> None:
    app = _app()
    window = ui.SecurityOverviewWindow(status_provider=lambda: _evidence())
    try:
        window.resize(1600, 980)
        window.show()
        app.processEvents()
        window._apply_responsive_layout(force=True)
        app.processEvents()

        root = window.findChild(QWidget, "SecurityRoot")
        assert root is not None
        assert root.sizePolicy().horizontalPolicy() == QSizePolicy.Policy.Expanding
        # 1600 - 260 sidebar - 48 page margins, allowing native frame variance.
        assert root.width() >= 1200
        assert window.hero.width() >= 1150
        assert window.modules_panel.width() >= 1150
        assert window.page_scroll.horizontalScrollBar().maximum() == 0
        assert all(card.width() >= 500 for card in window.card_widgets.values())
        assert all(metric.width() >= 300 for metric in window.metric_cards)
    finally:
        window.close()


def test_minimum_desktop_layout_reflows_without_overflow() -> None:
    app = _app()
    window = ui.SecurityOverviewWindow(status_provider=lambda: _evidence())
    try:
        window.resize(window.minimumWidth(), window.minimumHeight())
        window.show()
        app.processEvents()
        window._apply_responsive_layout(force=True)
        app.processEvents()
        assert window.page_scroll.horizontalScrollBar().maximum() == 0
        assert window.hero_layout.direction() == ui.QBoxLayout.Direction.TopToBottom
        assert all(card.width() >= 280 for card in window.card_widgets.values())
    finally:
        window.close()


def test_display_copy_is_compact_and_does_not_claim_protection_when_unverified() -> None:
    badge, headline, summary = ui._display_posture(model.POSTURE_UNVERIFIED)
    assert badge == "Verifica necessaria"
    assert "verificare" in headline.lower()
    assert "protetto" in summary.lower()
    assert "BC Sentinel è attivo" not in headline


def test_window_minimum_size_and_offscreen_self_check_contract() -> None:
    _app()
    window = ui.SecurityOverviewWindow(status_provider=lambda: _evidence())
    try:
        assert window.minimumWidth() >= 1080
        assert window.minimumHeight() >= 720
    finally:
        window.close()
    check = ui.self_check()
    assert check["passed"] is True
    assert check["startup_scan_dispatch"] is False
    assert check["startup_rescue_dispatch"] is False
    assert check["smart_scan_enabled"] is False

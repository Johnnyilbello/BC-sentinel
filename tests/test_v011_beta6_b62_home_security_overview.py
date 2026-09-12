from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("BC_SENTINEL_REDUCED_MOTION", "1")

from PySide6.QtWidgets import QApplication, QBoxLayout, QSizePolicy

from sentinel import home_security_model as model
from sentinel import home_security_ui as ui
from sentinel.ui_pages import ThreatAlertDialog


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


def _evidence(*, malware: str = model.STATUS_ENGINE_AVAILABLE, behavior: str = model.STATUS_ENGINE_AVAILABLE, web: str = model.STATUS_ENGINE_AVAILABLE, recovery: str = model.STATUS_READY, verified_runtime: bool = False) -> dict:
    def item(layer_id: str, status: str, verified: bool) -> model.LayerEvidence:
        return model.LayerEvidence(layer_id=layer_id,status=status,runtime_verified=verified,summary=f"fixture:{layer_id}:{status}",raw={"fixture":True,"status":status},provenance="b62_test_fixture")
    return {model.LAYER_MALWARE:item(model.LAYER_MALWARE,malware,verified_runtime),model.LAYER_BEHAVIOR:item(model.LAYER_BEHAVIOR,behavior,verified_runtime),model.LAYER_WEB:item(model.LAYER_WEB,web,verified_runtime),model.LAYER_RECOVERY:item(model.LAYER_RECOVERY,recovery,recovery==model.STATUS_READY)}


def _show_at(window: ui.SecurityOverviewWindow, width: int, height: int = 900) -> None:
    app=_app(); window.resize(width,height); window.show(); app.processEvents(); window._apply_responsive_layout(force=True); app.processEvents(); window._sync_all_scroll_widths(); app.processEvents()


def test_profile_schema_and_parent_safety_contract() -> None:
    assert model.PROFILE=="v0.11.0-beta.6-b62"; assert model.SCHEMA=="bc-sentinel-beta6-home-security-overview-v1"
    contract=model.validate_b62_safety_contract(); assert contract["passed"] is True; assert contract["startup_scan_dispatch"] is False; assert contract["startup_rescue_dispatch"] is False; assert contract["automatic_repair"] is False; assert contract["automatic_quarantine"] is False; assert contract["destructive_authority_added"] is False; assert contract["smart_scan_enabled"] is False


def test_active_status_requires_explicit_runtime_verification() -> None:
    with pytest.raises(ValueError,match="active_requires_runtime_verification"):
        model.LayerEvidence(layer_id=model.LAYER_MALWARE,status=model.STATUS_ACTIVE,runtime_verified=False,summary="invalid optimistic fixture").validate()


def test_source_availability_alone_never_becomes_protected() -> None:
    snapshot=model.build_snapshot(); assert snapshot.posture==model.POSTURE_UNVERIFIED; runtime=[c for c in snapshot.cards if c.card_id in model.REQUIRED_RUNTIME_LAYERS]; assert runtime; assert all(c.status!=model.STATUS_ACTIVE for c in runtime); assert all(c.runtime_verified is False for c in runtime)


def test_verified_fixture_can_be_protected_but_missing_proof_cannot() -> None:
    verified=model.build_snapshot(lambda:_evidence(malware=model.STATUS_ACTIVE,behavior=model.STATUS_ACTIVE,web=model.STATUS_ACTIVE,verified_runtime=True)); assert verified.posture==model.POSTURE_PROTECTED
    payload=_evidence(malware=model.STATUS_ACTIVE,behavior=model.STATUS_ACTIVE,web=model.STATUS_ACTIVE,verified_runtime=True); payload[model.LAYER_WEB]=model.LayerEvidence(layer_id=model.LAYER_WEB,status=model.STATUS_UNAVAILABLE,runtime_verified=False,summary="missing live web proof",raw={"reason":"fixture_missing"},provenance="test"); assert model.build_snapshot(lambda:payload).posture==model.POSTURE_UNVERIFIED


def test_advanced_details_preserve_raw_evidence_and_provenance() -> None:
    payload=_evidence(); payload[model.LAYER_MALWARE]=model.LayerEvidence(layer_id=model.LAYER_MALWARE,status=model.STATUS_ENGINE_AVAILABLE,runtime_verified=False,summary="engine present",raw={"deep":{"hash":"ABC","source":"fixture"}},provenance="unit_test_probe"); card=next(c for c in model.build_snapshot(lambda:payload).cards if c.card_id==model.LAYER_MALWARE); assert card.advanced_details["raw_evidence"]=={"deep":{"hash":"ABC","source":"fixture"}}; assert card.advanced_details["provenance"]=="unit_test_probe"


def test_stitch_tokens_and_navigation_order_are_exact() -> None:
    assert ui.COLOR_TOKENS["canvas"].lower()=="#0f1412"; assert ui.COLOR_TOKENS["surface_1"].lower()=="#1c211f"; assert ui.COLOR_TOKENS["accent"].lower()=="#10b981"; assert ui.SPACING_TOKENS=={"xs":4,"sm":8,"md":16,"lg":24,"xl":32,"xxl":48}; assert tuple(label for _,label in ui.NAV_ITEMS)==ui.PAGE_ORDER; assert 120<=ui.MOTION_TOKENS["micro"]<=160; assert 180<=ui.MOTION_TOKENS["state"]<=220; assert 220<=ui.MOTION_TOKENS["panel"]<=280; assert ui.MOTION_TOKENS["page"]<=320


def test_window_builds_complete_stitch_shell_without_dispatching_scan() -> None:
    calls=[]
    def provider(): calls.append("status"); return _evidence()
    _app(); window=ui.SecurityOverviewWindow(status_provider=provider)
    try:
        assert calls==["status"]; assert window.windowTitle()==ui.WINDOW_TITLE; assert window.stack.count()==6; assert tuple(window.nav_buttons)==ui.PAGE_ORDER; assert all(b.isEnabled() for b in window.nav_buttons.values()); assert all(not b.icon().isNull() for b in window.nav_buttons.values()); assert window.smart_scan_button.isEnabled() is False; assert window.full_scan_button.isEnabled() is False; assert window.sidebar_scan_button.isEnabled() is False; assert len(window.card_widgets)==4; assert window.recovery_window is None
    finally: window.close()


def test_navigation_changes_visual_page_only_and_does_not_reprobe_security() -> None:
    calls=[]
    def provider(): calls.append("status"); return _evidence()
    app=_app(); window=ui.SecurityOverviewWindow(status_provider=provider)
    try:
        for index,page in enumerate(ui.PAGE_ORDER): window.nav_buttons[page].click(); app.processEvents(); assert window.stack.currentIndex()==index
        assert calls==["status"]; assert window.recovery_window is None; assert window.scan_page.quick_scan.isEnabled() is False; assert window.scan_page.full_scan.isEnabled() is False
    finally: window.close()


def test_quarantine_and_history_never_invent_rows_without_real_provider() -> None:
    _app(); window=ui.SecurityOverviewWindow(status_provider=lambda:_evidence())
    try:
        assert window.quarantine_page.table.rowCount()==0; assert window.quarantine_page.table.isVisible() is False; assert window.history_page.table.rowCount()==0; assert window.history_page.table.isVisible() is False
    finally: window.close()


def test_recovery_navigation_opens_b61_without_discovery(monkeypatch: pytest.MonkeyPatch) -> None:
    from sentinel import rescue_home_ui_model as b61_model
    invoked=[]
    def forbidden(*args,**kwargs): invoked.append("discover"); raise AssertionError("B6-1 discovery dispatched while opening System & Recovery")
    monkeypatch.setattr(b61_model,"run_operator_discovery",forbidden); app=_app(); window=ui.SecurityOverviewWindow(status_provider=lambda:_evidence())
    try:
        recovery=window.card_widgets[model.LAYER_RECOVERY]; assert recovery.action_button.isEnabled() is True; recovery.action_button.click(); app.processEvents(); assert invoked==[]; assert window.recovery_window is not None; assert window.recovery_window.ui_state.state=="IDLE"; assert window.recovery_window.discovery_view is None
    finally:
        if window.recovery_window is not None: window.recovery_window.close()
        window.close()


def test_refresh_is_passive_and_rebuilds_status_bound_pages() -> None:
    calls=[]
    def provider(): calls.append("status"); return _evidence()
    app=_app(); window=ui.SecurityOverviewWindow(status_provider=provider)
    try:
        old=window.protection_page; window.refresh_button.click(); app.processEvents(); assert calls==["status","status"]; assert window.smart_scan_button.isEnabled() is False; assert window.recovery_window is None; assert window.protection_page is not old; assert window.stack.count()==6
    finally: window.close()


def test_stitch_large_desktop_geometry_has_no_horizontal_overflow() -> None:
    window=ui.SecurityOverviewWindow(status_provider=lambda:_evidence())
    try:
        _show_at(window,1600,980); assert window.sidebar.width()==260; assert window.page_scroll.horizontalScrollBar().maximum()==0; assert window.page_host.width()==window.page_scroll.viewport().width(); assert window.hero_layout.direction()==QBoxLayout.Direction.LeftToRight; assert window.content_root.width()>=1250; assert window.hero.width()>=1200; assert window.modules_panel.width()>=1200; assert all(card.width()>=500 for card in window.card_widgets.values()); assert all(metric.width()>=300 for metric in window.metric_cards)
    finally: window.close()


def test_standard_laptop_reflows_intentionally_without_overflow() -> None:
    window=ui.SecurityOverviewWindow(status_provider=lambda:_evidence())
    try:
        _show_at(window,1080,820); assert window.sidebar.width()==220; assert window.page_scroll.horizontalScrollBar().maximum()==0; assert window.page_host.width()==window.page_scroll.viewport().width(); assert window.hero_layout.direction()==QBoxLayout.Direction.TopToBottom; assert window.metrics_grid.itemAtPosition(1,0) is not None; assert window.cards_grid.itemAtPosition(1,0) is not None
    finally: window.close()


def test_tablet_width_uses_icon_rail_and_all_pages_fit_outer_viewport() -> None:
    app=_app(); window=ui.SecurityOverviewWindow(status_provider=lambda:_evidence())
    try:
        _show_at(window,760,760); assert window.sidebar.width()==76; assert window.brand_copy.isVisible() is False; assert window.page_scroll.horizontalScrollBar().maximum()==0
        for page in ui.PAGE_ORDER:
            window._navigate(page); app.processEvents(); window._sync_all_scroll_widths(); assert window.page_scroll.horizontalScrollBar().maximum()==0; assert window.stack.currentWidget().minimumWidth()==0
            current=window.stack.currentWidget()
            if hasattr(current,"horizontalScrollBar"): assert current.horizontalScrollBar().maximum()==0
    finally: window.close()


def test_minimum_narrow_window_has_no_outer_horizontal_overflow() -> None:
    window=ui.SecurityOverviewWindow(status_provider=lambda:_evidence())
    try:
        _show_at(window,window.minimumWidth(),window.minimumHeight()); assert window.minimumWidth()<=560; assert window.sidebar.width()==76; assert window.page_scroll.horizontalScrollBar().maximum()==0; assert window.page_host.width()==window.page_scroll.viewport().width(); assert window.hero_layout.direction()==QBoxLayout.Direction.TopToBottom
    finally: window.close()


def test_threat_dialog_never_enables_quarantine_without_real_callback() -> None:
    _app(); dialog=ThreatAlertDialog({"name":"fixture","reason":"fixture only"})
    try: assert dialog.quarantine_button.isEnabled() is False
    finally: dialog.close()


def test_shared_dark_surface_and_no_unicode_nav_placeholders() -> None:
    _app(); window=ui.SecurityOverviewWindow(status_provider=lambda:_evidence())
    try:
        style=window.styleSheet(); assert "#PageViewport" in style; assert ui.COLOR_TOKENS["canvas"] in style; assert "#0b0e12" not in style; assert all(button.text() in ui.PAGE_ORDER for button in window.nav_buttons.values())
    finally: window.close()


def test_offscreen_self_check_contract_remains_passive() -> None:
    check=ui.self_check(); assert check["passed"] is True; assert check["startup_scan_dispatch"] is False; assert check["startup_rescue_dispatch"] is False; assert check["smart_scan_enabled"] is False

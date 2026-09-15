"""Offscreen clicks; no live scanner or user quarantine storage."""
import json
import os
import time
from dataclasses import replace
from unittest.mock import Mock
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("BC_SENTINEL_REDUCED_MOTION", "1")

import pytest
from PySide6.QtCore import Qt, QTimer
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QAbstractButton, QAbstractItemView, QLabel, QMessageBox, QPlainTextEdit
from sentinel.ui_product_copy import product_text
from sentinel.ui_pages import HistoryPage, QuarantinePage, ThreatAlertDialog
from sentinel.home_threat_cards_ui import ThreatCardWidget
from sentinel import home_guided_resolution_window as ui
from sentinel import home_security_model
from test_v011_beta6_b63_smart_scan_ui import UiFixtureProvider, _evidence
from test_v011_beta6_b659_quarantine_integrity import _card


@pytest.fixture
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def window(app, monkeypatch, tmp_path):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "Local"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "User"))
    monkeypatch.setattr(home_security_model, "default_evidence_provider", lambda: _evidence())
    provider = UiFixtureProvider(finding=True)
    from sentinel import smart_scan_provider_loader
    original = smart_scan_provider_loader.load_default_provider()
    monkeypatch.setattr(smart_scan_provider_loader, "load_default_provider", lambda: replace(original, provider=provider))
    w = ui.B65SecurityOverviewWindow()
    w.show()
    app.processEvents()
    yield w, provider
    if w.smart_scan_worker is not None:
        w.smart_scan_coordinator.request_cancel()
        w.smart_scan_worker.wait(3000)
    w.close()
    app.processEvents()


def click(button, app):
    QTest.mouseClick(button, Qt.MouseButton.LeftButton)
    app.processEvents()


def wait_scan(w, app):
    deadline = time.monotonic() + 5
    while w.smart_scan_worker is not None and time.monotonic() < deadline:
        app.processEvents()
        QTest.qWait(10)
    assert w.smart_scan_worker is None


def test_copy_preserves_raw(app, tmp_path):
    path = tmp_path / "sample.txt"
    path.write_text("fixture")
    model = replace(_card(path, "test"), title="Elemento da verificare", reason="Static scanner assessment: temp_execution_candidate", category="static_malware_scan", source_check_id="smart_scope_04")
    before = model.to_dict()
    card = ThreatCardWidget(model)
    card.show()
    app.processEvents()
    visible = " ".join(label.text() for label in card.findChildren(QLabel) if label.isVisible())
    assert "Comportamento sospetto" in visible
    assert "Analisi malware" in visible
    assert "Scansione intelligente" in visible
    assert "temp_execution_candidate" not in visible
    assert "smart_scope_04" not in visible
    click(card.advanced_button, app)
    assert card.advanced_text.isVisible()
    assert "temp_execution_candidate" in card.advanced_text.toPlainText()
    assert model.to_dict() == before
    click(card.advanced_button, app)
    assert not card.advanced_text.isVisible()
    card.close()


def test_navigation_refresh_and_all_button_wiring(window, app):
    w, provider = window
    for name, button in w.nav_buttons.items():
        click(button, app)
        assert w._current_page == name
        assert w.stack.currentWidget().isVisible()
        for control in w.findChildren(QAbstractButton):
            if not control.isVisible():
                continue
            assert control.accessibleName() or control.text(), control.objectName()
            assert control.toolTip(), control.text()
            if control.isEnabled():
                assert control.receivers("2clicked(bool)") or control.receivers("2toggled(bool)"), control.text()
    click(w.refresh_button, app)
    assert provider.run_calls == 0
    for width in (600, 1440):
        w.resize(width, 900)
        w._apply_responsive_layout(force=True)
        app.processEvents()
        assert w.sidebar_scan_button.accessibleName()
        assert "B6-" not in w.sidebar_scan_button.text()
    assert not w.full_scan_button.isEnabled()
    assert all(not b.isEnabled() for b in w._footer_buttons)


@pytest.mark.parametrize("entry", ["smart_scan_button", "sidebar_scan_button", "page"])
def test_scan_launch_real_click(window, app, entry):
    w, provider = window
    button = w.scan_page.quick_scan if entry == "page" else getattr(w, entry)
    if entry == "page":
        click(w.nav_buttons["Scansione"], app)
    click(button, app)
    wait_scan(w, app)
    assert provider.run_calls == 1
    assert w.last_smart_scan_result is not None
    click(w.scan_page.advanced_button, app)
    assert w.scan_page.advanced_text.isVisible()
    click(w.scan_page.advanced_button, app)
    assert not w.scan_page.advanced_text.isVisible()


def test_cancel_real_click(window, app):
    w, provider = window
    provider.block = True
    click(w.smart_scan_button, app)
    click(w.scan_page.cancel_scan, app)
    wait_scan(w, app)
    assert provider.cancel_seen


def test_quarantine_refresh_preserves_restore_and_cancel_is_safe(window, app, monkeypatch):
    w, _ = window
    rows = [{"file": "fixture.txt", "restore_key": "fixture"}, {"file": "blocked.txt", "status": "Verifica richiesta"}]
    monkeypatch.setattr(w.home_quarantine_controller, "quarantine_rows", lambda: rows)
    w.quarantine_page.rows_provider = lambda: rows
    restore = Mock(side_effect=AssertionError("restore must not run on No"))
    monkeypatch.setattr(w.home_quarantine_controller, "rollback", restore)
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.No)
    click(w.nav_buttons["Quarantena"], app)
    for _ in range(2):
        click(w.quarantine_page.refresh_button, app)
        button = w.quarantine_page.table.cellWidget(0, 6)
        assert button is not None
        assert w.quarantine_page.table.cellWidget(1, 6) is None
        click(button, app)
    restore.assert_not_called()
    assert not w.quarantine_page.filter_button.isEnabled()


def test_inactive_filters_and_legacy_details(app):
    q = QuarantinePage(rows_provider=lambda: [{"file": "fixture"}])
    h = HistoryPage(rows_provider=lambda: [{"level": "HIGH"}])
    assert not q.filter_button.isEnabled()
    assert all(not b.isEnabled() for b in h.filter_buttons)
    for page in (q, h):
        page.show()
        app.processEvents()
        table = page.table
        assert table.editTriggers() == QAbstractItemView.EditTrigger.NoEditTriggers
        cell = table.visualItemRect(table.item(0, 0)).center()
        QTest.mouseClick(table.viewport(), Qt.MouseButton.LeftButton, pos=cell)
        assert table.currentRow() == 0
    d = ThreatAlertDialog({"name": "Fixture", "reason": "Test", "sha256": "abc"})
    d.show()
    app.processEvents()
    details = next(b for b in d.findChildren(QAbstractButton) if b.text() == "Dettagli")
    click(details, app)
    assert d.findChild(QPlainTextEdit).isVisible()
    assert not d.quarantine_button.isEnabled()
    click(next(b for b in d.findChildren(QAbstractButton) if b.text() == "Ignora per ora"), app)
    assert not d.isVisible()
    q.close()
    h.close()


def test_unknown_codes_have_safe_copy():
    assert "future_code" not in product_text("future_code")


def test_settings_indicators_are_read_only(window, app):
    from sentinel.ui_design_system import ReadOnlyToggle
    w, _ = window
    click(w.nav_buttons["Impostazioni"], app)
    for toggle in w.settings_page.findChildren(ReadOnlyToggle):
        before = toggle.on
        QTest.mouseClick(toggle, Qt.MouseButton.LeftButton)
        assert toggle.on == before
        assert toggle.toolTip()


def test_recovery_buttons_dispatch_only_on_click(window, app, monkeypatch):
    w, provider = window
    calls = []
    monkeypatch.setattr(w, "_handle_card_action", calls.append)
    click(w.refresh_button, app)
    click(w.nav_buttons["Dashboard"], app)
    card = w.card_widgets[home_security_model.LAYER_RECOVERY]
    click(card.details_button, app)
    assert card.details_button.isChecked()
    click(card.details_button, app)
    click(card.action_button, app)
    assert calls == [home_security_model.LAYER_RECOVERY]
    click(w.nav_buttons["Protezione"], app)
    action = next(b for b in w.protection_page.findChildren(QAbstractButton) if b.text() == "Apri")
    click(action, app)
    assert calls == [home_security_model.LAYER_RECOVERY] * 2
    assert provider.run_calls == 0


@pytest.mark.parametrize("accept", [False, True])
def test_quarantine_card_confirmation_clicks_use_mock_only(window, app, monkeypatch, accept):
    w, _ = window
    controller = w.home_quarantine_controller
    monkeypatch.setattr(controller, "assess", lambda *a: SimpleNamespace(ready=True, reason=""))
    prepare = Mock(return_value=SimpleNamespace(plan=SimpleNamespace(target=SimpleNamespace(locator="fixture.txt"))))
    execute = Mock(return_value=SimpleNamespace(result_id="fixture"))
    rollback = Mock(return_value=SimpleNamespace(rollback_id="fixture"))
    monkeypatch.setattr(controller, "prepare_confirmation", prepare)
    monkeypatch.setattr(controller, "confirm_and_execute", execute)
    monkeypatch.setattr(controller, "rollback", rollback)
    click(w.smart_scan_button, app)
    wait_scan(w, app)
    card = w.scan_page.threat_card_widgets[0]
    guidance = card.findChildren(QAbstractButton)
    details = next(b for b in guidance if b.text() == "Dettagli risoluzione")
    click(details, app)
    assert details.isChecked()
    click(details, app)
    button = next(b for b in guidance if b.property("quarantineMode") == "quarantine")

    def answer_dialog():
        box = app.activeModalWidget()
        assert isinstance(box, QMessageBox)
        target = next(b for b in box.buttons() if (box.buttonRole(b) == QMessageBox.ButtonRole.AcceptRole) == accept)
        QTest.mouseClick(target, Qt.MouseButton.LeftButton)

    QTimer.singleShot(0, answer_dialog)
    click(button, app)
    prepare.assert_called_once()
    assert execute.call_count == int(accept)
    if accept:
        assert button.property("quarantineMode") == "restore"
        QTimer.singleShot(0, answer_dialog)
        click(button, app)
        rollback.assert_called_once()
        assert not button.isEnabled()
    else:
        rollback.assert_not_called()




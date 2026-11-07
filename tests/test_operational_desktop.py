from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QApplication, QFileDialog, QMessageBox

from sentinel.operational_desktop import OperationalWindow
from sentinel import storage_analyzer


@pytest.fixture
def desktop(tmp_path, monkeypatch):
    QApplication.instance() or QApplication([])
    monkeypatch.setattr(QMessageBox, "information", lambda *a, **kw: QMessageBox.StandardButton.Ok)
    monkeypatch.setattr(QMessageBox, "warning", lambda *a, **kw: QMessageBox.StandardButton.Yes)
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **kw: QMessageBox.StandardButton.Yes)
    window = OperationalWindow(data_root=tmp_path / "profile")
    yield window
    window.storage_page.process = None
    if window.offline_dialog is not None:
        window.offline_dialog.close()
    window.close()


@pytest.mark.parametrize("route", [
    "Dashboard", "Motore BC", "Quarantena", "Storage Analyzer", "Impostazioni e aiuto",
])
def test_every_sidebar_button_changes_real_page(desktop, route):
    desktop.nav_buttons[route].click()
    assert desktop.stack.currentWidget() is desktop.pages[route]
    assert desktop.nav_buttons[route].isChecked()


def test_overview_launches_local_scan_with_selected_folder(desktop, tmp_path, monkeypatch):
    calls = []
    folder = str(tmp_path / "folder with spaces")
    monkeypatch.setattr(QFileDialog, "getExistingDirectory", lambda *a, **kw: folder)
    monkeypatch.setattr(desktop.bc_page, "start_scan", calls.append)
    desktop.command_buttons["dashboard_bc"].click()
    assert calls == [folder]


def test_data_folder_button_opens_local_destination(desktop, monkeypatch):
    urls = []
    monkeypatch.setattr(QDesktopServices, "openUrl", lambda url: urls.append(url.toString()) or True)
    desktop.command_buttons["data_folder"].click()
    assert len(urls) == 1 and urls[0].startswith("file:")
    assert desktop.data_root.is_dir()


@pytest.mark.parametrize("key", ["help", "about", "administrator"])
def test_information_and_admin_buttons_produce_visible_response(desktop, monkeypatch, key):
    messages = []
    monkeypatch.setattr(QMessageBox, "information", lambda *a, **kw: messages.append(a[1:3]))
    monkeypatch.setattr("sentinel.operational_desktop.sys.frozen", False, raising=False)
    desktop.command_buttons[key].click()
    assert messages


@pytest.mark.parametrize("key", ["history_export", "diagnostics"])
def test_export_buttons_save_actual_json(desktop, tmp_path, monkeypatch, key):
    destination = tmp_path / f"{key}.json"
    desktop._record("fixture", "eseguita")
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *a, **kw: (str(destination), "JSON"))
    desktop.command_buttons[key].click()
    data = json.loads(destination.read_text(encoding="utf-8"))
    assert data


def test_legacy_history_keeps_bc_events_without_rewriting_original(tmp_path):
    QApplication.instance() or QApplication([])
    history = tmp_path / "history.json"
    previous = [{"azione": "quick", "esito": "Old integration"},
                {"azione": "Scansione BC", "esito": "Completata"}]
    history.write_text(json.dumps(previous), encoding="utf-8")
    window = OperationalWindow(data_root=tmp_path)
    try:
        assert "Scansione BC" in window.history.toPlainText()
        assert "Old integration" not in window.history.toPlainText()
        window._record("Scansione BC", "Nuova scansione")
        assert json.loads(history.read_text(encoding="utf-8")) == previous
        assert len(json.loads(window.history_path.read_text(encoding="utf-8"))) == 2
    finally:
        window.close()


def test_storage_buttons_and_offline_button_open_real_components(desktop, monkeypatch):
    monkeypatch.setattr(storage_analyzer, "availability", lambda: (True, "pronto"))
    calls = []
    monkeypatch.setattr(storage_analyzer, "launch", lambda: calls.append(True) or SimpleNamespace(poll=lambda: 0))
    desktop.command_buttons["dashboard_storage"].click()
    assert desktop.stack.currentWidget() is desktop.pages["Storage Analyzer"]
    desktop.storage_page.launch_button.click()
    assert calls == [True]
    desktop.command_buttons["offline_settings"].click()
    assert desktop.stack.currentWidget() is desktop.pages["Scansione offline"]
    desktop.command_buttons["offline_open"].click()
    assert desktop.offline_dialog is not None
    assert desktop.offline_dialog.isVisible()


def test_main_routes_match_the_bc_navigation(desktop):
    assert [button.text() for button in desktop.nav_buttons.values()] == [
        "Panoramica", "Scansione", "Minacce", "Archivio", "Impostazioni"
    ]
    assert set(desktop.command_buttons) == {
        "dashboard_bc", "dashboard_folder", "dashboard_storage", "offline_settings", "offline_open",
        "history_refresh", "history_export", "administrator", "diagnostics", "data_folder", "help", "about",
    }
    assert all(button.isEnabled() for button in desktop.command_buttons.values())


def test_elevation_is_blocked_before_launch_while_offline_worker_is_active(desktop, monkeypatch):
    import sentinel.operational_desktop as module
    with monkeypatch.context() as patch:
        patch.setattr(module.sys, "frozen", True, raising=False)
        patch.setattr(module.ctypes.windll.shell32, "ShellExecuteW",
                      lambda *a: pytest.fail("elevation dispatched during active worker"))
        desktop.offline_dialog = SimpleNamespace(_thread=object())
        desktop.command_buttons["administrator"].click()
        desktop.offline_dialog = None


def test_unexpected_callback_exception_is_reported_and_logged(desktop, monkeypatch):
    import sentinel.operational_desktop as module
    messages = []
    monkeypatch.setattr(module.sys, "excepthook", module.sys.excepthook)
    monkeypatch.setattr(QMessageBox, "critical", lambda *a: messages.append(a[2]))
    module.install_exception_reporting(desktop)
    try:
        raise ValueError("Errore campione")
    except ValueError:
        module.sys.excepthook(*module.sys.exc_info())
    assert messages and "Errore campione" in messages[0]
    assert "Errore campione" in (desktop.data_root / "errors.log").read_text(encoding="utf-8")


def test_monitor_coverage_warnings_reach_threats_and_badge(desktop):
    page = desktop.bc_page
    page.monitor_counts = [0, 0, 0]
    page.monitor_folder = "C:/test-watch"
    page.monitor = SimpleNamespace(stop_event=SimpleNamespace(is_set=lambda: False))
    try:
        page._monitor_batch({"files": 0, "findings": [], "skipped": 0, "errors": []}, 3)
        page._monitor_failed("Sorgente eventi persa")
        assert desktop._unread_bc_notices == 2
        desktop.nav_buttons["Quarantena"].click()
        notices = desktop.bc_notices.toPlainText()
        assert "3 eventi da verificare" in notices
        assert "Sorgente eventi persa" in notices
        assert desktop._unread_bc_notices == 0
    finally:
        page.monitor = None


def test_automatic_isolation_requires_approval_and_uses_verified_vault(desktop, monkeypatch):
    pane = desktop.bc_vault
    calls = []
    monkeypatch.setattr(pane.vault, "isolate", lambda path, digest: calls.append((path, digest)))
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **kw: QMessageBox.StandardButton.No)
    pane.auto_isolate.setChecked(True)
    assert not pane.auto_isolate.isChecked()
    first = {"isolate_path": "C:/fixture-one.txt", "sha256": "a" * 64}
    pane.add_finding(first)
    assert not calls
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **kw: QMessageBox.StandardButton.Yes)
    pane.auto_isolate.setChecked(True)
    second = {"isolate_path": "C:/fixture-two.txt", "sha256": "b" * 64}
    pane.add_finding(second)
    assert calls == [(second["isolate_path"], second["sha256"])]
    assert pane.candidates.count() == 1

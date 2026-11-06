from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from PySide6.QtCore import QProcess
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
    window = OperationalWindow(data_root=tmp_path / "profile", auto_status=False)
    yield window
    window.engine.ready = False
    window.storage_page.process = None
    if window.offline_dialog is not None:
        window.offline_dialog.close()
    window.close()


@pytest.mark.parametrize("route", [
    "Dashboard", "Motore BC", "Scansione", "Scansione offline", "Quarantena", "Cronologia",
    "Protezione", "Storage Analyzer", "Impostazioni e aiuto",
])
def test_every_sidebar_button_changes_real_page(desktop, route):
    desktop.nav_buttons[route].click()
    assert desktop.stack.currentWidget() is desktop.pages[route]
    assert desktop.nav_buttons[route].isChecked()


@pytest.mark.parametrize("key,action", [
    ("dashboard_refresh", "status"), ("dashboard_quick", "quick"),
    ("dashboard_full", "full"), ("quarantine_refresh", "status"),
    ("protection_refresh", "status"), ("signatures", "update"),
])
def test_antivirus_buttons_dispatch_correct_action(desktop, monkeypatch, key, action):
    calls = []
    desktop.engine.ready = True
    monkeypatch.setattr(desktop.engine, "run", lambda value, **kw: calls.append((value, kw)))
    desktop.command_buttons[key].click()
    assert calls and calls[0][0] == action


@pytest.mark.parametrize("button,action", [
    ("refresh_button", "status"), ("quick_button", "quick"), ("full_button", "full"),
])
def test_embedded_engine_buttons_dispatch(desktop, monkeypatch, button, action):
    calls = []
    desktop.engine.ready = True
    desktop.engine._sync()
    monkeypatch.setattr(desktop.engine, "run", lambda value, **kw: calls.append(value))
    getattr(desktop.engine, button).click()
    assert calls == [action]


def test_custom_folder_selection_reaches_scan_action(desktop, tmp_path, monkeypatch):
    calls = []
    folder = str(tmp_path / "folder with spaces")
    monkeypatch.setattr(QFileDialog, "getExistingDirectory", lambda *a, **kw: folder)
    desktop.engine.ready = True
    monkeypatch.setattr(desktop.engine, "run", lambda value, **kw: calls.append((value, kw)))
    desktop.command_buttons["custom_scan"].click()
    assert calls == [("custom", {"scan_path": folder})]


def test_scan_waits_for_live_readiness_and_does_not_silently_disappear(desktop, monkeypatch):
    calls = []
    monkeypatch.setattr(desktop.engine, "run", lambda value, **kw: calls.append((value, kw)))
    desktop.command_buttons["dashboard_quick"].click()
    assert calls[0][0] == "status"
    assert desktop.pending_scan == ("quick", None)
    desktop.engine.ready = True
    desktop.engine.last_result = {"active_threats": [], "threat_history": []}
    desktop._engine_finished(0, QProcess.ExitStatus.NormalExit)
    assert calls[-1] == ("quick", {"scan_path": None})


def test_failed_start_clears_pending_scan_and_records_error(desktop):
    desktop.pending_scan = ("full", None)
    desktop.engine.status.setText("Impossibile avviare il motore")
    desktop._engine_error(QProcess.ProcessError.FailedToStart)
    assert desktop.pending_scan is None
    assert "Impossibile" in desktop.overview.text()
    assert desktop.events[-1]["esito"] == "Impossibile avviare il motore"


def test_removal_buttons_require_active_detections_and_confirmation(desktop, monkeypatch):
    calls = []
    desktop.engine.ready = True
    desktop.engine.active_count = 1
    desktop.engine._sync()
    monkeypatch.setattr(desktop.engine, "run", lambda value, **kw: calls.append((value, kw)))
    desktop.command_buttons["quarantine_remove"].click()
    assert calls == [("remove", {"removal_confirmed": True})]
    calls.clear()
    monkeypatch.setattr(QMessageBox, "warning", lambda *a, **kw: QMessageBox.StandardButton.No)
    desktop.engine.remove_button.click()
    assert calls == []


@pytest.mark.parametrize("key", ["quarantine_windows", "security_settings", "data_folder"])
def test_windows_and_folder_buttons_open_explicit_destinations(desktop, monkeypatch, key):
    urls = []
    monkeypatch.setattr(QDesktopServices, "openUrl", lambda url: urls.append(url.toString()) or True)
    desktop.command_buttons[key].click()
    assert len(urls) == 1
    if key == "data_folder":
        assert urls[0].startswith("file:")
        assert desktop.data_root.is_dir()
    else:
        assert urls == ["ms-settings:windowsdefender"]


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


def test_history_refresh_is_persistent_and_settings_timer_is_real(desktop):
    desktop._record("quick", "completata")
    desktop.history.clear()
    desktop.command_buttons["history_refresh"].click()
    assert "quick" in desktop.history.toPlainText()
    assert json.loads((desktop.data_root / "history.json").read_text())[0]["azione"] == "quick"
    desktop.auto_refresh.setChecked(True)
    assert desktop.refresh_timer.isActive()
    assert json.loads((desktop.data_root / "settings.json").read_text())["auto_refresh"] is True
    desktop.close()
    assert not desktop.refresh_timer.isActive()


def test_storage_buttons_and_offline_button_open_real_components(desktop, monkeypatch):
    monkeypatch.setattr(storage_analyzer, "availability", lambda: (True, "pronto"))
    calls = []
    monkeypatch.setattr(storage_analyzer, "launch", lambda: calls.append(True) or SimpleNamespace(poll=lambda: 0))
    desktop.command_buttons["dashboard_storage"].click()
    assert desktop.stack.currentWidget() is desktop.pages["Storage Analyzer"]
    desktop.storage_page.launch_button.click()
    assert calls == [True]
    desktop.command_buttons["offline_open"].click()
    assert desktop.offline_dialog is not None
    assert desktop.offline_dialog.isVisible()


def test_all_main_command_buttons_are_covered(desktop):
    assert set(desktop.command_buttons) == {
        "dashboard_bc", "dashboard_refresh", "dashboard_quick", "dashboard_full", "dashboard_storage", "custom_scan",
        "offline_open", "quarantine_refresh", "quarantine_windows", "quarantine_remove",
        "history_refresh", "history_export", "protection_refresh", "signatures",
        "security_settings", "administrator", "diagnostics", "data_folder", "help", "about",
    }
    assert all(button.isEnabled() for button in desktop.command_buttons.values())


def test_refresh_during_scan_has_visible_feedback(desktop, monkeypatch):
    messages = []
    with monkeypatch.context() as patch:
        patch.setattr(desktop.engine, "busy", lambda: True)
        patch.setattr(desktop.engine, "run", lambda *a, **kw: pytest.fail("second command dispatched"))
        patch.setattr(QMessageBox, "information", lambda *a, **kw: messages.append(a[2]))
        desktop.command_buttons["dashboard_refresh"].click()
        assert messages
        assert desktop.stack.currentWidget() is desktop.pages["Scansione"]


def test_synchronous_launch_failure_is_visible_and_clears_queue(desktop, monkeypatch):
    from sentinel import windows_defender
    def fail(*a, **kw):
        raise OSError("PowerShell non disponibile")
    monkeypatch.setattr(windows_defender, "command", fail)
    desktop.threats.setPlainText("Vecchi rilevamenti")
    desktop.command_buttons["dashboard_full"].click()
    assert desktop.pending_scan is None
    assert "PowerShell non disponibile" in desktop.overview.text()
    assert "Vecchi rilevamenti" not in desktop.threats.toPlainText()
    assert desktop.events


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

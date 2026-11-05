from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from PySide6.QtCore import QProcess
from PySide6.QtWidgets import QApplication, QMessageBox

from sentinel import windows_defender as defender
from sentinel.windows_defender_ui import WindowsDefenderDialog


def test_only_fixed_actions_are_accepted_and_removal_requires_consent(monkeypatch):
    with pytest.raises(ValueError):
        defender.command("status; Remove-Item C:\\")
    with pytest.raises(PermissionError):
        defender.command("remove")
    monkeypatch.setattr(defender.sys, "platform", "win32")
    monkeypatch.setattr(defender.Path, "is_file", lambda self: True)
    program, args = defender.command("quick")
    assert program.endswith("WindowsPowerShell\\v1.0\\powershell.exe")
    assert args[:3] == ["-NoLogo", "-NoProfile", "-NonInteractive"]
    assert "Start-MpScan -ScanType QuickScan" in args[-1]
    assert "Remove-MpThreat" not in args[-1]
    assert "Set-MpPreference" not in args[-1]
    _, removal = defender.command("remove", removal_confirmed=True)
    assert "Remove-MpThreat -ErrorAction Stop" in removal[-1]
    assert "$initial.AMRunningMode -ne 'Normal'" in removal[-1]


@pytest.fixture
def dialog():
    app = QApplication.instance() or QApplication([])
    window = WindowsDefenderDialog()
    yield window
    window.close()
    app.processEvents()


def test_opening_controls_does_not_dispatch_and_removal_is_initially_disabled(dialog):
    assert dialog.process.state() == QProcess.ProcessState.NotRunning
    assert not dialog.quick_button.isEnabled()
    assert not dialog.remove_button.isEnabled()


def test_declined_confirmation_never_invokes_removal(dialog, monkeypatch):
    dialog.ready = True
    dialog.active_count = 1
    dialog._sync()
    monkeypatch.setattr(QMessageBox, "warning", lambda *a: QMessageBox.StandardButton.No)
    monkeypatch.setattr(dialog, "run", lambda *a, **kw: pytest.fail("Removal dispatched"))
    dialog.remove_button.click()


@pytest.mark.parametrize("mode,threats,expected", [
    ("Normal", [{"name": "Harmless fixture", "id": "1"}], True),
    ("Normal", [], False),
    ("Passive Mode", [{"name": "Harmless fixture", "id": "1"}], False),
])
def test_real_engine_state_controls_actions(dialog, mode, threats, expected):
    payload = {
        "service_enabled": True, "antivirus_enabled": True,
        "mode": mode, "active_threats": threats,
    }
    original = dialog.process
    dialog.process = SimpleNamespace(
        readAllStandardOutput=lambda: json.dumps(payload).encode(),
        readAllStandardError=lambda: b"",
        state=lambda: QProcess.ProcessState.NotRunning,
    )
    try:
        dialog._finished(0, QProcess.ExitStatus.NormalExit)
        assert dialog.remove_button.isEnabled() is expected
        assert dialog.quick_button.isEnabled() is (mode == "Normal")
        assert "Motore Microsoft Defender" in dialog.report.toPlainText()
    finally:
        dialog.process = original


def test_failed_command_is_visible_and_cannot_enable_removal(dialog):
    original = dialog.process
    dialog.process = SimpleNamespace(
        readAllStandardOutput=lambda: b"",
        readAllStandardError=lambda: b"Access denied",
        state=lambda: QProcess.ProcessState.NotRunning,
    )
    try:
        dialog._finished(1, QProcess.ExitStatus.NormalExit)
        assert "Access denied" in dialog.status.text()
        assert not dialog.remove_button.isEnabled()
    finally:
        dialog.process = original

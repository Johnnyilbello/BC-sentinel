from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from PySide6.QtWidgets import QApplication

from sentinel import storage_analyzer as storage
from sentinel.storage_analyzer_ui import StorageAnalyzerPage
from sentinel.beta10_trust_center_ui import TrustCenterWindow


@pytest.fixture
def app():
    return QApplication.instance() or QApplication([])


def test_resolver_uses_source_and_frozen_resource_not_current_directory(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    assert storage.executable_path().parent.name == "storage_analyzer"
    assert storage.executable_path().parent.parent.name == "build"
    monkeypatch.setattr(storage.sys, "frozen", True, raising=False)
    monkeypatch.setattr(storage.sys, "_MEIPASS", str(tmp_path / "package"), raising=False)
    assert storage.executable_path() == tmp_path / "package" / "storage_analyzer" / storage.EXECUTABLE


def test_launcher_passes_one_exact_executable_without_shell(monkeypatch, tmp_path):
    executable = tmp_path / "folder with spaces" / storage.EXECUTABLE
    calls = []
    monkeypatch.setattr(storage, "availability", lambda: (True, "ready"))
    monkeypatch.setattr(storage, "executable_path", lambda: executable)
    monkeypatch.setattr(storage.subprocess, "Popen", lambda *a, **kw: calls.append((a, kw)))
    storage.launch()
    assert calls == [(([str(executable)],), {"cwd": str(executable.parent), "shell": False})]


def test_unavailable_component_never_launches_and_has_recovery(app, monkeypatch):
    monkeypatch.setattr(storage, "availability", lambda: (False, "Componente mancante"))
    monkeypatch.setattr(storage, "launch", lambda: pytest.fail("must not launch"))
    page = StorageAnalyzerPage()
    assert not page.launch_button.isEnabled()
    assert "mancante" in page.status.text()
    page.launch()
    page.close()


def test_launch_failure_can_be_retried(app, monkeypatch):
    monkeypatch.setattr(storage, "availability", lambda: (True, "ready"))
    def fail():
        raise OSError("accesso negato")
    monkeypatch.setattr(storage, "launch", fail)
    page = StorageAnalyzerPage()
    page.launch_button.click()
    assert "accesso negato" in page.status.text()
    assert page.launch_button.isEnabled()
    page.close()


def test_duplicate_launch_and_child_exit(app, monkeypatch):
    monkeypatch.setattr(storage, "availability", lambda: (True, "ready"))
    child = SimpleNamespace(poll=lambda: None)
    calls = []
    monkeypatch.setattr(storage, "launch", lambda: calls.append(True) or child)
    page = StorageAnalyzerPage()
    page.launch_button.click()
    page.launch()
    assert len(calls) == 1
    assert not page.launch_button.isEnabled()
    child.poll = lambda: 1
    page._poll()
    assert "errore" in page.status.text()
    assert page.launch_button.isEnabled()
    page.close()


def test_navigation_refresh_and_narrow_layout_preserve_storage_route(app, monkeypatch):
    monkeypatch.setattr(storage, "availability", lambda: (True, "ready"))
    window = TrustCenterWindow(include_storage=True)
    try:
        assert window.stack.count() == 8
        assert window.storage_page.process is None
        for width in (1440, 960, 560):
            window.resize(width, 820)
            window.show()
            window._apply_responsive_layout(force=True)
            window.nav_buttons["Storage Analyzer"].click()
            app.processEvents()
            window._sync_all_scroll_widths()
            app.processEvents()
            assert window.stack.currentWidget() is window.storage_scroll
            assert window.storage_scroll.horizontalScrollBar().maximum() == 0
            assert window.nav_buttons["Storage Analyzer"].accessibleName() == "Storage Analyzer"
            window._refresh_snapshot()
            app.processEvents()
            assert window.stack.currentWidget() is window.storage_scroll
            window._navigate("Dashboard")
            window._navigate("Storage Analyzer")
            assert window.stack.currentWidget() is window.storage_scroll
    finally:
        window.close()

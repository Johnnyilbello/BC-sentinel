from pathlib import Path
import ast

def test_activity_page_and_service_ui_present():
    src=Path("app/ui/main_window.py").read_text(encoding="utf-8")
    assert '("Attività", "≋")' in src
    assert "def _activity_page" in src
    assert "Telemetria avanzata attiva" in src
    assert "Fallback locale attivo" in src
    assert "Installa Protection Service" in src

def test_taskbar_icon_configuration_present():
    src=Path("app/main.py").read_text(encoding="utf-8")
    assert "SetCurrentProcessExplicitAppUserModelID" in src
    assert "app.setWindowIcon" in src

def test_main_window_parses():
    ast.parse(Path("app/ui/main_window.py").read_text(encoding="utf-8"))

def test_service_build_is_separate_executable():
    ps=Path("bootstrap.ps1").read_text(encoding="utf-8-sig")
    dedicated=Path("BUILD-SERVIZIO-PROTEZIONE.ps1").read_text(encoding="utf-8-sig")
    assert "BC-Sentinel-Protection" in ps
    assert "BUILD-SERVIZIO-PROTEZIONE.ps1" in ps
    assert "protection_service_entry.py" in dedicated

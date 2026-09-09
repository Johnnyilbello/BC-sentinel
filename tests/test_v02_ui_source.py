from pathlib import Path
import ast

def test_ui_v02_features():
    src=Path("app/ui/main_window.py").read_text(encoding="utf-8")
    for token in ("QSystemTrayIcon","AnimatedStackedWidget","PulseDot","Spiega con AI","ETW Telemetry","Persistence Monitor"):
        assert token in src

def test_ui_parses():
    ast.parse(Path("app/ui/main_window.py").read_text(encoding="utf-8"))

def test_background_mode():
    src=Path("app/main.py").read_text(encoding="utf-8")
    assert '"--background" in sys.argv' in src
    assert "setQuitOnLastWindowClosed(False)" in src

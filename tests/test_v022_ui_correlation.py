from pathlib import Path
import ast

def test_activity_shows_correlation_context():
    source=Path("app/ui/main_window.py").read_text(encoding="utf-8")
    assert "correlation_score_delta" in source
    assert "Correlazione comportamentale" in source
    assert "EventDeduplicator" in source

def test_ui_parses():
    ast.parse(Path("app/ui/main_window.py").read_text(encoding="utf-8"))

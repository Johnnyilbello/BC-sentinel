from pathlib import Path
import ast

REQUIRED = {
    "_quarantine_page",
    "_history_page",
    "_activity_page",
    "_protection_page",
    "_settings_page",
    "_telemetry_status_changed",
    "_refresh_telemetry_visual_state",
    "_consume_telemetry_events",
    "_attribution_for_path",
    "refresh_activity",
    "refresh_all",
    "present_threat",
    "toggle_etw",
}

def _mainwindow():
    source=Path("app/ui/main_window.py").read_text(encoding="utf-8")
    tree=ast.parse(source)
    return next(
        n for n in tree.body
        if isinstance(n,ast.ClassDef) and n.name=="MainWindow"
    )

def test_critical_methods_belong_to_mainwindow():
    cls=_mainwindow()
    methods={
        n.name for n in cls.body
        if isinstance(n,ast.FunctionDef)
    }
    assert not (REQUIRED-methods), sorted(REQUIRED-methods)

def test_v021_helpers_not_leaked_to_module_scope():
    source=Path("app/ui/main_window.py").read_text(encoding="utf-8")
    tree=ast.parse(source)
    leaked={
        n.name for n in tree.body
        if isinstance(n,ast.FunctionDef)
    }
    assert "_activity_page" not in leaked
    assert "_telemetry_status_changed" not in leaked
    assert "_attribution_for_path" not in leaked

def test_bootstrap_redirects_python_stderr_safely():
    source=Path("bootstrap.ps1").read_text(encoding="utf-8-sig")
    assert "Start-Process" in source
    assert "RedirectStandardOutput" in source
    assert "RedirectStandardError" in source
    assert "$proc.ExitCode" in source

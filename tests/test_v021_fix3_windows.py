from pathlib import Path
import ast

def test_appuserid_is_only_for_frozen_exe():
    source=Path("app/main.py").read_text(encoding="utf-8")
    assert 'getattr(sys, "frozen", False)' in source
    assert "SetCurrentProcessExplicitAppUserModelID" in source

def test_native_taskbar_icon_fallback_present():
    source=Path("app/ui/main_window.py").read_text(encoding="utf-8")
    assert "def _apply_native_windows_icon" in source
    assert "WM_SETICON" in source and "LoadImageW" in source and "SendMessageW" in source

def test_no_automated_test_writes_canonical_eicar_constant_to_disk():
    sources = [
        Path("tests/test_scanner.py"),
        Path("tests/test_eicar_end_to_end.py"),
        Path("tests/test_v071_beta3_ioc_containment_inbox_performance.py"),
    ]
    forbidden="write_bytes(" + "EICAR_TEST_STRING" + ")"
    for source in sources:
        assert forbidden not in source.read_text(encoding="utf-8"), source

def test_bootstrap_captures_pytest_output():
    source=Path("bootstrap.ps1").read_text(encoding="utf-8-sig")
    assert "bc-sentinel-pytest-out" in source
    assert "RedirectStandardError $testErr" in source
    assert "$testProc.ExitCode" in source

def test_main_window_still_parses_and_owns_methods():
    source=Path("app/ui/main_window.py").read_text(encoding="utf-8")
    tree=ast.parse(source)
    cls=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=="MainWindow")
    methods={n.name for n in cls.body if isinstance(n,ast.FunctionDef)}
    assert "_apply_native_windows_icon" in methods
    assert "_activity_page" in methods
    assert "_settings_page" in methods

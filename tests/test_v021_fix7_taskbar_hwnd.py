from pathlib import Path
import ast

def test_taskbar_icon_sets_window_and_class_icons():
    source=Path("app/ui/main_window.py").read_text(encoding="utf-8")
    assert "WM_SETICON" in source
    assert "GCLP_HICON = -14" in source
    assert "GCLP_HICONSM = -34" in source
    assert "SetClassLongPtrW" in source
    assert "SetClassLongW" in source

def test_taskbar_native_types_are_pointer_sized():
    source=Path("app/ui/main_window.py").read_text(encoding="utf-8")
    assert "LONG_PTR = ctypes.c_ssize_t" in source
    assert "WPARAM_T = ctypes.c_size_t" in source
    assert "LPARAM_T = ctypes.c_ssize_t" in source

def test_icon_is_reapplied_after_first_show():
    source=Path("app/ui/main_window.py").read_text(encoding="utf-8")
    assert "QTimer.singleShot(0, self._apply_native_windows_icon)" in source
    assert "QTimer.singleShot(150, self._apply_native_windows_icon)" in source
    assert "QTimer.singleShot(700, self._apply_native_windows_icon)" in source

def test_source_run_does_not_force_unregistered_appuserid():
    source=Path("app/main.py").read_text(encoding="utf-8")
    assert 'os.name == "nt" and getattr(sys, "frozen", False)' in source
    assert "SetCurrentProcessExplicitAppUserModelID" in source

def test_ui_still_parses_and_mainwindow_owns_icon_method():
    source=Path("app/ui/main_window.py").read_text(encoding="utf-8")
    tree=ast.parse(source)
    cls=next(
        n for n in tree.body
        if isinstance(n,ast.ClassDef) and n.name=="MainWindow"
    )
    methods={
        n.name for n in cls.body
        if isinstance(n,ast.FunctionDef)
    }
    assert "_apply_native_windows_icon" in methods
    assert "showEvent" in methods

from pathlib import Path
import ast

def test_main_imports_os_before_using_os_name():
    source = Path("app/main.py").read_text(encoding="utf-8")
    tree = ast.parse(source)

    imported_os = False
    uses_os_name = False

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(alias.name == "os" for alias in node.names):
                imported_os = True
        if isinstance(node, ast.Attribute):
            if (
                isinstance(node.value, ast.Name)
                and node.value.id == "os"
                and node.attr == "name"
            ):
                uses_os_name = True

    assert uses_os_name
    assert imported_os

def test_main_has_single_qicon_import():
    source = Path("app/main.py").read_text(encoding="utf-8")
    assert source.count("from PySide6.QtGui import QIcon") == 1

def test_bootstrap_captures_python_traceback_on_startup_failure():
    source = Path("bootstrap.ps1").read_text(encoding="utf-8-sig")
    assert "Start-Process" in source
    assert "RedirectStandardOutput" in source
    assert "RedirectStandardError" in source
    assert "function Write-BCLog" in source
    assert "Write-BCLog -Message ([string]$_)" in source
    assert "$proc.ExitCode" in source

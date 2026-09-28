import os
from pathlib import Path

from tools.windows_packaging import build_environment


def test_foreign_native_libraries_cannot_enter_packaging_search_path():
    original = {"SystemRoot": str(Path('system')), "PATH": "foreign/poppler/bin", "PYTHONPATH": "foreign/python", "PYTHONHOME": "foreign/home", "QT_PLUGIN_PATH": "foreign/qt", "QT_QPA_PLATFORM_PLUGIN_PATH": "foreign/plugins", "TEMP": "build-temp"}
    before = dict(original)
    result = build_environment(original, str(Path('venv/Scripts/python.exe')), str(Path('python/python.exe')))
    assert result['PATH'].split(os.pathsep) == [str(Path('venv/Scripts')), str(Path('python')), str(Path('system/System32')), str(Path('system'))]
    assert all(name not in result for name in ('PYTHONPATH', 'PYTHONHOME', 'QT_PLUGIN_PATH', 'QT_QPA_PLATFORM_PLUGIN_PATH'))
    assert result['TEMP'] == 'build-temp'
    assert original == before

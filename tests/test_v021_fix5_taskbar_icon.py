from pathlib import Path
import ast
import struct

def _ico_sizes(path):
    data=Path(path).read_bytes()
    reserved,kind,count=struct.unpack_from("<HHH",data,0)
    assert reserved==0
    assert kind==1
    sizes=set()
    offset=6
    for _ in range(count):
        width=data[offset] or 256
        height=data[offset+1] or 256
        sizes.add((width,height))
        offset += 16
    return sizes

def test_multidpi_ico_contains_taskbar_sizes():
    sizes=_ico_sizes("app/assets/bc_sentinel.ico")
    for size in (
        (16,16),(20,20),(24,24),(32,32),
        (40,40),(48,48),(256,256),
    ):
        assert size in sizes

def test_runtime_qt_icon_prefers_png():
    main=Path("app/main.py").read_text(encoding="utf-8")
    ui=Path("app/ui/main_window.py").read_text(encoding="utf-8")
    assert 'bc_sentinel_icon.png' in main
    assert 'app.setWindowIcon(qt_icon)' in main
    assert 'self.setWindowIcon(qicon)' in ui

def test_pyinstaller_assets_use_meipass():
    cfg=Path("sentinel/config.py").read_text(encoding="utf-8")
    assert 'getattr(sys, "_MEIPASS"' in cfg

def test_win32_icon_calls_are_x64_safe():
    ui=Path("app/ui/main_window.py").read_text(encoding="utf-8")
    assert 'ctypes.WinDLL("user32"' in ui
    assert "LoadImageW.argtypes" in ui
    assert "HANDLE = ctypes.c_void_p" in ui
    assert "LoadImageW.restype = HANDLE" in ui
    assert "SendMessageW.argtypes" in ui
    assert "ctypes.c_ssize_t" in ui

def test_mainwindow_still_owns_all_icon_and_ui_methods():
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
    for name in (
        "_apply_native_windows_icon",
        "_activity_page",
        "_settings_page",
        "_quarantine_page",
    ):
        assert name in methods

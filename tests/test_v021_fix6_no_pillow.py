from pathlib import Path

def test_test_suite_has_no_pillow_dependency():
    offenders=[]
    current=Path(__file__).name
    for path in Path("tests").glob("test_*.py"):
        if path.name == current:
            continue
        source=path.read_text(encoding="utf-8",errors="ignore")
        if "from PIL" in source or "import PIL" in source:
            offenders.append(path.name)
    assert not offenders, offenders

def test_icon_test_uses_stdlib_struct():
    source=Path("tests/test_v021_fix5_taskbar_icon.py").read_text(encoding="utf-8")
    assert "import struct" in source
    assert "struct.unpack_from" in source
    assert "PIL" not in source

from pathlib import Path
import pytest
import sentinel.scanner as scanner_mod
from sentinel.config import Settings

def test_scan_file_excludes_managed_app_root(tmp_path, monkeypatch):
    app = tmp_path / "BC-Sentinel"
    app.mkdir()
    f = app / "own_test.py"
    f.write_text("harmless", encoding="utf-8")

    monkeypatch.setattr(scanner_mod, "APP_ROOT", app)
    s = scanner_mod.StaticScanner(Settings(exclude_self=True))
    with pytest.raises(ValueError, match="self-managed"):
        s.scan_file(f)

def test_self_exclusion_can_be_disabled_for_integrity_work(tmp_path, monkeypatch):
    app = tmp_path / "BC-Sentinel"
    app.mkdir()
    f = app / "own_test.py"
    f.write_text("harmless", encoding="utf-8")

    monkeypatch.setattr(scanner_mod, "APP_ROOT", app)
    s = scanner_mod.StaticScanner(Settings(exclude_self=False))
    r = s.scan_file(f)
    assert r.path.endswith("own_test.py")

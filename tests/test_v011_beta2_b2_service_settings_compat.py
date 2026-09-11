from __future__ import annotations

from pathlib import Path

import pytest

from tools.v011_beta2_b2_service_settings_compat import MARKER, apply


_SOURCE = '''from .config import APP_ROOT, DATA_DIR, EXE_DIR, PROGRAM_DATA_DIR, Settings

CONFIG_FIELDS = ("realtime_enabled", "monitored_dirs", "ransomware_dirs")

def _settings_from_dict(raw):
    settings = Settings.defaults()
    for key in CONFIG_FIELDS:
        if key in raw:
            setattr(settings, key, raw[key])
    settings.monitored_dirs = [str(x) for x in settings.monitored_dirs if str(x)]
    settings.ransomware_dirs = [str(x) for x in settings.ransomware_dirs if str(x)]
    return settings

class ProtectionConfigStore:
    pass

class ProtectionRuntime:
    def start(self):
        try:
            self.settings = self.config_store.load()
        except Exception as exc:
            return False
        realtime_running = bool(self.realtime.start()) if self.settings.realtime_enabled else False
        return realtime_running

    def resume(self):
        # Resume using persisted settings.
        self._protection_enabled = True
        self.settings = self.config_store.load()
        realtime_running = bool(self.realtime.start()) if self.settings.realtime_enabled else False
        return realtime_running
'''


def _write_fixture(root: Path, source: str = _SOURCE) -> Path:
    target = root / "sentinel" / "protection_service_core.py"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(source, encoding="utf-8")
    return target


def test_service_settings_migration_is_surgical_and_idempotent(tmp_path: Path):
    target = _write_fixture(tmp_path)

    first = apply(tmp_path)
    patched = target.read_text(encoding="utf-8")

    assert first["changed"] is True
    assert MARKER in patched
    assert "Settings, ensure_service_profile_roots" in patched
    assert "settings = ensure_service_profile_roots(settings)" in patched
    assert patched.count("loaded_settings = ensure_service_profile_roots(self.config_store.load())") == 2
    assert patched.count("setattr(self.settings, key, getattr(loaded_settings, key))") == 2
    assert "self.settings = self.config_store.load()" not in patched

    second = apply(tmp_path)
    assert second["changed"] is False
    assert second["status"] == "already_canonical"
    assert target.read_text(encoding="utf-8") == patched


def test_service_settings_migration_refuses_unknown_source_shape(tmp_path: Path):
    _write_fixture(tmp_path, _SOURCE.replace("self.settings = self.config_store.load()", "self.settings = custom_loader()", 1))

    with pytest.raises(RuntimeError, match="refusing partial patch"):
        apply(tmp_path)

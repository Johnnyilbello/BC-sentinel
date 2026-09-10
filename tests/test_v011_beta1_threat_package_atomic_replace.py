from pathlib import Path
import os
import shutil

import pytest

from sentinel.threat_packages import ThreatPackageError, ThreatPackageManager
from tools.v011_threat_package_windows_compat import HELPER, apply_compat_patch


def test_atomic_replace_retries_transient_windows_access_denied(monkeypatch, tmp_path):
    source = tmp_path / "active-behavior.json.tmp"
    target = tmp_path / "active-behavior.json"
    source.write_text("new", encoding="utf-8")
    target.write_text("old", encoding="utf-8")
    attempts = {"count": 0}

    def flaky_replace(src, dst):
        attempts["count"] += 1
        if attempts["count"] < 3:
            exc = PermissionError(5, "simulated transient Windows access denied")
            exc.winerror = 5
            raise exc
        src_path = Path(src)
        dst_path = Path(dst)
        dst_path.write_bytes(src_path.read_bytes())
        src_path.unlink()
        return None

    monkeypatch.setattr(os, "replace", flaky_replace)
    monkeypatch.setattr("sentinel.threat_packages.time.sleep", lambda _: None)
    ThreatPackageManager._replace_file_with_retry(source, target, attempts=4)

    assert attempts["count"] == 3
    assert target.read_text(encoding="utf-8") == "new"
    assert not source.exists()


def test_atomic_replace_retries_transient_windows_access_denied_for_directory(monkeypatch, tmp_path):
    source = tmp_path / "active-yara.tmp"
    target = tmp_path / "active-yara"
    source.mkdir()
    (source / "active-package.json").write_text("new", encoding="utf-8")
    attempts = {"count": 0}

    def flaky_replace(src, dst):
        attempts["count"] += 1
        if attempts["count"] < 3:
            exc = PermissionError(5, "simulated transient Windows directory access denied")
            exc.winerror = 5
            raise exc
        src_path = Path(src)
        dst_path = Path(dst)
        dst_path.mkdir()
        for child in src_path.iterdir():
            if child.is_file():
                (dst_path / child.name).write_bytes(child.read_bytes())
        shutil.rmtree(src_path)
        return None

    monkeypatch.setattr(os, "replace", flaky_replace)
    monkeypatch.setattr("sentinel.threat_packages.time.sleep", lambda _: None)
    ThreatPackageManager._replace_file_with_retry(source, target, attempts=4)

    assert attempts["count"] == 3
    assert (target / "active-package.json").read_text(encoding="utf-8") == "new"
    assert not source.exists()


def test_existing_threat_package_patch_is_upgraded_for_yara_directory_and_retry_helper(tmp_path):
    target = tmp_path / "threat_packages.py"
    target.write_text(
        "from pathlib import Path\n"
        "import os\n"
        "import time\n\n"
        "class ThreatPackageError(RuntimeError):\n"
        "    pass\n\n"
        "class ThreatPackageManager:\n"
        "    @staticmethod\n"
        "    def _replace_file_with_retry(source: Path, target: Path, *, attempts: int = 8) -> None:\n"
        "        os.replace(source, target)\n\n"
        "    @staticmethod\n"
        "    def _remove_tree_with_retry(path: Path, *, required: bool, attempts: int = 6) -> bool:\n"
        "        return True\n\n"
        "    def publish(self):\n"
        "        self._replace_file_with_retry(tmp, self.state_path)\n"
        "        self._replace_file_with_retry(tmp, self.activation_journal_path)\n"
        "        self._replace_file_with_retry(tmp, self.active_behavior_path)\n"
        "        self._replace_file_with_retry(tmp, self.active_behavior_path)\n"
        "        self._replace_file_with_retry(tmp, self.active_behavior_path)\n"
        "        os.replace(tmp, self.active_yara_dir)\n",
        encoding="utf-8",
    )

    first = apply_compat_patch(target)
    second = apply_compat_patch(target)
    text = target.read_text(encoding="utf-8")

    assert first["patched"] is True
    assert "retry_helper_canonicalized" in first["upgrades"]
    assert "yara_directory_retry" in first["upgrades"]
    assert second["patched"] is False
    assert text.count("self._replace_file_with_retry(tmp, self.active_yara_dir)") == 1
    assert "os.replace(tmp, self.active_yara_dir)" not in text
    helper_start = text.index("    @staticmethod\n    def _replace_file_with_retry(")
    helper_end = text.index("    @staticmethod\n    def _remove_tree_with_retry", helper_start)
    assert text[helper_start:helper_end] == HELPER


def test_atomic_replace_fails_closed_after_bounded_transient_retries(monkeypatch, tmp_path):
    source = tmp_path / "state.json.tmp"
    target = tmp_path / "state.json"
    source.write_text("new", encoding="utf-8")

    def always_locked(src, dst):
        exc = PermissionError(32, "simulated sharing violation")
        exc.winerror = 32
        raise exc

    monkeypatch.setattr(os, "replace", always_locked)
    monkeypatch.setattr("sentinel.threat_packages.time.sleep", lambda _: None)
    with pytest.raises(ThreatPackageError, match="cannot atomically publish"):
        ThreatPackageManager._replace_file_with_retry(source, target, attempts=3)


def test_atomic_replace_does_not_retry_unrelated_errors(monkeypatch, tmp_path):
    source = tmp_path / "state.json.tmp"
    target = tmp_path / "state.json"
    source.write_text("new", encoding="utf-8")
    attempts = {"count": 0}

    def invalid_replace(src, dst):
        attempts["count"] += 1
        raise OSError(22, "invalid argument")

    monkeypatch.setattr(os, "replace", invalid_replace)
    with pytest.raises(OSError):
        ThreatPackageManager._replace_file_with_retry(source, target, attempts=8)
    assert attempts["count"] == 1

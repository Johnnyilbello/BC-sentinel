from pathlib import Path
import os

import pytest

from sentinel.threat_packages import ThreatPackageError, ThreatPackageManager


def test_atomic_replace_retries_transient_windows_access_denied(monkeypatch, tmp_path):
    source = tmp_path / "active-behavior.json.tmp"
    target = tmp_path / "active-behavior.json"
    source.write_text("new", encoding="utf-8")
    target.write_text("old", encoding="utf-8")
    real_replace = os.replace
    attempts = {"count": 0}

    def flaky_replace(src, dst):
        attempts["count"] += 1
        if attempts["count"] < 3:
            exc = PermissionError(5, "simulated transient Windows access denied")
            exc.winerror = 5
            raise exc
        return real_replace(src, dst)

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
    real_replace = os.replace
    attempts = {"count": 0}

    def flaky_replace(src, dst):
        attempts["count"] += 1
        if attempts["count"] < 3:
            exc = PermissionError(5, "simulated transient Windows directory access denied")
            exc.winerror = 5
            raise exc
        return real_replace(src, dst)

    monkeypatch.setattr(os, "replace", flaky_replace)
    monkeypatch.setattr("sentinel.threat_packages.time.sleep", lambda _: None)
    ThreatPackageManager._replace_file_with_retry(source, target, attempts=4)

    assert attempts["count"] == 3
    assert (target / "active-package.json").read_text(encoding="utf-8") == "new"
    assert not source.exists()


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

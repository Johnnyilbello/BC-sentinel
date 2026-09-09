import time
from pathlib import Path

from sentinel.config import Settings
from sentinel.database import Database
from sentinel.realtime import RealtimeMonitor


def make_monitor(tmp_path):
    protected = tmp_path / "Documents"
    protected.mkdir()

    noisy = tmp_path / "Temp"
    noisy.mkdir()

    settings = Settings(
        monitored_dirs=[str(protected), str(noisy)],
        ransomware_dirs=[str(protected)],
        ransomware_startup_grace_seconds=30,
    )

    db = Database(tmp_path / "db.sqlite")
    return RealtimeMonitor(settings=settings, db=db), protected, noisy


def test_temp_is_not_ransomware_scored(tmp_path):
    monitor, protected, noisy = make_monitor(tmp_path)
    monitor._started_monotonic = time.monotonic() - 60

    for i in range(60):
        monitor._fs_event("modified", str(noisy / f"x{i}.txt"))

    assert len(monitor.ransomware.events) == 0


def test_startup_grace_suppresses_file_bursts(tmp_path):
    monitor, protected, noisy = make_monitor(tmp_path)
    monitor._started_monotonic = time.monotonic()

    for i in range(60):
        monitor._fs_event("modified", str(protected / f"x{i}.txt"))

    assert len(monitor.ransomware.events) == 0


def test_after_grace_protected_folder_is_scored(tmp_path):
    monitor, protected, noisy = make_monitor(tmp_path)
    monitor._started_monotonic = time.monotonic() - 60

    monitor._fs_event("modified", str(protected / "x.txt"))

    assert len(monitor.ransomware.events) == 1


def test_dev_venv_tree_is_excluded(tmp_path):
    monitor, protected, noisy = make_monitor(tmp_path)
    monitor._started_monotonic = time.monotonic() - 60

    venv_file = protected / "project" / ".venv" / "Lib" / "x.py"
    venv_file.parent.mkdir(parents=True)

    monitor._fs_event("modified", str(venv_file))

    assert len(monitor.ransomware.events) == 0

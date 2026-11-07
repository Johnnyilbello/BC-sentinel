import hashlib
import json
import os
from threading import Event, Thread

from watchdog.events import FileCreatedEvent, FileModifiedEvent, FileMovedEvent

from sentinel.bc_folder_monitor import PendingChanges, monitor_folder
from sentinel.bc_rename_activity import MIN_RENAMES, WINDOW_SECONDS, RenameActivity


def test_queue_coalesces_writes_keeps_move_destination_and_discloses_capacity(tmp_path):
    pending = PendingChanges(settle=0, capacity=2)
    target = str(tmp_path / "first.txt")
    moved = str(tmp_path / "moved.txt")
    pending.dispatch(FileCreatedEvent(target))
    pending.dispatch(FileModifiedEvent(target))
    pending.dispatch(FileMovedEvent(str(tmp_path / "previous.txt"), moved))
    pending.dispatch(FileCreatedEvent(str(tmp_path / "overflow.txt")))
    assert pending.take_ready() == ([target, moved], 1)
    assert pending.take_ready() == ([], 0)


def test_live_monitor_detects_new_nested_file_without_changing_it(tmp_path):
    root = tmp_path / "watch"
    nested = root / "nested"
    nested.mkdir(parents=True)
    existing = root / "existing.txt"
    payload = b"harmless monitor fixture"
    existing.write_bytes(payload)
    signatures = tmp_path / "catalog.json"
    signatures.write_text(json.dumps({"schema": "bc-sentinel-offline-intel-v1", "approved": True,
        "sha256": [{"value": hashlib.sha256(payload).hexdigest(), "name": "fixture", "source": "test"}]}))
    started, detected, stop = Event(), Event(), Event()
    results = []
    errors = []

    def report(result, missed):
        results.extend(result["findings"])
        if results:
            detected.set()

    def run():
        try:
            monitor_folder(root, catalog=signatures, yara_path=None, stop=stop,
                           started=lambda _: started.set(), report=report)
        except Exception as exc:
            errors.append(exc)

    monitor = Thread(target=run, daemon=True)
    monitor.start()
    try:
        assert started.wait(10), errors
        target = nested / "new.txt"
        target.write_bytes(payload)
        assert detected.wait(15), errors
        assert {entry["path"] for entry in results} == {str(target)}
        assert target.read_bytes() == payload
    finally:
        stop.set()
        monitor.join(10)
    assert not monitor.is_alive()
    assert not errors


def test_rename_alert_uses_distinct_paths_and_window(tmp_path):
    time = [0.0]
    tracker = RenameActivity(tmp_path, clock=lambda: time[0])
    same_source = tmp_path / "one.docx"
    for i in range(MIN_RENAMES):
        assert tracker.observe(same_source, tmp_path / f"{i}.bc-test") is None
        assert tracker.observe(tmp_path / f"{i}.docx", tmp_path / f"{i}.pdf") is None
    time[0] += WINDOW_SECONDS + 1
    for i in range(MIN_RENAMES - 1):
        assert tracker.observe(tmp_path / f"{i}.docx", tmp_path / f"{i}.bc-test") is None
    assert tracker.observe(tmp_path.parent / "other.docx", tmp_path / "outside.bc-test") is None
    alert = tracker.observe(tmp_path / "last.docx", tmp_path / "last.bc-test")
    assert alert.distinct_renames == MIN_RENAMES
    assert alert.extension == ".bc-test"
    assert tracker.observe(tmp_path / "extra.docx", tmp_path / "extra.bc-test") is None


def test_continuous_writes_cannot_postpone_monitor_scan_forever(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr("sentinel.bc_folder_monitor.monotonic", lambda: clock[0])
    pending = PendingChanges()
    pending.dispatch(FileModifiedEvent("busy.txt"))
    for step in range(1, 11):
        clock[0] = step * 0.5
        pending.dispatch(FileModifiedEvent("busy.txt"))
    assert pending.take_ready() == (["busy.txt"], 0)


def test_ready_busy_file_is_not_hidden_behind_settling_file(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr("sentinel.bc_folder_monitor.monotonic", lambda: clock[0])
    pending = PendingChanges()
    pending.dispatch(FileModifiedEvent("busy.txt"))
    clock[0] = 4.9
    pending.dispatch(FileModifiedEvent("new.txt"))
    pending.dispatch(FileModifiedEvent("busy.txt"))
    clock[0] = 5.0
    assert pending.take_ready() == (["busy.txt"], 0)
    clock[0] = 5.6
    assert pending.take_ready() == (["new.txt"], 0)


def test_changed_file_recovers_from_temporary_windows_sharing_violation(tmp_path, monkeypatch):
    from pathlib import Path

    from sentinel.bc_scan import BCScanEngine, scan_changed

    target = tmp_path / "busy.txt"
    target.write_text("harmless fixture")
    engine = BCScanEngine.load(None, None)
    original_open = Path.open
    attempts = []

    def open_file(path, *args, **kwargs):
        if path == target:
            attempts.append(path)
            if len(attempts) == 1:
                error = PermissionError(13, "sharing violation", str(path))
                if os.name != "nt":
                    error.winerror = 32
                raise error
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", open_file)
    result = scan_changed(tmp_path, [target], engine, cancelled=lambda: False,
                          wait_for_retry=lambda _: False)
    assert len(attempts) == 2
    assert result["files"] == 1
    assert result["skipped"] == 0

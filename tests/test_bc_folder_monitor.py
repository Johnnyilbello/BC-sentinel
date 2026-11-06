import hashlib
import json
from threading import Event, Thread

from watchdog.events import FileCreatedEvent, FileModifiedEvent, FileMovedEvent

from sentinel.bc_folder_monitor import PendingChanges, monitor_folder


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

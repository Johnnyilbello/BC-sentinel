"""Scan changed files in one explicitly selected folder while the app is open."""
from collections import OrderedDict
import os
from pathlib import Path
from threading import Lock
from time import monotonic

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from sentinel.bc_scan import BCScanEngine, scan_changed, scan_root
from sentinel.bc_rename_activity import RenameActivity


class PendingChanges(FileSystemEventHandler):
    """Coalesce repeated writes and disclose when the application queue fills."""

    def __init__(self, *, settle=0.65, capacity=1024, activity=None, on_alert=None):
        self.settle = settle
        self.capacity = capacity
        self._paths = OrderedDict()
        self._lock = Lock()
        self._missed = 0
        self._activity = activity
        self._on_alert = on_alert

    def on_any_event(self, event):
        if event.event_type not in {"created", "modified", "moved"}:
            return
        path = os.fsdecode(event.dest_path if event.event_type == "moved" else event.src_path)
        if not path:
            return
        alert = None
        with self._lock:
            if event.is_directory:
                # A populated directory can enter the watch without a file event
                # for every member. Do not count it as fully observed.
                self._missed += event.event_type == "moved"
                return
            if self._activity is not None and event.event_type == "moved":
                alert = self._activity.observe(Path(os.path.abspath(os.fsdecode(event.src_path))),
                                               Path(os.path.abspath(path)))
            key = os.path.normcase(os.path.abspath(path))
            if key not in self._paths and len(self._paths) >= self.capacity:
                self._missed += 1
            else:
                self._paths[key] = (monotonic() + self.settle, path)
                self._paths.move_to_end(key)
        if alert is not None and self._on_alert is not None:
            self._on_alert(alert)

    def take_ready(self, limit=16):
        now = monotonic()
        ready = []
        with self._lock:
            while self._paths and len(ready) < limit:
                _, (deadline, path) = next(iter(self._paths.items()))
                if deadline > now:
                    break
                self._paths.popitem(last=False)
                ready.append(path)
            missed, self._missed = self._missed, 0
        return ready, missed


def monitor_folder(folder, *, catalog, yara_path, stop, started, report, on_alert=None):
    root = scan_root(folder)
    identity = root.stat()
    engine = BCScanEngine.load(catalog, yara_path)
    if stop.is_set():
        return
    def publish_alert(alert):
        if not stop.is_set() and on_alert is not None:
            on_alert(str(root), alert)

    changes = PendingChanges(activity=RenameActivity(root), on_alert=publish_alert)
    observer = Observer()
    observer.schedule(changes, str(root), recursive=True)
    observer.start()
    try:
        started(str(root))
        while not stop.wait(0.2):
            if (not observer.is_alive() or not observer.emitters or
                    not all(emitter.is_alive() for emitter in observer.emitters)):
                raise OSError("Il monitor Windows ha perso la sorgente degli eventi.")
            if not os.path.samestat(identity, root.stat()):
                raise OSError("La cartella monitorata è stata sostituita.")
            paths, missed = changes.take_ready()
            if paths or missed:
                result = scan_changed(root, paths, engine, cancelled=stop.is_set)
                report(result, missed)
    finally:
        observer.stop()
        observer.join()

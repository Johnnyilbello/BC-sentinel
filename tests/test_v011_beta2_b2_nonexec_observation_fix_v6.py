from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace

from tools.v011_beta2_b2_nonexec_observation_fix_v6 import MARKER, transform_realtime


SOURCE = '''from pathlib import Path

POTENTIALLY_EXECUTABLE = {".exe", ".dll"}

class Scanner:
    def __init__(self):
        self.calls = []

    def scan_file(self, path):
        self.calls.append(path)
        return {"path": path}

class RealtimeMonitor:
    def __init__(self, event_callback=None):
        self.event_callback = event_callback
        self.scanner = Scanner()

    def _queue_scan(self, path):
        p = Path(path)
        if p.name == ".bc_sentinel_canary.txt":
            return
        if p.suffix.lower() not in POTENTIALLY_EXECUTABLE:
            return
        threading.Thread(
            target=self._scan_when_stable,
            args=(path,),
            name="BCS-RealtimeScan",
            daemon=True,
        ).start()

    def _scan_when_stable(self, path):
        try:
            # bc-sentinel-v011-beta2-watchdog-file-observation-v1: emit only after file stabilization, before static scan
            if self.event_callback is not None:
                try:
                    self.event_callback(str(path))
                except Exception:
                    pass
        except Exception:
            pass
        return self.scanner.scan_file(str(path))
'''


class ImmediateThread:
    created = 0

    def __init__(self, *, target, args, name, daemon):
        type(self).created += 1
        self.target = target
        self.args = args
        self.name = name
        self.daemon = daemon

    def start(self):
        self.target(*self.args)


def _module_from(text: str):
    namespace = {
        "threading": SimpleNamespace(Thread=ImmediateThread),
    }
    exec(compile(text, "<v6-test>", "exec"), namespace, namespace)
    return namespace


def test_transform_is_ast_valid_idempotent_and_keeps_executable_filter():
    patched = transform_realtime(SOURCE)
    ast.parse(patched)
    assert patched.count(MARKER) == 1
    assert patched.count("POTENTIALLY_EXECUTABLE") == SOURCE.count("POTENTIALLY_EXECUTABLE")
    assert patched.count("self.event_callback(str(path))") == 2
    assert transform_realtime(patched) == patched


def test_tmp_is_observed_but_never_static_scanned_and_no_scan_thread_is_created(tmp_path: Path):
    ImmediateThread.created = 0
    patched = transform_realtime(SOURCE)
    ns = _module_from(patched)
    observed: list[str] = []
    monitor = ns["RealtimeMonitor"](event_callback=observed.append)
    marker = tmp_path / "bcs-v011-beta2-b2-native-test.tmp"
    marker.write_text("harmless\n", encoding="utf-8")

    monitor._queue_scan(str(marker))

    assert observed == [str(marker)]
    assert monitor.scanner.calls == []
    assert ImmediateThread.created == 0


def test_executable_path_keeps_existing_stabilization_and_static_scan(tmp_path: Path):
    ImmediateThread.created = 0
    patched = transform_realtime(SOURCE)
    ns = _module_from(patched)
    observed: list[str] = []
    monitor = ns["RealtimeMonitor"](event_callback=observed.append)
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")

    monitor._queue_scan(str(sample))

    assert observed == [str(sample)]
    assert monitor.scanner.calls == [str(sample)]
    assert ImmediateThread.created == 1


def test_canary_still_bypasses_observation_and_scan(tmp_path: Path):
    ImmediateThread.created = 0
    patched = transform_realtime(SOURCE)
    ns = _module_from(patched)
    observed: list[str] = []
    monitor = ns["RealtimeMonitor"](event_callback=observed.append)
    canary = tmp_path / ".bc_sentinel_canary.txt"
    canary.write_text("canary\n", encoding="utf-8")

    monitor._queue_scan(str(canary))

    assert observed == []
    assert monitor.scanner.calls == []
    assert ImmediateThread.created == 0


def test_two_hundred_benign_txt_events_create_zero_realtime_scan_threads(tmp_path: Path):
    ImmediateThread.created = 0
    patched = transform_realtime(SOURCE)
    ns = _module_from(patched)
    observed: list[str] = []
    monitor = ns["RealtimeMonitor"](event_callback=observed.append)

    for index in range(200):
        path = tmp_path / f"safe-{index:04d}.txt"
        path.write_text("benign\n", encoding="utf-8")
        monitor._queue_scan(str(path))

    assert len(observed) == 200
    assert monitor.scanner.calls == []
    assert ImmediateThread.created == 0

from __future__ import annotations

import ast

from tools.v011_beta2_b2_queue_scan_trace_compat_v4 import MARKER, transform_realtime


SOURCE = '''from __future__ import annotations

import threading

class RealtimeMonitor:
    def __init__(self):
        self._debounce = {}
        self._recent_hashes = {}
        self.event_callback = None

    def _queue_scan(self, path):
        if not path:
            return
        now = 1.0
        previous = self._debounce.get(str(path))
        if previous is not None and now - previous < 0.5:
            return
        self._debounce[str(path)] = now
        threading.Thread(
            target=self._scan_when_stable,
            args=(path,),
            name="BCS-RealtimeScan",
            daemon=True,
        ).start()

    def _scan_when_stable(self, path):
        if not path:
            return
        if self.event_callback is not None:
            self.event_callback(str(path))
        return
'''


def test_queue_stabilization_trace_is_ast_valid_and_idempotent():
    patched = transform_realtime(SOURCE)
    ast.parse(patched)
    assert patched.count(MARKER) == 1
    assert patched.count('trace_marker("QUEUE_SCAN_ENTER"') == 1
    assert patched.count('trace_marker("QUEUE_SCAN_RETURN"') == 2
    assert patched.count('trace_marker("QUEUE_SCAN_THREAD_START_REQUEST"') == 1
    assert patched.count('trace_marker("QUEUE_SCAN_THREAD_STARTED"') == 1
    assert patched.count('trace_marker("STABLE_ENTER"') == 1
    assert patched.count('trace_marker("STABLE_RETURN"') == 2
    assert transform_realtime(patched) == patched


def test_diagnostics_do_not_remove_original_queue_or_callback_logic():
    patched = transform_realtime(SOURCE)
    assert 'target=self._scan_when_stable' in patched
    assert 'self.event_callback(str(path))' in patched
    assert 'self._debounce[str(path)] = now' in patched
    assert 'daemon=True' in patched

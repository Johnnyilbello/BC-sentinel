from __future__ import annotations

from pathlib import Path

import pytest

from tools.v011_beta2_b2_file_observation_compat import (
    MARKER,
    transform_core_text,
    transform_realtime_text,
)


_REALTIME = '''class RealtimeMonitor:\n    def __init__(\n        self,\n        settings=None,\n        db=None,\n        callback=None,\n        ransomware_callback=None,\n        correlator=None,\n    ):\n        self.settings = settings\n        self.callback = callback\n        self.ransomware_callback = ransomware_callback\n        self.correlator = correlator\n        self.scanner = object()\n\n    def _scan_when_stable(self, path: str):\n        if not path:\n            return\n        try:\n            report = self.scanner.scan(path)\n        except OSError:\n            return\n        return report\n'''


_CORE = '''class SecurityEvent:\n    def __init__(self, **kwargs):\n        self.kwargs = kwargs\n\nclass RealtimeMonitor:\n    pass\n\nclass ProtectionRuntime:\n    def __init__(self):\n        self.realtime = RealtimeMonitor(\n            self.settings,\n            self.db,\n            callback=self._on_realtime_detection,\n            ransomware_callback=self._on_ransomware_detection,\n            correlator=self.correlator,\n        )\n\n    def _on_event(self, event):\n        return event\n\n    def _on_realtime_detection(self, report):\n        return report\n'''


def test_realtime_transform_emits_only_at_stabilized_scan_point():
    patched = transform_realtime_text(_REALTIME)
    assert patched.count(MARKER) == 1
    assert patched.count("event_callback=None") == 1
    assert patched.count("self.event_callback = event_callback") == 1
    assert patched.count("self.event_callback(str(path))") == 1
    assert patched.index("self.event_callback(str(path))") < patched.index("self.scanner.scan(path)")
    assert transform_realtime_text(patched) == patched


def test_core_transform_routes_observation_to_existing_event_pipeline():
    patched = transform_core_text(_CORE)
    assert patched.count(MARKER) == 1
    assert patched.count("event_callback=self._on_realtime_file_observed") == 1
    assert patched.count("def _on_realtime_file_observed") == 1
    assert 'category="filesystem"' in patched
    assert 'source="watchdog"' in patched
    assert "self._on_event(SecurityEvent(" in patched
    assert transform_core_text(patched) == patched


def test_realtime_transform_refuses_ambiguous_scanner_calls():
    source = _REALTIME.replace(
        "            report = self.scanner.scan(path)\n",
        "            first = self.scanner.scan(path)\n            report = self.scanner.scan(path)\n",
    )
    with pytest.raises(RuntimeError, match="exactly one scanner call"):
        transform_realtime_text(source)


def test_core_transform_refuses_unknown_construction_shape():
    source = _CORE.replace(
        "            correlator=self.correlator,\n",
        "            correlator=self.other_correlator,\n",
    )
    with pytest.raises(RuntimeError, match="construction shape"):
        transform_core_text(source)

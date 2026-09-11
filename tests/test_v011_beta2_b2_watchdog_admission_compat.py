from __future__ import annotations

from pathlib import Path

from tools.v011_beta2_b2_file_observation_compat import transform_core_text as transform_observation_core
from tools.v011_beta2_b2_watchdog_admission_compat import (
    ADMISSION_MARKER,
    BUCKET_CAPACITY,
    transform_core_text,
)


_CORE = '''class SecurityEvent:\n    def __init__(self, **kwargs):\n        self.kwargs = kwargs\n\nclass RealtimeMonitor:\n    pass\n\nclass ProtectionRuntime:\n    def __init__(self):\n        self.realtime = RealtimeMonitor(\n            self.settings,\n            self.db,\n            callback=self._on_realtime_detection,\n            ransomware_callback=self._on_ransomware_detection,\n            correlator=self.correlator,\n        )\n\n    def _on_event(self, event):\n        return event\n\n    def _on_realtime_detection(self, report):\n        return report\n'''


def _runtime_from_patched_core():
    observation = transform_observation_core(_CORE)
    patched = transform_core_text(observation)
    namespace: dict[str, object] = {}
    exec(patched, namespace, namespace)
    runtime_cls = namespace["ProtectionRuntime"]
    runtime = object.__new__(runtime_cls)
    events: list[object] = []
    runtime._on_event = lambda event: events.append(event)
    return runtime, events, patched


def test_admission_transform_is_deterministic_and_idempotent():
    observation = transform_observation_core(_CORE)
    patched = transform_core_text(observation)
    assert patched.count(ADMISSION_MARKER) == 1
    assert 'admission": "per_directory_token_bucket"' in patched
    assert '"suppressed_same_directory": suppressed_count' in patched
    assert "if not os_path.isfile(value)" in patched
    assert transform_core_text(patched) == patched


def test_same_directory_storm_is_bounded_but_other_directory_marker_survives(tmp_path: Path):
    runtime, events, _ = _runtime_from_patched_core()

    storm = tmp_path / "storm"
    storm.mkdir()
    storm_paths = []
    for index in range(32):
        path = storm / f"safe-{index:04d}.txt"
        path.write_text("benign storm\n", encoding="utf-8")
        storm_paths.append(path)

    for path in storm_paths:
        runtime._on_realtime_file_observed(str(path))

    storm_events = [event for event in events if event.kwargs.get("path", "").startswith(str(storm))]
    assert len(storm_events) <= int(BUCKET_CAPACITY)

    marker = tmp_path / "bcs-v011-beta2-b2-native-marker.tmp"
    marker.write_text("harmless marker\n", encoding="utf-8")
    runtime._on_realtime_file_observed(str(marker))

    marker_events = [event for event in events if event.kwargs.get("path") == str(marker)]
    assert len(marker_events) == 1
    assert marker_events[0].kwargs["data"]["admission"] == "per_directory_token_bucket"


def test_duplicate_path_is_deduplicated_and_missing_file_is_ignored(tmp_path: Path):
    runtime, events, _ = _runtime_from_patched_core()

    path = tmp_path / "single.tmp"
    path.write_text("safe\n", encoding="utf-8")
    runtime._on_realtime_file_observed(str(path))
    runtime._on_realtime_file_observed(str(path))
    assert [event.kwargs.get("path") for event in events].count(str(path)) == 1

    missing = tmp_path / "missing.tmp"
    runtime._on_realtime_file_observed(str(missing))
    assert all(event.kwargs.get("path") != str(missing) for event in events)

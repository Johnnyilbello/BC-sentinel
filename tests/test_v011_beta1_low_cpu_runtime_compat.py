from pathlib import Path

from tools.v011_low_cpu_runtime_compat import (
    FILE_ETW_RUNTIME_MODE,
    PROCESS_ETW_RUNTIME_MODE,
    apply_file_etw_idle_dormancy,
    apply_process_etw_idle_dormancy,
    apply_realtime_high_churn_root_patch,
)


def test_process_etw_dormancy_patch_is_idempotent_and_keeps_psutil_fallback_visible(tmp_path: Path):
    target = tmp_path / "etw_monitor.py"
    target.write_text(
        'ETW_PROVIDER_FILTER_MODE = "provider_side_event_id_v2"\n'
        'class X:\n'
        '    def status(self):\n'
        '        return {\n'
        '            "provider_filter_mode": ETW_PROVIDER_FILTER_MODE,\n'
        '        }\n'
        '    def start(self):\n'
        '        try:\n'
        '                self._capture.start()\n'
        '        except Exception as exc:\n'
        '            raise RuntimeError(str(exc))\n',
        encoding="utf-8",
    )

    first = apply_process_etw_idle_dormancy(target)
    second = apply_process_etw_idle_dormancy(target)
    text = target.read_text(encoding="utf-8")

    assert first["patched"] is True
    assert second["patched"] is False
    assert first["mode"] == PROCESS_ETW_RUNTIME_MODE == "dormant_idle_beta1"
    assert "PROCESS_ETW_CONTINUOUS = False" in text
    assert "self._stop_capture(self._capture)" in text
    assert "self._capture = None" in text
    assert '"process_runtime_mode": PROCESS_ETW_RUNTIME_MODE' in text
    assert '"process_tracking": bool(self.running and self._capture is not None)' in text
    assert '"process_fallback": "psutil_process_monitor"' in text
    assert '"provider_filter_mode": ETW_PROVIDER_FILTER_MODE' in text


def test_file_etw_dormancy_patch_is_idempotent_and_preserves_provider_shape(tmp_path: Path):
    target = tmp_path / "etw_monitor.py"
    target.write_text(
        'ETW_PROVIDER_FILTER_MODE = "provider_side_event_id_v2"\n'
        'class X:\n'
        '    def status(self):\n'
        '        return {\n'
        '            "provider_filter_mode": ETW_PROVIDER_FILTER_MODE,\n'
        '        }\n'
        '    def start(self):\n'
        '        try:\n'
        '                self._file_capture.start()\n'
        '        except Exception as exc:\n'
        '            raise RuntimeError(str(exc))\n',
        encoding="utf-8",
    )

    first = apply_file_etw_idle_dormancy(target)
    second = apply_file_etw_idle_dormancy(target)
    text = target.read_text(encoding="utf-8")

    assert first["patched"] is True
    assert second["patched"] is False
    assert first["mode"] == FILE_ETW_RUNTIME_MODE == "dormant_idle_beta1"
    assert "FILE_ETW_CONTINUOUS = False" in text
    assert "self._stop_capture(self._file_capture)" in text
    assert "self._file_capture = None" in text
    assert '"file_runtime_mode": FILE_ETW_RUNTIME_MODE' in text
    assert '"provider_filter_mode": ETW_PROVIDER_FILTER_MODE' in text


def test_realtime_high_churn_patch_keeps_watchdog_but_changes_recursion_policy(tmp_path: Path):
    target = tmp_path / "realtime.py"
    target.write_text(
        'from __future__ import annotations\n\n'
        'import json\n'
        'from pathlib import Path\n'
        'from .path_security import canonical_path\n\n'
        'class RealtimeMonitor:\n'
        '    def start(self):\n'
        '        for raw in self.settings.monitored_dirs:\n'
        '            p = Path(raw)\n'
        '            if p.exists() and p.is_dir():\n'
        '                try:\n'
        '                    obs.schedule(handler, str(p), recursive=True)\n'
        '                except OSError:\n'
        '                    continue\n',
        encoding="utf-8",
    )

    first = apply_realtime_high_churn_root_patch(target)
    second = apply_realtime_high_churn_root_patch(target)
    text = target.read_text(encoding="utf-8")

    assert first["patched"] is True
    assert second["patched"] is False
    assert "import os" in text
    assert "def _watchdog_recursive_for_root(path: Path) -> bool:" in text
    assert 'os.getenv("TEMP", "")' in text
    assert 'os.getenv("APPDATA", "")' in text
    assert "recursive=_watchdog_recursive_for_root(p)" in text
    assert "recursive=True" not in text

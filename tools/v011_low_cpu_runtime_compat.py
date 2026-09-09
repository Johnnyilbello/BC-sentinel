from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ETW_TARGET = ROOT / "sentinel" / "etw_monitor.py"
REALTIME_TARGET = ROOT / "sentinel" / "realtime.py"

PROCESS_ETW_RUNTIME_MODE = "dormant_idle_beta1"
PROCESS_ETW_CONTINUOUS = False
FILE_ETW_RUNTIME_MODE = "dormant_idle_beta1"
FILE_ETW_CONTINUOUS = False


def apply_process_etw_idle_dormancy(path: Path = ETW_TARGET) -> dict[str, object]:
    if not path.is_file():
        raise FileNotFoundError(f"etw_monitor.py missing: {path}")

    text = path.read_text(encoding="utf-8")
    patched = False

    if 'PROCESS_ETW_RUNTIME_MODE = "dormant_idle_beta1"' not in text:
        anchor = 'ETW_PROVIDER_FILTER_MODE = "provider_side_event_id_v2"\n'
        if text.count(anchor) != 1:
            raise RuntimeError("Unexpected ETW constants shape; refusing low-CPU Process ETW patch")
        text = text.replace(
            anchor,
            anchor
            + 'PROCESS_ETW_RUNTIME_MODE = "dormant_idle_beta1"\n'
            + 'PROCESS_ETW_CONTINUOUS = False\n',
            1,
        )
        patched = True

    dormancy_marker = "if not PROCESS_ETW_CONTINUOUS:\n                    self._stop_capture(self._capture)"
    if dormancy_marker not in text:
        anchor = "                self._capture.start()\n"
        if text.count(anchor) != 1:
            raise RuntimeError("Unexpected Process ETW startup shape; refusing low-CPU patch")
        text = text.replace(
            anchor,
            anchor
            + "                if not PROCESS_ETW_CONTINUOUS:\n"
            + "                    self._stop_capture(self._capture)\n"
            + "                    self._capture = None\n",
            1,
        )
        patched = True

    status_marker = '"process_runtime_mode": PROCESS_ETW_RUNTIME_MODE'
    if status_marker not in text:
        anchor = '            "provider_filter_mode": ETW_PROVIDER_FILTER_MODE,\n'
        if text.count(anchor) != 1:
            raise RuntimeError("Unexpected ETW status shape; refusing low-CPU Process ETW status patch")
        text = text.replace(
            anchor,
            anchor
            + '            "process_runtime_mode": PROCESS_ETW_RUNTIME_MODE,\n'
            + '            "process_tracking": bool(self.running and self._capture is not None),\n'
            + '            "process_fallback": "psutil_process_monitor",\n',
            1,
        )
        patched = True

    if patched:
        path.write_text(text, encoding="utf-8")

    verify = path.read_text(encoding="utf-8")
    required = (
        'PROCESS_ETW_RUNTIME_MODE = "dormant_idle_beta1"',
        'PROCESS_ETW_CONTINUOUS = False',
        dormancy_marker,
        status_marker,
        '"process_tracking": bool(self.running and self._capture is not None)',
        '"process_fallback": "psutil_process_monitor"',
    )
    missing = [marker for marker in required if marker not in verify]
    if missing:
        raise RuntimeError("Process ETW low-CPU patch incomplete: " + "; ".join(missing))

    return {"patched": patched, "path": str(path), "mode": PROCESS_ETW_RUNTIME_MODE}


def apply_file_etw_idle_dormancy(path: Path = ETW_TARGET) -> dict[str, object]:
    if not path.is_file():
        raise FileNotFoundError(f"etw_monitor.py missing: {path}")

    text = path.read_text(encoding="utf-8")
    patched = False

    if 'FILE_ETW_RUNTIME_MODE = "dormant_idle_beta1"' not in text:
        anchor = 'ETW_PROVIDER_FILTER_MODE = "provider_side_event_id_v2"\n'
        if text.count(anchor) != 1:
            raise RuntimeError("Unexpected ETW constants shape; refusing low-CPU File ETW patch")
        text = text.replace(
            anchor,
            anchor
            + 'FILE_ETW_RUNTIME_MODE = "dormant_idle_beta1"\n'
            + 'FILE_ETW_CONTINUOUS = False\n',
            1,
        )
        patched = True

    dormancy_marker = "if not FILE_ETW_CONTINUOUS:\n                    self._stop_capture(self._file_capture)"
    if dormancy_marker not in text:
        anchor = "                self._file_capture.start()\n"
        if text.count(anchor) != 1:
            raise RuntimeError("Unexpected Kernel-File ETW startup shape; refusing low-CPU patch")
        text = text.replace(
            anchor,
            anchor
            + "                if not FILE_ETW_CONTINUOUS:\n"
            + "                    self._stop_capture(self._file_capture)\n"
            + "                    self._file_capture = None\n",
            1,
        )
        patched = True

    status_marker = '"file_runtime_mode": FILE_ETW_RUNTIME_MODE'
    if status_marker not in text:
        anchor = '            "provider_filter_mode": ETW_PROVIDER_FILTER_MODE,\n'
        if text.count(anchor) != 1:
            raise RuntimeError("Unexpected ETW status shape; refusing low-CPU status patch")
        text = text.replace(
            anchor,
            anchor
            + '            "file_runtime_mode": FILE_ETW_RUNTIME_MODE,\n'
            + '            "file_tracking": bool(self.running and self._file_capture is not None),\n',
            1,
        )
        patched = True

    if patched:
        path.write_text(text, encoding="utf-8")

    verify = path.read_text(encoding="utf-8")
    required = (
        'FILE_ETW_RUNTIME_MODE = "dormant_idle_beta1"',
        'FILE_ETW_CONTINUOUS = False',
        dormancy_marker,
        status_marker,
        '"file_tracking": bool(self.running and self._file_capture is not None)',
    )
    missing = [marker for marker in required if marker not in verify]
    if missing:
        raise RuntimeError("File ETW low-CPU patch incomplete: " + "; ".join(missing))

    return {"patched": patched, "path": str(path), "mode": FILE_ETW_RUNTIME_MODE}


def apply_realtime_high_churn_root_patch(path: Path = REALTIME_TARGET) -> dict[str, object]:
    if not path.is_file():
        raise FileNotFoundError(f"realtime.py missing: {path}")

    text = path.read_text(encoding="utf-8")
    patched = False

    if "import os\n" not in text:
        anchor = "import json\n"
        if text.count(anchor) != 1:
            raise RuntimeError("Unexpected realtime imports; refusing high-churn watcher patch")
        text = text.replace(anchor, anchor + "import os\n", 1)
        patched = True

    helper_marker = "def _watchdog_recursive_for_root(path: Path) -> bool:"
    if helper_marker not in text:
        anchor = "\n\nclass RealtimeMonitor:\n"
        if text.count(anchor) != 1:
            raise RuntimeError("Unexpected RealtimeMonitor class shape; refusing watcher patch")
        helper = (
            "\n\ndef _watchdog_recursive_for_root(path: Path) -> bool:\n"
            "    try:\n"
            "        target = canonical_path(path)\n"
            "    except Exception:\n"
            "        return True\n"
            "    high_churn = set()\n"
            "    for raw in (os.getenv(\"TEMP\", \"\"), os.getenv(\"APPDATA\", \"\")):\n"
            "        if not raw:\n"
            "            continue\n"
            "        try:\n"
            "            high_churn.add(canonical_path(Path(raw)))\n"
            "        except Exception:\n"
            "            continue\n"
            "    return target not in high_churn\n"
        )
        text = text.replace(anchor, helper + anchor, 1)
        patched = True

    old_schedule = "                    obs.schedule(handler, str(p), recursive=True)\n"
    new_schedule = "                    obs.schedule(handler, str(p), recursive=_watchdog_recursive_for_root(p))\n"
    if new_schedule not in text:
        if text.count(old_schedule) != 1:
            raise RuntimeError("Unexpected watchdog scheduling shape; refusing high-churn watcher patch")
        text = text.replace(old_schedule, new_schedule, 1)
        patched = True

    if patched:
        path.write_text(text, encoding="utf-8")

    verify = path.read_text(encoding="utf-8")
    required = (
        helper_marker,
        'os.getenv("TEMP", "")',
        'os.getenv("APPDATA", "")',
        "recursive=_watchdog_recursive_for_root(p)",
    )
    missing = [marker for marker in required if marker not in verify]
    if missing:
        raise RuntimeError("Realtime high-churn watcher patch incomplete: " + "; ".join(missing))

    return {"patched": patched, "path": str(path)}


def main() -> int:
    process_etw = apply_process_etw_idle_dormancy()
    file_etw = apply_file_etw_idle_dormancy()
    realtime = apply_realtime_high_churn_root_patch()
    if process_etw["patched"]:
        print("v0.11 low-CPU runtime: continuous Process ETW moved to dormant-idle mode; psutil fallback remains active")
    else:
        print("v0.11 low-CPU runtime: Process ETW dormant-idle mode already canonical")
    if file_etw["patched"]:
        print("v0.11 low-CPU runtime: continuous File ETW moved to dormant-idle mode")
    else:
        print("v0.11 low-CPU runtime: File ETW dormant-idle mode already canonical")
    if realtime["patched"]:
        print("v0.11 low-CPU runtime: Temp/AppData watchdog roots limited to non-recursive monitoring")
    else:
        print("v0.11 low-CPU runtime: high-churn watchdog policy already canonical")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

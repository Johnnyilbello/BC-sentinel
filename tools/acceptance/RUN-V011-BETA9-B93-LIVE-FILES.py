from __future__ import annotations

"""Generate B9-3 harmless live local file-activity controls.

This is an acceptance harness, not product runtime authority. It mutates only
files that it creates inside dedicated temporary directories, exports aggregate
counts only, and deterministically removes the temporary directories afterward.
"""

import argparse
import hashlib
import json
import math
import shutil
import tempfile
import threading
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

SCHEMA = "bc-sentinel-beta9-ransomware-live-controls-v1"
SOURCE = "LOCAL_TEMP_FILE_ACTIVITY_LIVE_CONTROLS"
BOUNDARIES = {
    "local_only": True,
    "explicit_opt_in_required": True,
    "dedicated_temp_directory_only": True,
    "acceptance_harness_file_mutation": True,
    "user_file_access": False,
    "file_content_collected": False,
    "absolute_paths_exported": False,
    "personal_data_collected": False,
    "remote_access": False,
    "real_malware_executed": False,
    "product_file_write_authority": False,
    "product_file_rename_authority": False,
    "product_file_delete_authority": False,
    "remediation_authority": False,
    "automatic_quarantine": False,
    "privileged_system_mutation": False,
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    raw = -sum((count / len(data)) * math.log2(count / len(data)) for count in counts.values())
    return raw / 8.0


def _deterministic_high_entropy(seed: str, length: int = 4096) -> bytes:
    chunks: list[bytes] = []
    counter = 0
    while sum(len(chunk) for chunk in chunks) < length:
        chunks.append(hashlib.sha256(f"{seed}:{counter}".encode()).digest())
        counter += 1
    return b"".join(chunks)[:length]


class _Collector(FileSystemEventHandler):
    def __init__(self) -> None:
        super().__init__()
        self._lock = threading.Lock()
        self._writes: set[str] = set()
        self._renames: set[str] = set()

    def on_modified(self, event) -> None:  # type: ignore[override]
        if getattr(event, "is_directory", False):
            return
        with self._lock:
            self._writes.add(str(event.src_path))

    def on_created(self, event) -> None:  # type: ignore[override]
        if getattr(event, "is_directory", False):
            return
        with self._lock:
            self._writes.add(str(event.src_path))

    def on_moved(self, event) -> None:  # type: ignore[override]
        if getattr(event, "is_directory", False):
            return
        with self._lock:
            self._renames.add(str(event.dest_path))

    def counts(self) -> tuple[int, int]:
        with self._lock:
            return len(self._writes), len(self._renames)


def _wait_for_counts(collector: _Collector, *, writes: int, renames: int, timeout: float = 6.0) -> tuple[int, int]:
    deadline = time.monotonic() + timeout
    latest = collector.counts()
    while time.monotonic() < deadline:
        latest = collector.counts()
        if latest[0] >= writes and latest[1] >= renames:
            return latest
        time.sleep(0.05)
    return collector.counts()


def _run_control(control_id: str) -> dict:
    if control_id not in {
        "positive-ransomware-like",
        "administrative-backup-like",
        "benign-save",
    }:
        raise ValueError("unknown control")

    bulk = control_id != "benign-save"
    file_count = 24 if bulk else 2
    rename_target = 18 if bulk else 0
    initial = b"A" * 4096
    rewritten = _deterministic_high_entropy(control_id) if bulk else b"B" * 4096
    entropy_delta = max(0.0, _entropy(rewritten) - _entropy(initial))
    root = Path(tempfile.mkdtemp(prefix="BCSentinel-b93-"))
    observer: Observer | None = None
    started_at = ""
    completed_at = ""
    write_count = 0
    rename_count = 0
    try:
        paths: list[Path] = []
        for index in range(file_count):
            name = "canary.txt" if index == 0 and control_id == "positive-ransomware-like" else f"sample-{index:02d}.txt"
            path = root / name
            path.write_bytes(initial)
            paths.append(path)

        collector = _Collector()
        observer = Observer()
        observer.schedule(collector, str(root), recursive=False)
        observer.start()
        time.sleep(0.30)
        started_at = _utc_now()

        if bulk:
            for index, path in enumerate(paths):
                path.write_bytes(rewritten)
                if index < rename_target:
                    renamed = path.with_suffix(".b93")
                    path.rename(renamed)
                time.sleep(0.012)
        else:
            for path in paths:
                path.write_bytes(rewritten)
                time.sleep(0.025)

        write_count, rename_count = _wait_for_counts(
            collector,
            writes=file_count,
            renames=rename_target,
        )
        completed_at = _utc_now()
    finally:
        if observer is not None:
            observer.stop()
            observer.join(timeout=5.0)
        shutil.rmtree(root, ignore_errors=False)

    cleanup_state = "CLEAN" if not root.exists() else "FAILED"
    administrative = control_id == "administrative-backup-like"
    return {
        "control_id": control_id,
        "live_observation": True,
        "sandbox_scope": "DEDICATED_TEMP_DIRECTORY",
        "observer_backend": "WATCHDOG_LOCAL_FILESYSTEM",
        "write_event_count": int(write_count),
        "rename_event_count": int(rename_count),
        "entropy_delta": round(float(entropy_delta), 6),
        "extension_changed": bool(bulk),
        "canary_touched": control_id == "positive-ransomware-like",
        "known_backup_workflow": administrative,
        "user_initiated_bulk_operation": administrative,
        "started_at_utc": started_at,
        "completed_at_utc": completed_at,
        "cleanup_state": cleanup_state,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--confirm-live-controls", action="store_true")
    args = parser.parse_args()
    if not args.confirm_live_controls:
        raise SystemExit("Explicit B9-3 live-control confirmation is required.")

    controls = [_run_control(control_id) for control_id in (
        "positive-ransomware-like",
        "administrative-backup-like",
        "benign-save",
    )]
    payload = {
        "schema": SCHEMA,
        "source": SOURCE,
        "controls": controls,
        "boundaries": dict(BOUNDARIES),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, sort_keys=True, indent=2), encoding="utf-8")
    safe = {
        "controls": [
            {
                "control_id": row["control_id"],
                "write_event_count": row["write_event_count"],
                "rename_event_count": row["rename_event_count"],
                "cleanup_state": row["cleanup_state"],
            }
            for row in controls
        ],
        "personal_data_collected": False,
        "absolute_paths_exported": False,
    }
    print(json.dumps(safe, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

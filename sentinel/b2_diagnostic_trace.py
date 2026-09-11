from __future__ import annotations

from collections import deque
import json
import os
from pathlib import Path
from threading import RLock, current_thread
from time import time
from typing import Any

TRACE_PROFILE = "v0.11.0-beta.2-marker-trace-v1"
TRACE_MAX_RECORDS = 256
TRACE_FILENAME = "b2-marker-trace.jsonl"
_MARKER_TOKENS = ("bcs-v011", "bc-sentinel-v011")
_LOCK = RLock()
_RECORDS: deque[dict[str, Any]] = deque(maxlen=TRACE_MAX_RECORDS)
_SEQUENCE = 0


def _clean(value: Any, *, maximum: int = 1024) -> Any:
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, (list, tuple)):
        return [_clean(item, maximum=maximum) for item in list(value)[:32]]
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in list(value.items())[:32]:
            out[str(key)[:128]] = _clean(item, maximum=maximum)
        return out
    text = str(value)
    return text if len(text) <= maximum else text[:maximum] + "..."


def normalize_path(raw: str) -> str:
    value = str(raw or "")
    if not value:
        return ""
    try:
        return os.path.normcase(os.path.abspath(os.path.expandvars(os.path.expanduser(value))))
    except Exception:
        return os.path.normcase(value)


def is_diagnostic_marker(path: str) -> bool:
    value = str(path or "").casefold()
    if not value:
        return False
    try:
        name = Path(value).name.casefold()
    except Exception:
        name = value
    return any(token in name or token in value for token in _MARKER_TOKENS)


def _trace_file() -> Path:
    base = str(os.getenv("PROGRAMDATA", "") or "").strip()
    if not base:
        base = str(Path.home())
    return Path(base) / "BC Sentinel" / "Logs" / TRACE_FILENAME


def _append_file(record: dict[str, Any]) -> None:
    try:
        target = _trace_file()
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() and target.stat().st_size > 1_500_000:
            rotated = target.with_suffix(target.suffix + ".1")
            try:
                rotated.unlink(missing_ok=True)
                target.replace(rotated)
            except Exception:
                pass
        with target.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
    except Exception:
        pass


def trace_marker(stage: str, *, path: str = "", force: bool = False, **fields: Any) -> dict[str, Any] | None:
    if not force and not is_diagnostic_marker(path):
        return None
    global _SEQUENCE
    with _LOCK:
        _SEQUENCE += 1
        record = {
            "profile": TRACE_PROFILE,
            "seq": _SEQUENCE,
            "ts": round(time(), 6),
            "stage": str(stage or "unknown")[:128],
            "path": str(path or ""),
            "normalized_path": normalize_path(path),
            "pid": os.getpid(),
            "thread": current_thread().name,
            "fields": {str(k)[:128]: _clean(v) for k, v in fields.items()},
        }
        _RECORDS.append(record)
        _append_file(record)
        return dict(record)


def trace_snapshot(limit: int = 128) -> list[dict[str, Any]]:
    bounded = max(1, min(int(limit), TRACE_MAX_RECORDS))
    with _LOCK:
        return [dict(item) for item in list(_RECORDS)[-bounded:]]


def trace_metadata() -> dict[str, Any]:
    with _LOCK:
        return {
            "profile": TRACE_PROFILE,
            "buffered": len(_RECORDS),
            "capacity": TRACE_MAX_RECORDS,
            "last_sequence": _SEQUENCE,
            "jsonl_path": str(_trace_file()),
            "marker_tokens": list(_MARKER_TOKENS),
            "marker_only": True,
        }


def clear_trace() -> None:
    global _SEQUENCE
    with _LOCK:
        _RECORDS.clear()
        _SEQUENCE = 0

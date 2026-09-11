from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import tempfile
from time import sleep, time
from typing import Any

from tools.v011_beta2_b2_live_acceptance import ProductionClient

PROFILE = "v0.11.0-beta.2-path-alias-probe-v1"


def _long_path(value: str) -> str:
    text = str(value or "")
    if not text or os.name != "nt":
        return text
    try:
        kernel32 = ctypes.windll.kernel32
        fn = kernel32.GetLongPathNameW
        fn.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_ulong]
        fn.restype = ctypes.c_ulong
        needed = int(fn(text, None, 0))
        if needed <= 0:
            return text
        buf = ctypes.create_unicode_buffer(needed + 1)
        written = int(fn(text, buf, len(buf)))
        return buf.value if written > 0 else text
    except Exception:
        return text


def _short_path(value: str) -> str:
    text = str(value or "")
    if not text or os.name != "nt":
        return text
    try:
        kernel32 = ctypes.windll.kernel32
        fn = kernel32.GetShortPathNameW
        fn.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_ulong]
        fn.restype = ctypes.c_ulong
        needed = int(fn(text, None, 0))
        if needed <= 0:
            return text
        buf = ctypes.create_unicode_buffer(needed + 1)
        written = int(fn(text, buf, len(buf)))
        return buf.value if written > 0 else text
    except Exception:
        return text


def _counter(value: Any) -> int:
    try:
        return int(value or 0)
    except Exception:
        return 0


def _items(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, dict):
        return []
    raw = value.get("items")
    return [item for item in raw if isinstance(item, dict)] if isinstance(raw, list) else []


def _match_marker(items: list[dict[str, Any]], marker_name: str) -> list[dict[str, Any]]:
    needle = marker_name.casefold()
    out: list[dict[str, Any]] = []
    for item in items:
        try:
            blob = json.dumps(item, ensure_ascii=False, sort_keys=True).casefold()
        except Exception:
            blob = str(item).casefold()
        if needle in blob:
            out.append(item)
    return out


def run(output: Path, *, poll_seconds: float = 8.0) -> int:
    client = ProductionClient()
    before = client.call("edr_status")
    started = time()

    temp_root_raw = tempfile.gettempdir()
    token = f"{os.getpid()}-{int(started * 1000)}"
    marker = Path(temp_root_raw) / f"bcs-v011-b2-alias-{token}.tmp"
    marker.write_text("BC Sentinel harmless Windows path-alias diagnostic marker\n", encoding="utf-8")

    raw_path = str(marker)
    long_path = _long_path(raw_path)
    short_path = _short_path(long_path)
    aliases: list[str] = []
    for value in (raw_path, long_path, short_path):
        if value and value.casefold() not in {item.casefold() for item in aliases}:
            aliases.append(value)

    hunts: dict[str, dict[str, Any]] = {
        alias: {"observed": False, "event_ids": [], "paths": []}
        for alias in aliases
    }

    deadline = time() + max(1.0, float(poll_seconds))
    latest_file_items: list[dict[str, Any]] = []
    latest_all_items: list[dict[str, Any]] = []
    try:
        while time() < deadline:
            for alias, record in hunts.items():
                if record["observed"]:
                    continue
                page = client.call("edr_hunt", {"indicator": alias, "kind": "path", "limit": 20})
                found = _items(page)
                if found:
                    record["observed"] = True
                    record["event_ids"] = [str(item.get("event_id") or "") for item in found]
                    record["paths"] = [str(item.get("path") or "") for item in found]

            file_page = client.call(
                "edr_timeline",
                {"category": "file", "since": started - 1.0, "limit": 500},
            )
            all_page = client.call(
                "edr_timeline",
                {"since": started - 1.0, "limit": 500},
            )
            latest_file_items = _items(file_page)
            latest_all_items = _items(all_page)
            file_matches = _match_marker(latest_file_items, marker.name)
            all_matches = _match_marker(latest_all_items, marker.name)
            if any(record["observed"] for record in hunts.values()) or file_matches or all_matches:
                break
            sleep(0.35)

        after = client.call("edr_status")
        file_matches = _match_marker(latest_file_items, marker.name)
        all_matches = _match_marker(latest_all_items, marker.name)

        raw_observed = bool(hunts.get(raw_path, {}).get("observed"))
        long_observed = bool(hunts.get(long_path, {}).get("observed"))
        if raw_observed:
            diagnosis = "raw_temp_path_hunt_works"
        elif long_path.casefold() != raw_path.casefold() and long_observed:
            diagnosis = "windows_short_vs_long_path_hunt_mismatch_confirmed"
        elif file_matches:
            diagnosis = "file_event_stored_but_exact_path_hunt_mismatch"
        elif all_matches:
            diagnosis = "marker_stored_under_non_file_category"
        elif _counter(after.get("service_ingested")) > _counter(before.get("service_ingested")):
            diagnosis = "service_ingested_other_events_but_marker_not_observed"
        else:
            diagnosis = "interactive_temp_marker_not_reaching_service_owned_edr"

        result = {
            "profile": PROFILE,
            "passed": True,
            "diagnostic_only": True,
            "client_surface": client.surface,
            "temp_root_raw": temp_root_raw,
            "marker_name": marker.name,
            "paths": {
                "raw": raw_path,
                "long": long_path,
                "short": short_path,
                "aliases_differ": len(aliases) > 1,
            },
            "status": {
                "service_ingested_before": _counter(before.get("service_ingested")),
                "service_ingested_after": _counter(after.get("service_ingested")),
                "service_ingested_delta": _counter(after.get("service_ingested")) - _counter(before.get("service_ingested")),
                "service_ingest_errors_before": _counter(before.get("service_ingest_errors")),
                "service_ingest_errors_after": _counter(after.get("service_ingest_errors")),
            },
            "hunts": hunts,
            "file_timeline_count": len(latest_file_items),
            "all_timeline_count": len(latest_all_items),
            "file_marker_matches": [
                {
                    "event_id": str(item.get("event_id") or ""),
                    "category": str(item.get("category") or ""),
                    "path": str(item.get("path") or ""),
                    "source": str(item.get("source") or ""),
                }
                for item in file_matches[:20]
            ],
            "all_marker_matches": [
                {
                    "event_id": str(item.get("event_id") or ""),
                    "category": str(item.get("category") or ""),
                    "path": str(item.get("path") or ""),
                    "source": str(item.get("source") or ""),
                }
                for item in all_matches[:20]
            ],
            "diagnosis": diagnosis,
        }
        output.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    finally:
        try:
            marker.unlink(missing_ok=True)
        except Exception:
            pass


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="BC Sentinel B2 Windows short/long path alias probe")
    parser.add_argument("--output", default="acceptance-v011-beta2-b2-path-alias-probe.json")
    parser.add_argument("--poll-seconds", type=float, default=8.0)
    args = parser.parse_args()
    return run(Path(args.output), poll_seconds=args.poll_seconds)


if __name__ == "__main__":
    raise SystemExit(main())

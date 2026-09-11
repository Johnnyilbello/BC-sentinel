from __future__ import annotations

import argparse
import getpass
import json
import os
from pathlib import Path
import tempfile
from time import sleep, time
from typing import Any

from tools.v011_beta2_b2_live_acceptance import ProductionClient

PROFILE = "v0.11.0-beta.2-native-ingestion-probe-v1"


def _status_counter(status: dict[str, Any], key: str) -> int:
    try:
        return int(status.get(key) or 0)
    except Exception:
        return 0


def _norm_key(path: Path) -> str:
    try:
        return os.path.normcase(os.path.abspath(str(path)))
    except Exception:
        return str(path).casefold()


def _candidate_roots() -> list[tuple[str, Path]]:
    home = Path.home()
    raw: list[tuple[str, Path]] = [
        ("temp", Path(tempfile.gettempdir())),
        ("downloads", home / "Downloads"),
        ("desktop", home / "Desktop"),
        ("documents", home / "Documents"),
    ]
    appdata = os.getenv("APPDATA", "").strip()
    if appdata:
        raw.append(("appdata", Path(appdata)))

    seen: set[str] = set()
    out: list[tuple[str, Path]] = []
    for label, root in raw:
        key = _norm_key(root)
        if not key or key in seen:
            continue
        seen.add(key)
        out.append((label, root))
    return out


def _timeline_matches(items: list[Any], marker_name: str) -> list[dict[str, Any]]:
    needle = marker_name.casefold()
    matches: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        try:
            serialized = json.dumps(item, ensure_ascii=False, sort_keys=True).casefold()
        except Exception:
            serialized = str(item).casefold()
        if needle in serialized:
            matches.append(item)
    return matches


def run(output: Path, *, poll_seconds: float = 8.0) -> int:
    client = ProductionClient()
    status_before = client.call("edr_status")
    started = time()
    token = f"{os.getpid()}-{int(started * 1000)}"
    records: dict[str, dict[str, Any]] = {}

    try:
        for label, root in _candidate_roots():
            record: dict[str, Any] = {
                "label": label,
                "root": str(root),
                "root_exists": bool(root.is_dir()),
                "write_ok": False,
                "write_error": "",
                "marker_path": "",
                "hunt_observed": False,
                "hunt_event_ids": [],
                "timeline_match_count": 0,
                "timeline_paths": [],
            }
            records[label] = record
            if not root.is_dir():
                record["write_error"] = "root_missing"
                continue
            marker = root / f"bcs-v011-b2-probe-{label}-{token}.tmp"
            record["marker_path"] = str(marker)
            try:
                marker.write_text(
                    "BC Sentinel harmless native-ingestion diagnostic marker\n",
                    encoding="utf-8",
                )
                record["write_ok"] = True
            except Exception as exc:
                record["write_error"] = f"{type(exc).__name__}: {exc}"

        deadline = time() + max(1.0, float(poll_seconds))
        while time() < deadline:
            pending = False
            for record in records.values():
                if not record.get("write_ok") or record.get("hunt_observed"):
                    continue
                pending = True
                hunt = client.call(
                    "edr_hunt",
                    {"indicator": str(record["marker_path"]), "kind": "path", "limit": 20},
                )
                items = hunt.get("items")
                if isinstance(items, list) and items:
                    record["hunt_observed"] = True
                    record["hunt_event_ids"] = [
                        str(item.get("event_id") or "")
                        for item in items
                        if isinstance(item, dict)
                    ]
            if not pending:
                break
            sleep(0.35)

        status_after = client.call("edr_status")
        timeline = client.call(
            "edr_timeline",
            {"category": "file", "since": started - 1.0, "limit": 500},
        )
        timeline_items = timeline.get("items")
        if not isinstance(timeline_items, list):
            timeline_items = []

        for record in records.values():
            marker_path = str(record.get("marker_path") or "")
            if not marker_path:
                continue
            marker_name = Path(marker_path).name
            matches = _timeline_matches(timeline_items, marker_name)
            record["timeline_match_count"] = len(matches)
            record["timeline_paths"] = [
                str(item.get("path") or "") for item in matches[:10] if isinstance(item, dict)
            ]
            if record.get("hunt_observed"):
                record["classification"] = "hunt_visible"
            elif matches:
                record["classification"] = "stored_but_exact_hunt_miss"
            elif record.get("write_ok"):
                record["classification"] = "no_file_telemetry_observed"
            else:
                record["classification"] = "marker_not_written"

        ingested_before = _status_counter(status_before, "service_ingested")
        ingested_after = _status_counter(status_after, "service_ingested")
        errors_before = _status_counter(status_before, "service_ingest_errors")
        errors_after = _status_counter(status_after, "service_ingest_errors")

        writable = [r for r in records.values() if r.get("write_ok")]
        visible = [r for r in writable if r.get("hunt_observed")]
        stored_only = [
            r for r in writable
            if (not r.get("hunt_observed")) and int(r.get("timeline_match_count") or 0) > 0
        ]
        invisible = [
            r for r in writable
            if (not r.get("hunt_observed")) and int(r.get("timeline_match_count") or 0) == 0
        ]

        temp_record = records.get("temp", {})
        if bool(temp_record.get("hunt_observed")):
            diagnosis = "interactive_temp_ingestion_and_hunt_work"
        elif int(temp_record.get("timeline_match_count") or 0) > 0:
            diagnosis = "interactive_temp_stored_but_path_hunt_mismatch"
        elif visible:
            diagnosis = "interactive_temp_root_not_covered_while_other_user_roots_are_covered"
        elif stored_only:
            diagnosis = "file_events_reach_edr_but_exact_path_hunt_is_not_reliable"
        elif writable and (ingested_after - ingested_before) <= 0:
            diagnosis = "no_probe_file_events_reached_service_owned_edr"
        elif invisible:
            diagnosis = "probe_events_not_identifiable_in_recent_file_telemetry"
        else:
            diagnosis = "probe_inconclusive"

        result = {
            "profile": PROFILE,
            "passed": True,
            "diagnostic_only": True,
            "production_client_surface": client.surface,
            "identity": {
                "username": getpass.getuser(),
                "home": str(Path.home()),
                "temp": tempfile.gettempdir(),
                "appdata": os.getenv("APPDATA", ""),
            },
            "status": {
                "service_ingested_before": ingested_before,
                "service_ingested_after": ingested_after,
                "service_ingested_delta": ingested_after - ingested_before,
                "service_ingest_errors_before": errors_before,
                "service_ingest_errors_after": errors_after,
                "service_ingest_errors_delta": errors_after - errors_before,
                "service_owned_store": bool(status_after.get("service_owned_store")),
                "authenticated_ipc_required": bool(status_after.get("authenticated_ipc_required")),
            },
            "recent_file_timeline_count": len(timeline_items),
            "records": records,
            "diagnosis": diagnosis,
        }
        output.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    finally:
        for record in records.values():
            marker_path = str(record.get("marker_path") or "")
            if not marker_path:
                continue
            try:
                Path(marker_path).unlink(missing_ok=True)
            except Exception:
                pass


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel v0.11 Beta2 native file-ingestion diagnostic probe")
    parser.add_argument(
        "--output",
        default="acceptance-v011-beta2-b2-native-ingestion-probe.json",
    )
    parser.add_argument("--poll-seconds", type=float, default=8.0)
    args = parser.parse_args()
    return run(Path(args.output), poll_seconds=args.poll_seconds)


if __name__ == "__main__":
    raise SystemExit(main())

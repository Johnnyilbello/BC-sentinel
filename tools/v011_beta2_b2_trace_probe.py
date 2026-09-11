from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import tempfile
from time import sleep, time
from typing import Any

from tools.v011_beta2_b2_live_acceptance import ProductionClient

PROFILE = "v0.11.0-beta.2-marker-trace-probe-v1"
EXPECTED_STAGES = (
    "WATCHDOG_EVENT_RECEIVED",
    "WATCHDOG_EVENT_QUEUED",
    "WATCHDOG_FORWARD_BEGIN",
    "WATCHDOG_FORWARD_END",
    "FILE_STABLE_CALLBACK_ENTER",
    "OBSERVATION_CALLBACK_ENTER",
    "ADMISSION_ACCEPT",
    "SECURITY_EVENT_CREATED",
    "EDR_BRIDGE_INGEST_ENTER",
    "EDR_ADAPTER_CONVERTED",
    "EDR_PIPELINE_RETURN",
    "EDR_BRIDGE_INGEST_RESULT",
    "SECURITY_EVENT_PIPELINE_RETURN",
    "FILE_STABLE_CALLBACK_RETURN",
    "EDR_HUNT_QUERY",
    "EDR_HUNT_RESULT",
)


def _roots() -> list[tuple[str, Path]]:
    home = Path.home()
    raw = [
        ("temp", Path(tempfile.gettempdir())),
        ("downloads", home / "Downloads"),
        ("desktop", home / "Desktop"),
        ("documents", home / "Documents"),
    ]
    appdata = str(os.getenv("APPDATA", "") or "").strip()
    if appdata:
        raw.append(("appdata", Path(appdata)))
    seen: set[str] = set()
    out: list[tuple[str, Path]] = []
    for label, root in raw:
        try:
            key = os.path.normcase(os.path.abspath(str(root)))
        except Exception:
            key = str(root).casefold()
        if key in seen:
            continue
        seen.add(key)
        out.append((label, root))
    return out


def _trace_items(status: dict[str, Any]) -> list[dict[str, Any]]:
    items = status.get("diagnostic_marker_trace")
    return [item for item in items if isinstance(item, dict)] if isinstance(items, list) else []


def _matches(items: list[dict[str, Any]], marker: Path) -> list[dict[str, Any]]:
    needle = marker.name.casefold()
    out = []
    for item in items:
        path = str(item.get("path") or "")
        normalized = str(item.get("normalized_path") or "")
        fields = item.get("fields") or {}
        serialized = json.dumps(fields, ensure_ascii=False, sort_keys=True) if isinstance(fields, dict) else str(fields)
        if needle in path.casefold() or needle in normalized.casefold() or needle in serialized.casefold():
            out.append(item)
    return sorted(out, key=lambda item: (int(item.get("seq") or 0), float(item.get("ts") or 0.0)))


def _hunt(client: ProductionClient, path: Path) -> dict[str, Any]:
    try:
        result = client.call("edr_hunt", {"indicator": str(path), "kind": "path", "limit": 50})
        items = result.get("items") if isinstance(result, dict) else None
        return {
            "ok": True,
            "count": len(items) if isinstance(items, list) else 0,
            "event_ids": [str(item.get("event_id") or "") for item in items[:10] if isinstance(item, dict)] if isinstance(items, list) else [],
        }
    except Exception as exc:
        return {"ok": False, "count": 0, "event_ids": [], "error": f"{type(exc).__name__}: {exc}"}


def _timeline(client: ProductionClient, path: Path, started: float) -> dict[str, Any]:
    matches: list[dict[str, Any]] = []
    per_category: dict[str, int] = {}
    for category in ("filesystem", "file"):
        try:
            result = client.call(
                "edr_timeline",
                {"category": category, "since": started - 1.0, "limit": 500},
            )
            items = result.get("items") if isinstance(result, dict) else None
            if not isinstance(items, list):
                items = []
            per_category[category] = len(items)
            needle = path.name.casefold()
            for item in items:
                if not isinstance(item, dict):
                    continue
                serialized = json.dumps(item, ensure_ascii=False, sort_keys=True).casefold()
                if needle in serialized:
                    matches.append(item)
        except Exception as exc:
            per_category[category] = -1
            per_category[f"{category}_error"] = str(exc)
    return {
        "counts": per_category,
        "match_count": len(matches),
        "event_ids": [str(item.get("event_id") or "") for item in matches[:10]],
        "paths": [str(item.get("path") or "") for item in matches[:10]],
        "categories": [str(item.get("category") or "") for item in matches[:10]],
    }


def _diagnose(trace: list[dict[str, Any]], hunt: dict[str, Any], timeline: dict[str, Any]) -> str:
    stages = [str(item.get("stage") or "") for item in trace]
    drop = next((item for item in reversed(trace) if str(item.get("stage") or "") == "ADMISSION_DROP"), None)
    if drop is not None:
        fields = drop.get("fields") or {}
        return "admission_drop:" + str(fields.get("reason") or "unknown")
    if not stages:
        return "watchdog_never_observed_marker"
    if "WATCHDOG_FORWARD_END" not in stages:
        return "watchdog_dispatch_or_coalescing_stopped_before_inner_handler"
    if "FILE_STABLE_CALLBACK_ENTER" not in stages:
        return "realtime_handler_never_reached_stabilized_callback"
    if "OBSERVATION_CALLBACK_ENTER" not in stages:
        return "realtime_event_callback_not_wired_or_callback_failed_before_entry"
    if "ADMISSION_ACCEPT" not in stages:
        return "watchdog_admission_did_not_accept_marker"
    if "EDR_BRIDGE_INGEST_ENTER" not in stages:
        return "security_event_did_not_reach_edr_bridge"
    if "EDR_BRIDGE_INGEST_RESULT" not in stages:
        return "edr_bridge_ingest_did_not_return"
    result_record = next((item for item in reversed(trace) if str(item.get("stage") or "") == "EDR_BRIDGE_INGEST_RESULT"), None)
    fields = (result_record or {}).get("fields") or {}
    if not bool(fields.get("stored")):
        return "edr_store_rejected_event:" + str(fields.get("disposition") or "unknown")
    if int(hunt.get("count") or 0) > 0:
        return "end_to_end_hunt_visible"
    if int(timeline.get("match_count") or 0) > 0:
        return "stored_and_timeline_visible_but_exact_path_hunt_missed"
    return "stored_reported_by_pipeline_but_not_query_visible"


def run(output: Path, *, poll_seconds: float = 12.0) -> int:
    client = ProductionClient()
    status_before = client.call("edr_status")
    started = time()
    token = f"{os.getpid()}-{int(started * 1000)}"
    records: dict[str, dict[str, Any]] = {}
    paths: dict[str, Path] = {}

    try:
        for label, root in _roots():
            rec = {
                "root": str(root),
                "root_exists": root.is_dir(),
                "write_ok": False,
                "write_error": "",
            }
            records[label] = rec
            if not root.is_dir():
                continue
            marker = root / f"bcs-v011-trace-{label}-{token}.tmp"
            paths[label] = marker
            try:
                marker.write_text("BC Sentinel harmless marker-trace probe\n", encoding="utf-8")
                rec["write_ok"] = True
                rec["path"] = str(marker)
            except Exception as exc:
                rec["write_error"] = f"{type(exc).__name__}: {exc}"

        deadline = time() + max(2.0, float(poll_seconds))
        latest_status = status_before
        while time() < deadline:
            latest_status = client.call("edr_status")
            items = _trace_items(latest_status)
            complete = True
            for label, marker in paths.items():
                trace = _matches(items, marker)
                if not any(str(item.get("stage") or "") == "EDR_BRIDGE_INGEST_RESULT" for item in trace):
                    complete = False
                    break
            if complete:
                break
            sleep(0.35)

        status_after = client.call("edr_status")
        trace_items = _trace_items(status_after)
        for label, marker in paths.items():
            trace = _matches(trace_items, marker)
            hunt = _hunt(client, marker)
            # Re-fetch after hunt so EDR_HUNT_QUERY/RESULT is included in the service trace.
            trace = _matches(_trace_items(client.call("edr_status")), marker)
            timeline = _timeline(client, marker, started)
            stages = [str(item.get("stage") or "") for item in trace]
            records[label].update({
                "trace_count": len(trace),
                "stages": stages,
                "last_stage": stages[-1] if stages else "",
                "trace": trace,
                "hunt": hunt,
                "timeline": timeline,
                "diagnosis": _diagnose(trace, hunt, timeline),
            })

        before_ingested = int(status_before.get("service_ingested") or 0)
        after_ingested = int(status_after.get("service_ingested") or 0)
        result = {
            "profile": PROFILE,
            "passed": True,
            "diagnostic_only": True,
            "expected_stages": list(EXPECTED_STAGES),
            "trace_meta": status_after.get("diagnostic_marker_trace_meta") or {},
            "service_ingested_before": before_ingested,
            "service_ingested_after": after_ingested,
            "service_ingested_delta": after_ingested - before_ingested,
            "service_ingest_errors_before": int(status_before.get("service_ingest_errors") or 0),
            "service_ingest_errors_after": int(status_after.get("service_ingest_errors") or 0),
            "records": records,
        }
        output.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        print(json.dumps(result, indent=2, ensure_ascii=False))
        print("\nB2 MARKER TRACE SUMMARY")
        for label, rec in records.items():
            if not rec.get("write_ok"):
                print(f"- {label}: marker_not_written | {rec.get('write_error') or 'root missing'}")
                continue
            print(
                f"- {label}: {rec.get('diagnosis')} | last={rec.get('last_stage') or 'NONE'} | "
                f"trace={rec.get('trace_count', 0)} | hunt={rec.get('hunt', {}).get('count', 0)} | "
                f"timeline={rec.get('timeline', {}).get('match_count', 0)}"
            )
        return 0
    finally:
        for marker in paths.values():
            try:
                marker.unlink(missing_ok=True)
            except Exception:
                pass


def main() -> int:
    parser = argparse.ArgumentParser(description="Trace harmless B2 filesystem markers across watchdog, admission, EDR storage and hunt")
    parser.add_argument("--output", default="acceptance-v011-beta2-b2-marker-trace-probe.json")
    parser.add_argument("--poll-seconds", type=float, default=12.0)
    args = parser.parse_args()
    return run(Path(args.output), poll_seconds=args.poll_seconds)


if __name__ == "__main__":
    raise SystemExit(main())

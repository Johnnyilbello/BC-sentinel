from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import tempfile
import time

import psutil

from sentinel.protection_client import ProtectionServiceClient

DEFAULT_MAX_IDLE_CPU_PERCENT = 25.0
DEFAULT_MIN_IPC_RPS = 10.0
DEFAULT_MAX_STORM_CPU_PERCENT = 250.0


def _thread_cpu_snapshot(proc: psutil.Process) -> dict[int, float]:
    try:
        return {
            int(thread.id): float(thread.user_time + thread.system_time)
            for thread in proc.threads()
        }
    except (psutil.Error, OSError):
        return {}


def _thread_cpu_deltas(before: dict[int, float], after: dict[int, float], elapsed: float, *, limit: int = 8) -> list[dict]:
    if elapsed <= 0:
        return []
    rows = []
    for tid, end_cpu in after.items():
        start_cpu = before.get(tid, end_cpu)
        delta = max(0.0, end_cpu - start_cpu)
        if delta <= 0:
            continue
        rows.append({
            "tid": int(tid),
            "cpu_seconds": round(delta, 6),
            "cpu_percent_of_one_core": round(delta / elapsed * 100.0, 2),
        })
    rows.sort(key=lambda row: row["cpu_seconds"], reverse=True)
    return rows[: max(1, int(limit))]


def _cpu_delta(proc: psutil.Process, seconds: float) -> tuple[float, float, float]:
    start_cpu = sum(proc.cpu_times()[:2])
    start = time.perf_counter()
    time.sleep(max(0.2, seconds))
    elapsed = time.perf_counter() - start
    end_cpu = sum(proc.cpu_times()[:2])
    cpu = max(0.0, end_cpu - start_cpu)
    return cpu, (cpu / elapsed * 100.0) if elapsed else 0.0, elapsed


def _evaluate(*, idle_cpu_percent: float, ipc_successful: int, ipc_requests: int, ipc_rps: float, storm_cpu_percent: float, hardening_ok: bool, max_idle_cpu_percent: float, min_ipc_rps: float, max_storm_cpu_percent: float) -> tuple[bool, dict, list[str]]:
    checks = {
        "idle_cpu_within_limit": idle_cpu_percent <= max_idle_cpu_percent,
        "ipc_all_successful": ipc_successful == ipc_requests,
        "ipc_throughput_floor": ipc_rps >= min_ipc_rps,
        "storm_cpu_within_limit": storm_cpu_percent <= max_storm_cpu_percent,
        "hardening_ok": bool(hardening_ok),
    }
    reasons = []
    if not checks["idle_cpu_within_limit"]:
        reasons.append(f"idle CPU {idle_cpu_percent:.2f}% exceeds {max_idle_cpu_percent:.2f}% of one core")
    if not checks["ipc_all_successful"]:
        reasons.append(f"IPC {ipc_successful}/{ipc_requests} successful")
    if not checks["ipc_throughput_floor"]:
        reasons.append(f"IPC throughput {ipc_rps:.2f}/s below {min_ipc_rps:.2f}/s")
    if not checks["storm_cpu_within_limit"]:
        reasons.append(f"storm CPU {storm_cpu_percent:.2f}% exceeds {max_storm_cpu_percent:.2f}% of one core")
    if not checks["hardening_ok"]:
        reasons.append("hardening posture is not healthy")
    return all(checks.values()), checks, reasons


def run(
    idle_seconds: float = 3.0,
    ipc_requests: int = 100,
    storm_files: int = 200,
    *,
    max_idle_cpu_percent: float = DEFAULT_MAX_IDLE_CPU_PERCENT,
    min_ipc_rps: float = DEFAULT_MIN_IPC_RPS,
    max_storm_cpu_percent: float = DEFAULT_MAX_STORM_CPU_PERCENT,
) -> dict:
    if os.name != "nt":
        return {"passed": False, "error": "Windows-only benchmark"}
    client = ProtectionServiceClient(timeout=2.0)
    status = client.status()
    if not status:
        return {"passed": False, "error": client.last_error or "service unavailable"}
    pid = int(status.get("pid") or 0)
    if pid <= 0:
        return {"passed": False, "error": "invalid service pid"}
    proc = psutil.Process(pid)

    rss_start = proc.memory_info().rss
    idle_threads_before = _thread_cpu_snapshot(proc)
    idle_cpu_seconds, idle_cpu_one_core, idle_elapsed = _cpu_delta(proc, idle_seconds)
    idle_threads_after = _thread_cpu_snapshot(proc)
    idle_hot_threads = _thread_cpu_deltas(idle_threads_before, idle_threads_after, idle_elapsed)
    rss_idle = proc.memory_info().rss

    ipc_start = time.perf_counter()
    ipc_ok = 0
    for _ in range(max(1, ipc_requests)):
        if client.status():
            ipc_ok += 1
    ipc_elapsed = time.perf_counter() - ipc_start

    with tempfile.TemporaryDirectory(prefix="bcs-v061-storm-") as tmp:
        root = Path(tmp)
        before_cpu = sum(proc.cpu_times()[:2])
        before = time.perf_counter()
        paths = []
        for i in range(max(1, storm_files)):
            path = root / f"safe-{i:04d}.txt"
            path.write_text("BC Sentinel v0.6.1 benign event storm\n", encoding="utf-8")
            paths.append(path)
        for path in paths:
            path.write_text("BC Sentinel v0.6.1 benign event storm updated\n", encoding="utf-8")
        for path in paths:
            try:
                path.unlink()
            except OSError:
                pass
        time.sleep(1.0)
        storm_elapsed = time.perf_counter() - before
        storm_cpu = max(0.0, sum(proc.cpu_times()[:2]) - before_cpu)

    hardening = client.hardening_status() or {}
    requested = max(1, ipc_requests)
    ipc_rps = (ipc_ok / ipc_elapsed) if ipc_elapsed else 0.0
    storm_cpu_percent = (storm_cpu / storm_elapsed * 100.0) if storm_elapsed else 0.0
    passed, checks, failure_reasons = _evaluate(
        idle_cpu_percent=idle_cpu_one_core,
        ipc_successful=ipc_ok,
        ipc_requests=requested,
        ipc_rps=ipc_rps,
        storm_cpu_percent=storm_cpu_percent,
        hardening_ok=bool(hardening.get("ok")),
        max_idle_cpu_percent=max_idle_cpu_percent,
        min_ipc_rps=min_ipc_rps,
        max_storm_cpu_percent=max_storm_cpu_percent,
    )
    return {
        "passed": passed,
        "checks": checks,
        "failure_reasons": failure_reasons,
        "thresholds": {
            "max_idle_cpu_percent_of_one_core": max_idle_cpu_percent,
            "min_ipc_requests_per_second": min_ipc_rps,
            "max_storm_cpu_percent_of_one_core": max_storm_cpu_percent,
        },
        "service": {
            "pid": pid,
            "health": status.get("health"),
            "transport": status.get("transport"),
            "rss_start_bytes": rss_start,
            "rss_idle_bytes": rss_idle,
            "thread_count": len(idle_threads_after),
        },
        "idle": {
            "seconds": idle_seconds,
            "measured_elapsed_seconds": round(idle_elapsed, 6),
            "cpu_seconds": round(idle_cpu_seconds, 6),
            "cpu_percent_of_one_core": round(idle_cpu_one_core, 2),
            "hottest_threads": idle_hot_threads,
        },
        "ipc": {
            "requests": requested,
            "successful": ipc_ok,
            "elapsed_seconds": round(ipc_elapsed, 6),
            "requests_per_second": round(ipc_rps, 2),
        },
        "benign_event_storm": {
            "files": max(1, storm_files),
            "operations": max(1, storm_files) * 3,
            "elapsed_seconds": round(storm_elapsed, 6),
            "service_cpu_seconds": round(storm_cpu, 6),
            "cpu_percent_of_one_core": round(storm_cpu_percent, 2),
        },
        "hardening": hardening,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel v0.6.1 Protection Service benchmark")
    parser.add_argument("--idle-seconds", type=float, default=3.0)
    parser.add_argument("--ipc-requests", type=int, default=100)
    parser.add_argument("--storm-files", type=int, default=200)
    parser.add_argument("--max-idle-cpu-percent", type=float, default=DEFAULT_MAX_IDLE_CPU_PERCENT)
    parser.add_argument("--min-ipc-rps", type=float, default=DEFAULT_MIN_IPC_RPS)
    parser.add_argument("--max-storm-cpu-percent", type=float, default=DEFAULT_MAX_STORM_CPU_PERCENT)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = run(
        max(0.2, args.idle_seconds),
        max(1, args.ipc_requests),
        max(1, args.storm_files),
        max_idle_cpu_percent=max(0.0, args.max_idle_cpu_percent),
        min_ipc_rps=max(0.0, args.min_ipc_rps),
        max_storm_cpu_percent=max(0.0, args.max_storm_cpu_percent),
    )
    text = json.dumps(result, indent=2, ensure_ascii=False)
    print(text)
    if args.output:
        args.output.write_text(text + "\n", encoding="utf-8")
    return 0 if result.get("passed") else 2


if __name__ == "__main__":
    raise SystemExit(main())

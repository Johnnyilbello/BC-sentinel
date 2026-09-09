from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from sentinel.core.events import SecurityEvent
from sentinel.correlation_engine import BehavioralCorrelationEngine
from sentinel.process_tree import ProcessNode


def run_benchmark(events: int = 10000, processes: int = 200) -> dict:
    events = max(100, int(events))
    processes = max(1, int(processes))
    engine = BehavioralCorrelationEngine(window_seconds=45.0)
    ancestry = {
        pid: [ProcessNode(pid=pid, ppid=1, name=f"worker{pid}.exe", create_time=float(pid))]
        for pid in range(1000, 1000 + processes)
    }

    start = time.perf_counter()
    max_delta = 0
    correlated = 0
    for i in range(events):
        pid = 1000 + (i % processes)
        phase = i % 5
        ts = 1000.0 + i * 0.001
        if phase in {0, 1, 2}:
            event = SecurityEvent(
                category="file",
                action="write",
                source="benchmark",
                pid=pid,
                process_name=f"worker{pid}.exe",
                path=rf"C:\bench\{pid}\f{i % 64}.dat",
                ts=ts,
            )
        elif phase == 3:
            event = SecurityEvent(
                category="network",
                action="connect",
                source="benchmark",
                pid=pid,
                process_name=f"worker{pid}.exe",
                data={"remote_addr": f"203.0.113.{(i % 200) + 1}", "remote_port": 443},
                ts=ts,
            )
        else:
            event = SecurityEvent(
                category="process",
                action="start",
                source="benchmark",
                pid=pid,
                process_name=f"worker{pid}.exe",
                process_path=rf"C:\Program Files\Bench\worker{pid}.exe",
                ts=ts,
            )
        result = engine.assess(event, ancestry[pid])
        max_delta = max(max_delta, result.score_delta)
        if result.score_delta:
            correlated += 1

    elapsed = max(1e-9, time.perf_counter() - start)
    return {
        "events": events,
        "processes": processes,
        "elapsed_seconds": round(elapsed, 6),
        "events_per_second": round(events / elapsed, 2),
        "correlated_events": correlated,
        "max_score_delta": max_delta,
        "window_seconds": engine.window_seconds,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel Behavioral Correlation Engine 2.0 benchmark")
    parser.add_argument("--events", type=int, default=10000)
    parser.add_argument("--processes", type=int, default=200)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = run_benchmark(args.events, args.processes)
    text = json.dumps(result, indent=2)
    print(text)
    if args.output:
        args.output.write_text(text + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

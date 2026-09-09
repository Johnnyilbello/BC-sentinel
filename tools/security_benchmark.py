from __future__ import annotations

import argparse
import json
import tempfile
import time
import statistics
from pathlib import Path

from sentinel.config import Settings
from sentinel.database import Database
from sentinel.performance import PerformanceProbe
from sentinel.realtime import RealtimeMonitor
from sentinel.scanner import StaticScanner


def make_corpus(root: Path, count: int, size: int, executable_every: int = 100) -> None:
    root.mkdir(parents=True, exist_ok=True)
    payload = (b"BC Sentinel harmless benchmark payload\n" * ((size // 38) + 1))[:size]
    for i in range(count):
        suffix = ".cmd" if executable_every and i % executable_every == 0 else ".txt"
        (root / f"sample_{i:05d}{suffix}").write_bytes(payload + str(i).encode())


def scan_benchmark(root: Path, db: Database):
    settings = Settings.defaults()
    settings.exclude_self = False
    settings.reputation_enabled = False
    settings.scan_size_limit_mb = 16
    scanner = StaticScanner(settings, db=db)
    scanner.enable_profiling(True)
    probe = PerformanceProbe()

    scanner.reset_profile()
    start = probe.snapshot()
    first = list(scanner.scan_paths([root]))
    end = probe.snapshot()
    cold = probe.delta(start, end).to_dict()
    cold["files"] = len(first)
    cold["files_per_second"] = round(len(first) / max(cold["elapsed_seconds"], 1e-6), 2)
    cold["hash_cache_hits"] = sum(1 for r in first if r.hashes_cached)
    cold["hash_cache_hit_ratio"] = round(cold["hash_cache_hits"] / max(1, len(first)), 4)
    cold["phase_profile"] = scanner.profile_snapshot()

    scanner.reset_profile()
    start = probe.snapshot()
    second = list(scanner.scan_paths([root]))
    end = probe.snapshot()
    warm = probe.delta(start, end).to_dict()
    warm["files"] = len(second)
    warm["files_per_second"] = round(len(second) / max(warm["elapsed_seconds"], 1e-6), 2)
    warm["hash_cache_hits"] = sum(1 for r in second if r.hashes_cached)
    warm["hash_cache_hit_ratio"] = round(warm["hash_cache_hits"] / max(1, len(second)), 4)
    warm["speedup_vs_cold"] = round(cold["elapsed_seconds"] / max(warm["elapsed_seconds"], 1e-6), 3)
    warm["cache_security_mode"] = "hash-cache plus deterministic content reinspection; PE parser gated by MZ magic; in-memory YARA for fully-read small files"
    warm["phase_profile"] = scanner.profile_snapshot()
    return {"cold_scan": cold, "warm_scan": warm}


def scan_benchmark_median(root: Path, db: Database, *, runs: int = 3, first_pair: dict | None = None):
    """Repeat application-cache cold/warm pairs and report robust medians.

    `cold` clears only BC Sentinel's hash_cache table. OS page cache / endpoint
    security are intentionally left untouched because they are part of the real
    Windows environment whose variance this median is meant to absorb.
    """
    count = max(3, min(int(runs), 7))
    pairs = []
    pair_results = []
    if isinstance(first_pair, dict) and "cold_scan" in first_pair and "warm_scan" in first_pair:
        pair_results.append(first_pair)
    while len(pair_results) < count:
        db.execute("DELETE FROM hash_cache")
        pair_results.append(scan_benchmark(root, db))
    for index, pair in enumerate(pair_results):
        pairs.append({
            "run": index + 1,
            "cold_elapsed_seconds": float(pair["cold_scan"]["elapsed_seconds"]),
            "warm_elapsed_seconds": float(pair["warm_scan"]["elapsed_seconds"]),
            "cold_files_per_second": float(pair["cold_scan"]["files_per_second"]),
            "warm_files_per_second": float(pair["warm_scan"]["files_per_second"]),
            "warm_hash_cache_hit_ratio": float(pair["warm_scan"]["hash_cache_hit_ratio"]),
            "speedup": float(pair["warm_scan"]["speedup_vs_cold"]),
        })
    cold = [item["cold_elapsed_seconds"] for item in pairs]
    warm = [item["warm_elapsed_seconds"] for item in pairs]
    cold_fps = [item["cold_files_per_second"] for item in pairs]
    warm_fps = [item["warm_files_per_second"] for item in pairs]
    ratios = [item["warm_hash_cache_hit_ratio"] for item in pairs]
    return {
        "runs": pairs,
        "run_count": count,
        "cold_elapsed_median_seconds": round(statistics.median(cold), 6),
        "warm_elapsed_median_seconds": round(statistics.median(warm), 6),
        "cold_files_per_second_median": round(statistics.median(cold_fps), 2),
        "warm_files_per_second_median": round(statistics.median(warm_fps), 2),
        "warm_hash_cache_hit_ratio_median": round(statistics.median(ratios), 4),
        "speedup_from_medians": round(statistics.median(cold) / max(statistics.median(warm), 1e-6), 3),
        "cold_elapsed_range_seconds": [round(min(cold), 6), round(max(cold), 6)],
        "warm_elapsed_range_seconds": [round(min(warm), 6), round(max(warm), 6)],
    }


def realtime_benchmark(root: Path, db: Database, seconds: float):
    settings = Settings.defaults()
    settings.monitored_dirs = [str(root)]
    settings.ransomware_dirs = []
    settings.ransomware_enabled = False
    settings.reputation_enabled = False
    monitor = RealtimeMonitor(settings, db=db)
    probe = PerformanceProbe()

    workload = []
    for i in range(20):
        candidate = root / f"rt_{i:03d}.cmd"
        candidate.write_text(f"@echo off\nrem harmless {i}\n", encoding="utf-8")
        workload.append(candidate)

    start = probe.snapshot()
    started = monitor.start()
    if started:
        # Re-write after observer startup so the native watcher sees the events.
        for i, candidate in enumerate(workload):
            candidate.write_text(f"@echo off\nrem harmless changed {i}\n", encoding="utf-8")
        time.sleep(max(1.0, float(seconds)))
        monitor.stop()
        mode = "watchdog_observer"
    else:
        # CI/container fallback: exercise the exact stability + scan pipeline even
        # when watchdog is not installed. This is not an observer benchmark and
        # is labelled explicitly in the output.
        for candidate in workload[:10]:
            monitor._scan_when_stable(str(candidate))
        mode = "direct_pipeline_fallback"
    end = probe.snapshot()
    result = probe.delta(start, end).to_dict()
    result["started"] = bool(started)
    result["mode"] = mode
    result["files_exercised"] = 20 if started else 10
    result["duration_requested"] = float(seconds)

    if not started:
        repeat_start = probe.snapshot()
        for candidate in workload[:10]:
            monitor._scan_when_stable(str(candidate))
        repeat_end = probe.snapshot()
        repeat = probe.delta(repeat_start, repeat_end).to_dict()
        repeat["files"] = 10
        result["unchanged_repeat"] = repeat
    return result


def main():
    parser = argparse.ArgumentParser(description="BC Sentinel v0.3.1 hardening benchmark")
    parser.add_argument("--files", type=int, default=5000)
    parser.add_argument("--size", type=int, default=256)
    parser.add_argument("--realtime-seconds", type=float, default=3.0)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="bcs-v031-bench-") as tmp:
        root = Path(tmp) / "corpus"
        make_corpus(root, max(1, args.files), max(32, args.size))
        db = Database(Path(tmp) / "bench.sqlite")
        result = {
            "files_requested": args.files,
            "bytes_per_file": args.size,
            **scan_benchmark(root, db),
            "realtime": realtime_benchmark(root, db, args.realtime_seconds),
        }

    text = json.dumps(result, indent=2, ensure_ascii=False)
    print(text)
    if args.output:
        args.output.write_text(text + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()

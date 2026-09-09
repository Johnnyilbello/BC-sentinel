from __future__ import annotations

import os
import time
from dataclasses import dataclass, asdict


@dataclass(slots=True)
class PerformanceSnapshot:
    wall_time: float
    cpu_user: float
    cpu_system: float
    rss_bytes: int
    read_bytes: int
    write_bytes: int

    def to_dict(self):
        return asdict(self)


@dataclass(slots=True)
class PerformanceDelta:
    elapsed_seconds: float
    cpu_seconds: float
    cpu_percent_of_one_core: float
    rss_start_bytes: int
    rss_end_bytes: int
    rss_peak_estimate_bytes: int
    read_bytes: int
    write_bytes: int

    def to_dict(self):
        return asdict(self)


class PerformanceProbe:
    """Small optional psutil-backed probe for repeatable security benchmarks."""

    def __init__(self):
        self._process = None
        try:
            import psutil
            self._process = psutil.Process(os.getpid())
        except Exception:
            self._process = None

    def snapshot(self) -> PerformanceSnapshot:
        wall = time.perf_counter()
        if self._process is None:
            times = os.times()
            return PerformanceSnapshot(
                wall, float(times.user), float(times.system), 0, 0, 0
            )
        try:
            cpu = self._process.cpu_times()
            mem = self._process.memory_info()
            io = self._process.io_counters()
            return PerformanceSnapshot(
                wall,
                float(cpu.user),
                float(cpu.system),
                int(mem.rss),
                int(getattr(io, "read_bytes", 0)),
                int(getattr(io, "write_bytes", 0)),
            )
        except Exception:
            times = os.times()
            return PerformanceSnapshot(
                wall, float(times.user), float(times.system), 0, 0, 0
            )

    @staticmethod
    def delta(start: PerformanceSnapshot, end: PerformanceSnapshot) -> PerformanceDelta:
        elapsed = max(0.000001, end.wall_time - start.wall_time)
        cpu = max(0.0, (end.cpu_user + end.cpu_system) - (start.cpu_user + start.cpu_system))
        return PerformanceDelta(
            elapsed_seconds=round(elapsed, 6),
            cpu_seconds=round(cpu, 6),
            cpu_percent_of_one_core=round(cpu / elapsed * 100.0, 2),
            rss_start_bytes=int(start.rss_bytes),
            rss_end_bytes=int(end.rss_bytes),
            rss_peak_estimate_bytes=max(int(start.rss_bytes), int(end.rss_bytes)),
            read_bytes=max(0, int(end.read_bytes) - int(start.read_bytes)),
            write_bytes=max(0, int(end.write_bytes) - int(start.write_bytes)),
        )

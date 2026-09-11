from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import tempfile
import time
import tracemalloc
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Final, Iterator

from sentinel import rescue_integrity_certification as rr6

PROFILE: Final[str] = "v0.11.0-beta.5-b52"
SCHEMA: Final[str] = "bc-sentinel-beta5-stress-hardening-v1"

STATE_COMPLETE: Final[str] = "COMPLETE"
STATE_PARTIAL_FILE_LIMIT: Final[str] = "PARTIAL_FILE_LIMIT"
STATE_PARTIAL_BYTE_LIMIT: Final[str] = "PARTIAL_BYTE_LIMIT"
STATE_PARTIAL_TIME_LIMIT: Final[str] = "PARTIAL_TIME_LIMIT"
STATE_CANCELLED: Final[str] = "CANCELLED"
STATE_DEGRADED: Final[str] = "DEGRADED"
STATE_REFUSED: Final[str] = "REFUSED"

MAX_FILES_HARD: Final[int] = 200_000
MAX_TOTAL_BYTES_HARD: Final[int] = 8 * 1024 * 1024 * 1024
MAX_SECONDS_HARD: Final[float] = 120.0
MAX_DEPTH_HARD: Final[int] = 256
MAX_WORKERS_HARD: Final[int] = 8
MAX_INFLIGHT_HARD: Final[int] = 512
MAX_SAMPLE_BYTES_HARD: Final[int] = 1024 * 1024


@dataclass(frozen=True)
class StressLimits:
    max_files: int = 20_000
    max_total_sample_bytes: int = 1024 * 1024 * 1024
    max_elapsed_sec: float = 30.0
    max_depth: int = 96
    sample_bytes: int = 4096
    max_workers: int = 4
    max_inflight: int = 128
    slow_read_ms: float = 500.0

    def validate(self) -> None:
        if not (1 <= int(self.max_files) <= MAX_FILES_HARD):
            raise ValueError("B5-2 max_files outside bounded limit")
        if not (1 <= int(self.max_total_sample_bytes) <= MAX_TOTAL_BYTES_HARD):
            raise ValueError("B5-2 max_total_sample_bytes outside bounded limit")
        if not (0.25 <= float(self.max_elapsed_sec) <= MAX_SECONDS_HARD):
            raise ValueError("B5-2 max_elapsed_sec outside bounded limit")
        if not (1 <= int(self.max_depth) <= MAX_DEPTH_HARD):
            raise ValueError("B5-2 max_depth outside bounded limit")
        if not (1 <= int(self.sample_bytes) <= MAX_SAMPLE_BYTES_HARD):
            raise ValueError("B5-2 sample_bytes outside bounded limit")
        if not (1 <= int(self.max_workers) <= MAX_WORKERS_HARD):
            raise ValueError("B5-2 max_workers outside bounded limit")
        if not (1 <= int(self.max_inflight) <= MAX_INFLIGHT_HARD):
            raise ValueError("B5-2 max_inflight outside bounded limit")
        if int(self.max_inflight) < int(self.max_workers):
            raise ValueError("B5-2 max_inflight must be >= max_workers")
        if not (1.0 <= float(self.slow_read_ms) <= 10_000.0):
            raise ValueError("B5-2 slow_read_ms outside bounded limit")


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _canonical_json(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _is_reparse_or_symlink(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        st = path.stat(follow_symlinks=False)
        attrs = int(getattr(st, "st_file_attributes", 0) or 0)
        reparse = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
        return bool(attrs & reparse)
    except OSError:
        return True


def _validate_target(target_root: Path) -> tuple[Path, str]:
    original = Path(target_root)
    try:
        if original.is_symlink():
            raise ValueError(f"B5-2 target symlink/reparse refused before resolution: {original}")
        st = original.stat(follow_symlinks=False)
        attrs = int(getattr(st, "st_file_attributes", 0) or 0)
        reparse = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
        if bool(attrs & reparse):
            raise ValueError(f"B5-2 target symlink/reparse refused before resolution: {original}")
    except ValueError:
        raise
    except OSError as exc:
        raise ValueError(f"B5-2 target pre-resolution validation failed: {type(exc).__name__}:{exc}") from exc

    root = original.resolve(strict=True)
    if not root.is_dir() or _is_reparse_or_symlink(root):
        raise ValueError(f"B5-2 target must be a real directory: {root}")
    rr6.validate_offline_windows_root(root)
    return root, rr6.target_fingerprint(root)


def _iter_regular_files(root: Path, *, max_depth: int, enum_stats: dict) -> Iterator[tuple[Path, str, int, int]]:
    stack: list[tuple[Path, int]] = [(root, 0)]
    while stack:
        current, depth = stack.pop()
        enum_stats["max_depth_observed"] = max(int(enum_stats["max_depth_observed"]), depth)
        if depth > max_depth:
            enum_stats["depth_pruned"] += 1
            continue
        try:
            with os.scandir(current) as entries:
                dirs: list[Path] = []
                files: list[tuple[Path, int]] = []
                for entry in entries:
                    p = Path(entry.path)
                    try:
                        if entry.is_symlink() or _is_reparse_or_symlink(p):
                            enum_stats["reparse_skipped"] += 1
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            dirs.append(p)
                        elif entry.is_file(follow_symlinks=False):
                            st = entry.stat(follow_symlinks=False)
                            if stat.S_ISREG(st.st_mode):
                                files.append((p, int(st.st_size)))
                    except PermissionError:
                        enum_stats["enumeration_access_denied"] += 1
                    except OSError:
                        enum_stats["enumeration_errors"] += 1
                for p, size in sorted(files, key=lambda item: item[0].name.casefold()):
                    rel = str(p.relative_to(root)).replace("\\", "/")
                    yield p, rel, depth, size
                for directory in sorted(dirs, key=lambda p: p.name.casefold(), reverse=True):
                    stack.append((directory, depth + 1))
        except PermissionError:
            enum_stats["enumeration_access_denied"] += 1
        except OSError:
            enum_stats["enumeration_errors"] += 1


def _probe_one(
    path: Path,
    rel: str,
    depth: int,
    size: int,
    sample_bytes: int,
    reader: Callable[[Path, int], bytes] | None,
) -> dict:
    started = time.perf_counter()
    status = "readable"
    reason = "ok"
    sample = b""
    try:
        if reader is None:
            with path.open("rb") as handle:
                sample = handle.read(sample_bytes)
        else:
            sample = reader(path, sample_bytes)
        if not isinstance(sample, (bytes, bytearray)):
            raise TypeError("reader must return bytes")
    except PermissionError as exc:
        status = "access_denied"
        reason = f"PermissionError:{exc}"
    except OSError as exc:
        status = "io_error"
        code = int(getattr(exc, "winerror", 0) or getattr(exc, "errno", 0) or 0)
        reason = f"OSError:{code}:{exc}"
    except Exception as exc:
        status = "probe_error"
        reason = f"{type(exc).__name__}:{exc}"
    elapsed_ms = round((time.perf_counter() - started) * 1000.0, 3)
    return {
        "relative_path": rel,
        "depth": depth,
        "file_size": size,
        "status": status,
        "reason": reason,
        "sampled_bytes": len(sample),
        "sha256_sample": hashlib.sha256(sample).hexdigest() if sample else "",
        "elapsed_ms": elapsed_ms,
    }


def stress_probe_target(
    target_root: Path,
    *,
    limits: StressLimits | None = None,
    reader: Callable[[Path, int], bytes] | None = None,
    cancel_check: Callable[[], bool] | None = None,
) -> dict:
    limits = limits or StressLimits()
    limits.validate()
    started = time.perf_counter()
    root, fingerprint = _validate_target(Path(target_root))

    own_tracemalloc = not tracemalloc.is_tracing()
    if own_tracemalloc:
        tracemalloc.start()

    enum_stats = {
        "max_depth_observed": 0,
        "depth_pruned": 0,
        "reparse_skipped": 0,
        "enumeration_access_denied": 0,
        "enumeration_errors": 0,
    }
    counters = {
        "files_seen": 0,
        "scheduled": 0,
        "probed": 0,
        "readable": 0,
        "access_denied": 0,
        "io_errors": 0,
        "probe_errors": 0,
        "slow_reads": 0,
    }
    sampled_budget_reserved = 0
    sampled_bytes_actual = 0
    inflight_peak = 0
    records_by_seq: dict[int, dict] = {}
    completion_state = STATE_COMPLETE
    completion_reason = "enumeration_complete"
    pending: dict[Future, tuple[int, int]] = {}
    iterator = iter(_iter_regular_files(root, max_depth=limits.max_depth, enum_stats=enum_stats))
    iterator_exhausted = False
    stop_scheduling = False

    def remaining_time() -> float:
        return max(0.0, float(limits.max_elapsed_sec) - (time.perf_counter() - started))

    executor = ThreadPoolExecutor(max_workers=int(limits.max_workers), thread_name_prefix="b52-read")
    try:
        while True:
            if not stop_scheduling:
                if cancel_check is not None and bool(cancel_check()):
                    completion_state = STATE_CANCELLED
                    completion_reason = "operator_cancellation_requested"
                    stop_scheduling = True
                elif remaining_time() <= 0.0:
                    completion_state = STATE_PARTIAL_TIME_LIMIT
                    completion_reason = "time_budget_reached"
                    stop_scheduling = True

            while not stop_scheduling and not iterator_exhausted and len(pending) < int(limits.max_inflight):
                try:
                    path, rel, depth, size = next(iterator)
                    counters["files_seen"] += 1
                except StopIteration:
                    iterator_exhausted = True
                    break

                if counters["scheduled"] >= int(limits.max_files):
                    completion_state = STATE_PARTIAL_FILE_LIMIT
                    completion_reason = "file_budget_reached"
                    stop_scheduling = True
                    break

                requested = min(int(size), int(limits.sample_bytes))
                if sampled_budget_reserved + requested > int(limits.max_total_sample_bytes):
                    completion_state = STATE_PARTIAL_BYTE_LIMIT
                    completion_reason = "sample_byte_budget_reached"
                    stop_scheduling = True
                    break

                seq = int(counters["scheduled"])
                future = executor.submit(_probe_one, path, rel, depth, size, int(limits.sample_bytes), reader)
                pending[future] = (seq, requested)
                counters["scheduled"] += 1
                sampled_budget_reserved += requested
                inflight_peak = max(inflight_peak, len(pending))

            if not pending:
                if iterator_exhausted or stop_scheduling:
                    break
                continue

            timeout = min(0.1, max(0.001, remaining_time()))
            done, _ = wait(set(pending), timeout=timeout, return_when=FIRST_COMPLETED)
            if not done:
                if remaining_time() <= 0.0 and not stop_scheduling:
                    completion_state = STATE_PARTIAL_TIME_LIMIT
                    completion_reason = "time_budget_reached"
                    stop_scheduling = True
                continue

            for future in done:
                seq, _reserved = pending.pop(future)
                try:
                    record = future.result()
                except Exception as exc:
                    record = {
                        "relative_path": "<worker>",
                        "depth": -1,
                        "file_size": 0,
                        "status": "probe_error",
                        "reason": f"worker_exception:{type(exc).__name__}:{exc}",
                        "sampled_bytes": 0,
                        "sha256_sample": "",
                        "elapsed_ms": 0.0,
                    }
                records_by_seq[seq] = record
                counters["probed"] += 1
                sampled_bytes_actual += int(record.get("sampled_bytes", 0))
                status = str(record.get("status", ""))
                if status == "readable":
                    counters["readable"] += 1
                elif status == "access_denied":
                    counters["access_denied"] += 1
                elif status == "io_error":
                    counters["io_errors"] += 1
                else:
                    counters["probe_errors"] += 1
                if float(record.get("elapsed_ms", 0.0)) >= float(limits.slow_read_ms):
                    counters["slow_reads"] += 1
                    record["slow_read"] = True
                else:
                    record["slow_read"] = False

        if stop_scheduling:
            for future in list(pending):
                future.cancel()

        # Collect already-running bounded work. No target writes occur, and cancelled queued work is not replayed.
        for future, (seq, _reserved) in list(pending.items()):
            if future.cancelled():
                continue
            try:
                record = future.result(timeout=max(0.1, min(5.0, float(limits.max_elapsed_sec))))
            except Exception as exc:
                record = {
                    "relative_path": "<worker>",
                    "depth": -1,
                    "file_size": 0,
                    "status": "probe_error",
                    "reason": f"worker_finalize_exception:{type(exc).__name__}:{exc}",
                    "sampled_bytes": 0,
                    "sha256_sample": "",
                    "elapsed_ms": 0.0,
                }
            records_by_seq[seq] = record
            counters["probed"] += 1
            sampled_bytes_actual += int(record.get("sampled_bytes", 0))
            status = str(record.get("status", ""))
            if status == "readable":
                counters["readable"] += 1
            elif status == "access_denied":
                counters["access_denied"] += 1
            elif status == "io_error":
                counters["io_errors"] += 1
            else:
                counters["probe_errors"] += 1
            if float(record.get("elapsed_ms", 0.0)) >= float(limits.slow_read_ms):
                counters["slow_reads"] += 1
                record["slow_read"] = True
            else:
                record["slow_read"] = False
        pending.clear()
    finally:
        executor.shutdown(wait=True, cancel_futures=True)

    elapsed_sec = max(0.000001, time.perf_counter() - started)
    current_mem, peak_mem = tracemalloc.get_traced_memory() if tracemalloc.is_tracing() else (0, 0)
    if own_tracemalloc:
        tracemalloc.stop()

    records = [records_by_seq[k] for k in sorted(records_by_seq)]
    if completion_state == STATE_COMPLETE and (
        counters["access_denied"] > 0
        or counters["io_errors"] > 0
        or counters["probe_errors"] > 0
        or enum_stats["enumeration_access_denied"] > 0
        or enum_stats["enumeration_errors"] > 0
    ):
        completion_state = STATE_DEGRADED
        completion_reason = "read_or_enumeration_errors_observed"

    stable_records = [
        {
            "relative_path": r["relative_path"],
            "depth": r["depth"],
            "file_size": r["file_size"],
            "status": r["status"],
            "reason": r["reason"],
            "sampled_bytes": r["sampled_bytes"],
            "sha256_sample": r["sha256_sample"],
        }
        for r in records
    ]
    stable_core = {
        "schema": SCHEMA,
        "profile": PROFILE,
        "target_root": str(root),
        "target_fingerprint": fingerprint,
        "state": completion_state,
        "reason": completion_reason,
        "limits": asdict(limits),
        "counters": counters,
        "enumeration": enum_stats,
        "sampled_bytes": sampled_bytes_actual,
        "records": stable_records,
        "safety": {
            "target_read_only": True,
            "write_attempted": False,
            "target_execution": False,
            "repair_execution": False,
            "quarantine_execution": False,
            "file_delete": False,
            "registry_write": False,
            "boot_write": False,
            "automatic_action": False,
            "network_required": False,
            "cloud_required": False,
        },
    }
    probe_sha256 = hashlib.sha256(_canonical_json(stable_core)).hexdigest()
    return {
        **stable_core,
        "created_utc": _utc_now(),
        "probe_sha256": probe_sha256,
        "performance": {
            "elapsed_ms": round(elapsed_sec * 1000.0, 3),
            "files_per_sec": round(counters["probed"] / elapsed_sec, 3),
            "sampled_mib_per_sec": round((sampled_bytes_actual / (1024.0 * 1024.0)) / elapsed_sec, 3),
            "inflight_peak": inflight_peak,
            "max_workers": int(limits.max_workers),
            "max_inflight": int(limits.max_inflight),
            "python_current_bytes": int(current_mem),
            "python_peak_bytes": int(peak_mem),
        },
    }


def write_probe(result: dict, output_path: Path, target_root: Path) -> Path:
    root = Path(target_root).resolve(strict=True)
    output = Path(output_path).resolve(strict=False)
    try:
        output.relative_to(root)
        raise ValueError("B5-2 probe output must be outside target")
    except ValueError as exc:
        if str(exc).startswith("B5-2 probe output"):
            raise
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=output.name + ".", suffix=".tmp", dir=str(output.parent))
    os.close(fd)
    temp = Path(temp_name)
    try:
        temp.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(temp, output)
    finally:
        try:
            temp.unlink(missing_ok=True)
        except OSError:
            pass
    return output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel Beta5 B5-2 bounded large-scale stress probe")
    parser.add_argument("--target-root", required=True)
    parser.add_argument("--output")
    parser.add_argument("--max-files", type=int, default=20_000)
    parser.add_argument("--max-total-sample-bytes", type=int, default=1024 * 1024 * 1024)
    parser.add_argument("--max-elapsed-sec", type=float, default=30.0)
    parser.add_argument("--max-depth", type=int, default=96)
    parser.add_argument("--sample-bytes", type=int, default=4096)
    parser.add_argument("--max-workers", type=int, default=4)
    parser.add_argument("--max-inflight", type=int, default=128)
    parser.add_argument("--slow-read-ms", type=float, default=500.0)
    args = parser.parse_args(argv)
    try:
        limits = StressLimits(
            max_files=args.max_files,
            max_total_sample_bytes=args.max_total_sample_bytes,
            max_elapsed_sec=args.max_elapsed_sec,
            max_depth=args.max_depth,
            sample_bytes=args.sample_bytes,
            max_workers=args.max_workers,
            max_inflight=args.max_inflight,
            slow_read_ms=args.slow_read_ms,
        )
        result = stress_probe_target(Path(args.target_root), limits=limits)
        if args.output:
            write_probe(result, Path(args.output), Path(args.target_root))
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["state"] in {STATE_COMPLETE, STATE_DEGRADED} else 4
    except Exception as exc:
        print(json.dumps({"passed": False, "profile": PROFILE, "state": STATE_REFUSED, "stage": "stress_probe", "reason": f"{type(exc).__name__}:{exc}"}, indent=2))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

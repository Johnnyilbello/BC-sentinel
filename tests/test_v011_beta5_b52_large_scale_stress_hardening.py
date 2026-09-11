from __future__ import annotations

import hashlib
import time
from pathlib import Path

import pytest

from sentinel import rescue_stress_hardening as b52


def make_windows(root: Path) -> Path:
    cfg = root / "Windows" / "System32" / "config"
    cfg.mkdir(parents=True)
    (cfg / "SYSTEM").write_bytes(b"SYSTEM")
    (cfg / "SOFTWARE").write_bytes(b"SOFTWARE")
    (root / "Windows" / "System32" / "ntoskrnl.exe").write_bytes(b"MZ KERNEL")
    return root


def tree_hashes(root: Path) -> dict[str, str]:
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in root.rglob("*") if p.is_file()}


def add_files(root: Path, count: int, *, directory: str = "Data") -> None:
    base = root / directory
    base.mkdir(parents=True, exist_ok=True)
    for i in range(count):
        (base / f"f{i:05d}.bin").write_bytes((f"file-{i}" * 2).encode("ascii"))


def test_small_target_completes_read_only(tmp_path: Path) -> None:
    root = make_windows(tmp_path / "offline")
    add_files(root, 20)
    before = tree_hashes(root)
    result = b52.stress_probe_target(root, limits=b52.StressLimits(max_files=100, max_inflight=8, max_workers=2))
    assert result["state"] == b52.STATE_COMPLETE
    assert result["counters"]["probed"] == 23
    assert result["safety"]["write_attempted"] is False
    assert tree_hashes(root) == before


def test_file_limit_is_explicit_partial(tmp_path: Path) -> None:
    root = make_windows(tmp_path / "offline")
    add_files(root, 20)
    result = b52.stress_probe_target(root, limits=b52.StressLimits(max_files=5, max_inflight=2, max_workers=1))
    assert result["state"] == b52.STATE_PARTIAL_FILE_LIMIT
    assert result["reason"] == "file_budget_reached"
    assert result["counters"]["scheduled"] == 5
    assert result["counters"]["files_seen"] >= 6


def test_byte_limit_is_explicit_partial(tmp_path: Path) -> None:
    root = make_windows(tmp_path / "offline")
    add_files(root, 10)
    result = b52.stress_probe_target(
        root,
        limits=b52.StressLimits(max_files=100, sample_bytes=8, max_total_sample_bytes=16, max_workers=1, max_inflight=1),
    )
    assert result["state"] == b52.STATE_PARTIAL_BYTE_LIMIT
    assert result["reason"] == "sample_byte_budget_reached"
    assert result["sampled_bytes"] <= 16


def test_cancellation_is_explicit_and_no_write(tmp_path: Path) -> None:
    root = make_windows(tmp_path / "offline")
    add_files(root, 50)
    before = tree_hashes(root)
    calls = {"n": 0}

    def cancel() -> bool:
        calls["n"] += 1
        return calls["n"] >= 2

    result = b52.stress_probe_target(root, limits=b52.StressLimits(max_files=100, max_workers=1, max_inflight=1), cancel_check=cancel)
    assert result["state"] == b52.STATE_CANCELLED
    assert result["reason"] == "operator_cancellation_requested"
    assert tree_hashes(root) == before


def test_time_limit_is_explicit_partial(tmp_path: Path) -> None:
    root = make_windows(tmp_path / "offline")
    add_files(root, 20)

    def slow_reader(path: Path, amount: int) -> bytes:
        time.sleep(0.10)
        with path.open("rb") as handle:
            return handle.read(amount)

    result = b52.stress_probe_target(
        root,
        limits=b52.StressLimits(max_files=100, max_elapsed_sec=0.25, max_workers=1, max_inflight=1, slow_read_ms=10),
        reader=slow_reader,
    )
    assert result["state"] == b52.STATE_PARTIAL_TIME_LIMIT
    assert result["reason"] == "time_budget_reached"
    assert result["counters"]["slow_reads"] >= 1


def test_deep_tree_reports_depth_without_recursion(tmp_path: Path) -> None:
    root = make_windows(tmp_path / "offline")
    current = root / "Deep"
    for i in range(24):
        current = current / f"d{i:02d}"
    current.mkdir(parents=True)
    (current / "leaf.bin").write_bytes(b"leaf")
    result = b52.stress_probe_target(root, limits=b52.StressLimits(max_files=100, max_depth=64, max_workers=1, max_inflight=1))
    assert result["state"] == b52.STATE_COMPLETE
    assert result["enumeration"]["max_depth_observed"] >= 24


def test_depth_bound_prunes_beyond_limit(tmp_path: Path) -> None:
    root = make_windows(tmp_path / "offline")
    current = root / "Deep"
    for i in range(12):
        current = current / f"d{i:02d}"
    current.mkdir(parents=True)
    (current / "leaf.bin").write_bytes(b"leaf")
    result = b52.stress_probe_target(root, limits=b52.StressLimits(max_files=100, max_depth=4, max_workers=1, max_inflight=1))
    assert result["enumeration"]["depth_pruned"] >= 1
    assert all(not row["relative_path"].endswith("leaf.bin") for row in result["records"])


def test_large_file_is_sampled_not_fully_loaded(tmp_path: Path) -> None:
    root = make_windows(tmp_path / "offline")
    large = root / "Data" / "large.bin"
    large.parent.mkdir(parents=True)
    large.write_bytes(b"L" * (2 * 1024 * 1024))
    result = b52.stress_probe_target(root, limits=b52.StressLimits(max_files=20, sample_bytes=1024, max_workers=1, max_inflight=1))
    row = next(r for r in result["records"] if r["relative_path"] == "Data/large.bin")
    assert row["file_size"] == 2 * 1024 * 1024
    assert row["sampled_bytes"] == 1024


def test_read_error_marks_complete_probe_degraded(tmp_path: Path) -> None:
    root = make_windows(tmp_path / "offline")
    bad = root / "Data" / "bad.bin"
    bad.parent.mkdir(parents=True)
    bad.write_bytes(b"bad")

    def reader(path: Path, amount: int) -> bytes:
        if path == bad:
            raise OSError(5, "simulated io")
        with path.open("rb") as handle:
            return handle.read(amount)

    result = b52.stress_probe_target(root, limits=b52.StressLimits(max_files=20, max_workers=1, max_inflight=1), reader=reader)
    assert result["state"] == b52.STATE_DEGRADED
    assert result["counters"]["io_errors"] == 1


def test_inflight_and_worker_bounds_are_respected(tmp_path: Path) -> None:
    root = make_windows(tmp_path / "offline")
    add_files(root, 40)
    result = b52.stress_probe_target(root, limits=b52.StressLimits(max_files=100, max_workers=2, max_inflight=3))
    assert result["performance"]["max_workers"] == 2
    assert result["performance"]["max_inflight"] == 3
    assert 1 <= result["performance"]["inflight_peak"] <= 3


def test_output_inside_target_refused(tmp_path: Path) -> None:
    root = make_windows(tmp_path / "offline")
    result = b52.stress_probe_target(root, limits=b52.StressLimits(max_files=20, max_workers=1, max_inflight=1))
    with pytest.raises(ValueError, match="outside target"):
        b52.write_probe(result, root / "stress.json", root)


def test_output_outside_target_roundtrip(tmp_path: Path) -> None:
    root = make_windows(tmp_path / "offline")
    result = b52.stress_probe_target(root, limits=b52.StressLimits(max_files=20, max_workers=1, max_inflight=1))
    out = b52.write_probe(result, tmp_path / "evidence" / "stress.json", root)
    assert out.is_file()
    assert result["probe_sha256"] in out.read_text(encoding="utf-8")


def test_limits_and_probe_hash_are_valid(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        b52.StressLimits(max_files=0).validate()
    with pytest.raises(ValueError):
        b52.StressLimits(max_workers=9).validate()
    with pytest.raises(ValueError):
        b52.StressLimits(max_workers=4, max_inflight=2).validate()
    root = make_windows(tmp_path / "offline")
    result = b52.stress_probe_target(root, limits=b52.StressLimits(max_files=20, max_workers=1, max_inflight=1))
    assert len(result["probe_sha256"]) == 64
    int(result["probe_sha256"], 16)
    assert result["performance"]["python_peak_bytes"] >= 0

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
import time
from pathlib import Path

from sentinel import rescue_stress_hardening as b52

PROFILE = b52.PROFILE
CHECKPOINT = "B5-2-large-scale-stress-hardening"
FIXTURE_FILES = 12_000
DEEP_LEVELS = 40
THROUGHPUT_FLOOR_FILES_PER_SEC = 100.0
PEAK_PYTHON_MEMORY_CEILING = 192 * 1024 * 1024


def make_windows(root: Path) -> Path:
    cfg = root / "Windows" / "System32" / "config"
    cfg.mkdir(parents=True)
    (cfg / "SYSTEM").write_bytes(b"B52 SYSTEM")
    (cfg / "SOFTWARE").write_bytes(b"B52 SOFTWARE")
    (root / "Windows" / "System32" / "ntoskrnl.exe").write_bytes(b"MZ B52 KERNEL")
    return root


def tree_hashes(root: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for path in root.rglob("*"):
        if path.is_file() and not path.is_symlink():
            out[str(path.relative_to(root)).replace("\\", "/")] = hashlib.sha256(path.read_bytes()).hexdigest()
    return out


def build_large_fixture(root: Path) -> tuple[Path, Path]:
    target = make_windows(root / "offline")
    bulk = target / "Bulk"
    bulk.mkdir(parents=True)
    for i in range(FIXTURE_FILES):
        (bulk / f"item-{i:05d}.dat").write_bytes((f"B52-{i:05d}" * 2).encode("ascii"))

    deep = target / "Deep"
    for i in range(DEEP_LEVELS):
        deep = deep / f"d{i:02d}"
    deep.mkdir(parents=True)
    (deep / "deep-leaf.bin").write_bytes(b"deep")

    large = target / "Large" / "large.bin"
    large.parent.mkdir(parents=True)
    large.write_bytes(b"L" * (8 * 1024 * 1024))
    return target, large


def run_acceptance(output: Path) -> dict:
    with tempfile.TemporaryDirectory(prefix="bcs-b52-") as td:
        base = Path(td)
        target, large_file = build_large_fixture(base)
        before = tree_hashes(target)

        limits = b52.StressLimits(
            max_files=20_000,
            max_total_sample_bytes=64 * 1024 * 1024,
            max_elapsed_sec=60.0,
            max_depth=128,
            sample_bytes=64,
            max_workers=4,
            max_inflight=64,
            slow_read_ms=1000.0,
        )
        full = b52.stress_probe_target(target, limits=limits)
        evidence = b52.write_probe(full, base / "evidence" / "stress.json", target)
        after = tree_hashes(target)

        large_rel = str(large_file.relative_to(target)).replace("\\", "/")
        large_row = next((r for r in full["records"] if r["relative_path"] == large_rel), None)

        limited = b52.stress_probe_target(
            target,
            limits=b52.StressLimits(
                max_files=1000,
                max_total_sample_bytes=8 * 1024 * 1024,
                max_elapsed_sec=30.0,
                max_depth=128,
                sample_bytes=32,
                max_workers=2,
                max_inflight=16,
            ),
        )

        cancel_calls = {"n": 0}

        def cancel() -> bool:
            cancel_calls["n"] += 1
            return cancel_calls["n"] >= 3

        cancelled = b52.stress_probe_target(
            target,
            limits=b52.StressLimits(
                max_files=5000,
                max_total_sample_bytes=8 * 1024 * 1024,
                max_elapsed_sec=30.0,
                max_depth=128,
                sample_bytes=32,
                max_workers=1,
                max_inflight=1,
            ),
            cancel_check=cancel,
        )

        def slow_reader(path: Path, amount: int) -> bytes:
            time.sleep(0.08)
            with path.open("rb") as handle:
                return handle.read(amount)

        timed = b52.stress_probe_target(
            target,
            limits=b52.StressLimits(
                max_files=5000,
                max_total_sample_bytes=8 * 1024 * 1024,
                max_elapsed_sec=0.30,
                max_depth=128,
                sample_bytes=32,
                max_workers=1,
                max_inflight=1,
                slow_read_ms=10.0,
            ),
            reader=slow_reader,
        )

        checks = {
            "profile": full.get("profile") == PROFILE,
            "schema": full.get("schema") == b52.SCHEMA,
            "large_scale_complete": full.get("state") == b52.STATE_COMPLETE,
            "tens_of_thousands_scale": int(full["counters"]["probed"]) >= FIXTURE_FILES,
            "deep_tree_observed": int(full["enumeration"]["max_depth_observed"]) >= DEEP_LEVELS,
            "large_file_sample_bounded": bool(large_row) and int(large_row["file_size"]) == 8 * 1024 * 1024 and int(large_row["sampled_bytes"]) == 64,
            "file_limit_partial": limited.get("state") == b52.STATE_PARTIAL_FILE_LIMIT and int(limited["counters"]["scheduled"]) == 1000,
            "cancellation_partial": cancelled.get("state") == b52.STATE_CANCELLED,
            "time_limit_partial": timed.get("state") == b52.STATE_PARTIAL_TIME_LIMIT,
            "workers_bounded": int(full["performance"]["max_workers"]) <= 4,
            "inflight_bounded": int(full["performance"]["inflight_peak"]) <= 64,
            "throughput_floor": float(full["performance"]["files_per_sec"]) >= THROUGHPUT_FLOOR_FILES_PER_SEC,
            "memory_ceiling": int(full["performance"]["python_peak_bytes"]) <= PEAK_PYTHON_MEMORY_CEILING,
            "probe_hash_present": len(str(full.get("probe_sha256", ""))) == 64,
            "target_byte_identical": before == after,
            "output_outside_target": evidence.is_file() and not str(evidence).casefold().startswith(str(target).casefold()),
            "no_write_attempt": full["safety"]["write_attempted"] is False,
            "no_target_execution": full["safety"]["target_execution"] is False,
            "no_repair_execution": full["safety"]["repair_execution"] is False,
            "no_quarantine_execution": full["safety"]["quarantine_execution"] is False,
            "no_delete": full["safety"]["file_delete"] is False,
            "no_registry_write": full["safety"]["registry_write"] is False,
            "no_boot_write": full["safety"]["boot_write"] is False,
            "no_automatic_action": full["safety"]["automatic_action"] is False,
            "no_network_required": full["safety"]["network_required"] is False,
            "no_cloud_required": full["safety"]["cloud_required"] is False,
        }
        passed = all(checks.values())
        payload = {
            "profile": PROFILE,
            "checkpoint": CHECKPOINT,
            "passed": passed,
            "checks": checks,
            "detail": {
                "fixture_files": FIXTURE_FILES,
                "deep_levels": DEEP_LEVELS,
                "probed": full["counters"]["probed"],
                "sampled_bytes": full["sampled_bytes"],
                "max_depth_observed": full["enumeration"]["max_depth_observed"],
                "files_per_sec": full["performance"]["files_per_sec"],
                "sampled_mib_per_sec": full["performance"]["sampled_mib_per_sec"],
                "python_peak_bytes": full["performance"]["python_peak_bytes"],
                "inflight_peak": full["performance"]["inflight_peak"],
                "probe_sha256": full["probe_sha256"],
                "limited_state": limited["state"],
                "cancelled_state": cancelled["state"],
                "timed_state": timed["state"],
            },
            "thresholds": {
                "throughput_floor_files_per_sec": THROUGHPUT_FLOOR_FILES_PER_SEC,
                "peak_python_memory_ceiling_bytes": PEAK_PYTHON_MEMORY_CEILING,
                "max_inflight": 64,
                "max_workers": 4,
            },
            "new_mutation_authority_added": False,
            "automatic_destructive_action_enabled": False,
        }
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return payload


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    payload = run_acceptance(Path(args.output))
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if payload["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())

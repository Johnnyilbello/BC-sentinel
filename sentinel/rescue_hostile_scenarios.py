from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Final, Iterable

from sentinel import rescue_integrity_certification as rr6

PROFILE: Final[str] = "v0.11.0-beta.5-b51"
SCHEMA: Final[str] = "bc-sentinel-beta5-hostile-damaged-assessment-v1"

STATE_HEALTHY: Final[str] = "HEALTHY"
STATE_REVIEW: Final[str] = "REVIEW_REQUIRED"
STATE_DAMAGED: Final[str] = "DAMAGED"
STATE_ACCESS_RESTRICTED: Final[str] = "ACCESS_RESTRICTED"
STATE_IO_DEGRADED: Final[str] = "IO_DEGRADED"
STATE_REFUSED: Final[str] = "REFUSED"

MAX_FILES_HARD: Final[int] = 4096
MAX_TOTAL_BYTES_HARD: Final[int] = 128 * 1024 * 1024
MAX_SECONDS_HARD: Final[float] = 30.0
DEFAULT_SAMPLE_BYTES: Final[int] = 64 * 1024

CRITICAL_RELATIVE_PATHS: Final[tuple[str, ...]] = (
    "Windows/System32/config/SYSTEM",
    "Windows/System32/config/SOFTWARE",
    "Windows/System32/ntoskrnl.exe",
)

PERSISTENCE_ROOTS: Final[tuple[str, ...]] = (
    "ProgramData/Microsoft/Windows/Start Menu/Programs/StartUp",
    "Windows/System32/Tasks",
)

ACTIVE_SUFFIXES: Final[frozenset[str]] = frozenset({
    ".exe", ".dll", ".sys", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".wsf", ".hta", ".lnk"
})


@dataclass(frozen=True)
class AssessmentLimits:
    max_files: int = 512
    max_total_bytes: int = 16 * 1024 * 1024
    max_elapsed_sec: float = 8.0
    sample_bytes: int = DEFAULT_SAMPLE_BYTES
    slow_read_ms: float = 250.0

    def validate(self) -> None:
        if not (1 <= int(self.max_files) <= MAX_FILES_HARD):
            raise ValueError("B5-1 max_files outside bounded limit")
        if not (1 <= int(self.max_total_bytes) <= MAX_TOTAL_BYTES_HARD):
            raise ValueError("B5-1 max_total_bytes outside bounded limit")
        if not (0.5 <= float(self.max_elapsed_sec) <= MAX_SECONDS_HARD):
            raise ValueError("B5-1 max_elapsed_sec outside bounded limit")
        if not (1 <= int(self.sample_bytes) <= 1024 * 1024):
            raise ValueError("B5-1 sample_bytes outside bounded limit")
        if not (1.0 <= float(self.slow_read_ms) <= 5000.0):
            raise ValueError("B5-1 slow_read_ms outside bounded limit")


@dataclass(frozen=True)
class ProbeRecord:
    relative_path: str
    category: str
    size: int
    status: str
    sha256_sample: str
    elapsed_ms: float
    reasons: tuple[str, ...]

    def to_record(self) -> dict:
        return asdict(self)


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


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


def _canonical_json(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sample_file(path: Path, sample_bytes: int, reader: Callable[[Path, int], bytes] | None = None) -> tuple[str, int]:
    if reader is not None:
        data = reader(path, sample_bytes)
    else:
        with path.open("rb") as handle:
            data = handle.read(sample_bytes)
    return hashlib.sha256(data).hexdigest(), len(data)


def _candidate_paths(root: Path) -> Iterable[tuple[Path, str]]:
    yielded: set[str] = set()
    for rel in CRITICAL_RELATIVE_PATHS:
        p = root.joinpath(*rel.split("/"))
        yielded.add(str(p).casefold())
        yield p, "critical"

    for rel in PERSISTENCE_ROOTS:
        base = root.joinpath(*rel.split("/"))
        try:
            if not base.is_dir() or _is_reparse_or_symlink(base):
                continue
            for current, dirs, files in os.walk(base, topdown=True, followlinks=False):
                current_p = Path(current)
                dirs[:] = [d for d in sorted(dirs, key=str.casefold) if not _is_reparse_or_symlink(current_p / d)]
                for name in sorted(files, key=str.casefold):
                    p = current_p / name
                    key = str(p).casefold()
                    if key in yielded or _is_reparse_or_symlink(p):
                        continue
                    yielded.add(key)
                    yield p, "persistence"
        except OSError:
            continue

    users = root / "Users"
    try:
        if users.is_dir() and not _is_reparse_or_symlink(users):
            for profile in sorted((p for p in users.iterdir() if p.is_dir()), key=lambda p: p.name.casefold()):
                startup = profile / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
                if not startup.is_dir() or _is_reparse_or_symlink(startup):
                    continue
                for p in sorted((p for p in startup.iterdir() if p.is_file()), key=lambda p: p.name.casefold()):
                    key = str(p).casefold()
                    if key not in yielded and not _is_reparse_or_symlink(p):
                        yielded.add(key)
                        yield p, "persistence"
    except OSError:
        pass


def _critical_inventory(root: Path) -> tuple[list[str], list[str]]:
    present: list[str] = []
    missing: list[str] = []
    for rel in CRITICAL_RELATIVE_PATHS:
        p = root.joinpath(*rel.split("/"))
        try:
            (present if p.is_file() else missing).append(rel)
        except OSError:
            missing.append(rel)
    return present, missing


def assess_target(
    target_root: Path,
    *,
    limits: AssessmentLimits | None = None,
    reader: Callable[[Path, int], bytes] | None = None,
) -> dict:
    limits = limits or AssessmentLimits()
    limits.validate()
    started = time.perf_counter()
    root = Path(target_root).resolve(strict=True)
    if not root.is_dir() or _is_reparse_or_symlink(root):
        raise ValueError("B5-1 target must be a real directory, not symlink/reparse")

    fingerprint = ""
    target_contract_valid = False
    contract_error = ""
    try:
        rr6.validate_offline_windows_root(root)
        fingerprint = rr6.target_fingerprint(root)
        target_contract_valid = True
    except Exception as exc:
        contract_error = f"{type(exc).__name__}:{exc}"

    critical_present, critical_missing = _critical_inventory(root)
    records: list[ProbeRecord] = []
    counters = {
        "probed": 0,
        "readable": 0,
        "access_denied": 0,
        "io_errors": 0,
        "slow_reads": 0,
        "persistence_review_items": 0,
        "critical_missing": len(critical_missing),
    }
    total_bytes = 0
    truncated_by_files = False
    truncated_by_bytes = False
    truncated_by_time = False

    for path, category in _candidate_paths(root):
        if counters["probed"] >= limits.max_files:
            truncated_by_files = True
            break
        if time.perf_counter() - started > limits.max_elapsed_sec:
            truncated_by_time = True
            break
        rel = str(path.relative_to(root)).replace("\\", "/")
        reasons: list[str] = []
        probe_started = time.perf_counter()
        size = 0
        sample_hash = ""
        status = "readable"
        try:
            st = path.stat(follow_symlinks=False)
            if not stat.S_ISREG(st.st_mode):
                continue
            size = int(st.st_size)
            requested = min(size, limits.sample_bytes)
            if total_bytes + requested > limits.max_total_bytes:
                truncated_by_bytes = True
                break
            sample_hash, sampled = _sample_file(path, limits.sample_bytes, reader)
            total_bytes += sampled
            counters["readable"] += 1
            suffix = path.suffix.casefold()
            name = path.name.casefold()
            if category == "persistence" and (suffix in ACTIVE_SUFFIXES or name.count(".") >= 2):
                reasons.append("persistence_active_content_review")
                counters["persistence_review_items"] += 1
        except PermissionError:
            status = "access_denied"
            reasons.append("permission_denied")
            counters["access_denied"] += 1
        except OSError as exc:
            status = "io_error"
            reasons.append(f"os_error:{int(getattr(exc, 'winerror', 0) or getattr(exc, 'errno', 0) or 0)}")
            counters["io_errors"] += 1
        elapsed_ms = round((time.perf_counter() - probe_started) * 1000.0, 3)
        if elapsed_ms >= limits.slow_read_ms:
            reasons.append("slow_read")
            counters["slow_reads"] += 1
        counters["probed"] += 1
        records.append(ProbeRecord(rel, category, size, status, sample_hash, elapsed_ms, tuple(reasons)))

    if not target_contract_valid or critical_missing:
        state = STATE_DAMAGED
        reason = "critical_target_contract_or_files_missing"
    elif counters["access_denied"] > 0:
        state = STATE_ACCESS_RESTRICTED
        reason = "one_or_more_required_probes_access_denied"
    elif counters["io_errors"] > 0 or counters["slow_reads"] > 0 or truncated_by_time:
        state = STATE_IO_DEGRADED
        reason = "io_errors_slow_reads_or_time_budget"
    elif counters["persistence_review_items"] > 0:
        state = STATE_REVIEW
        reason = "persistence_items_require_operator_review"
    else:
        state = STATE_HEALTHY
        reason = "bounded_read_only_probe_clean"

    core = {
        "schema": SCHEMA,
        "profile": PROFILE,
        "target_root": str(root),
        "target_fingerprint": fingerprint,
        "target_contract_valid": target_contract_valid,
        "target_contract_error": contract_error,
        "state": state,
        "reason": reason,
        "critical_present": critical_present,
        "critical_missing": critical_missing,
        "limits": asdict(limits),
        "counters": counters,
        "total_sampled_bytes": total_bytes,
        "truncated_by_files": truncated_by_files,
        "truncated_by_bytes": truncated_by_bytes,
        "truncated_by_time": truncated_by_time,
        "records": [r.to_record() for r in records],
        "safety": {
            "target_read_only": True,
            "write_attempted": False,
            "target_execution": False,
            "registry_write": False,
            "boot_write": False,
            "file_delete": False,
            "repair_execution": False,
            "quarantine_execution": False,
            "network_required": False,
            "cloud_required": False,
            "automatic_action": False,
        },
    }
    assessment_sha = hashlib.sha256(_canonical_json(core)).hexdigest()
    return {
        **core,
        "created_utc": _utc_now(),
        "elapsed_ms": round((time.perf_counter() - started) * 1000.0, 3),
        "assessment_sha256": assessment_sha,
    }


def write_assessment(result: dict, output_path: Path, target_root: Path) -> Path:
    root = Path(target_root).resolve(strict=True)
    output = Path(output_path).resolve(strict=False)
    try:
        output.relative_to(root)
        raise ValueError("B5-1 assessment output must be outside target")
    except ValueError as exc:
        if str(exc).startswith("B5-1 assessment output"):
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
    parser = argparse.ArgumentParser(description="BC Sentinel Beta5 B5-1 hostile/damaged offline target assessment")
    parser.add_argument("--target-root", required=True)
    parser.add_argument("--output")
    parser.add_argument("--max-files", type=int, default=512)
    parser.add_argument("--max-total-bytes", type=int, default=16 * 1024 * 1024)
    parser.add_argument("--max-elapsed-sec", type=float, default=8.0)
    parser.add_argument("--sample-bytes", type=int, default=DEFAULT_SAMPLE_BYTES)
    parser.add_argument("--slow-read-ms", type=float, default=250.0)
    args = parser.parse_args(argv)
    try:
        limits = AssessmentLimits(args.max_files, args.max_total_bytes, args.max_elapsed_sec, args.sample_bytes, args.slow_read_ms)
        result = assess_target(Path(args.target_root), limits=limits)
        if args.output:
            write_assessment(result, Path(args.output), Path(args.target_root))
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["state"] in {STATE_HEALTHY, STATE_REVIEW, STATE_IO_DEGRADED} else 3
    except Exception as exc:
        print(json.dumps({"passed": False, "profile": PROFILE, "state": STATE_REFUSED, "stage": "assessment", "reason": f"{type(exc).__name__}:{exc}"}, indent=2))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import stat
import subprocess
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Final, Iterable

from sentinel import rescue_integrity_certification as rr6

PROFILE: Final[str] = "v0.11.0-beta.5-b50"
RESULT_SCHEMA: Final[str] = "bc-sentinel-beta5-target-discovery-v1"

STATE_READY: Final[str] = "READY"
STATE_LOCKED: Final[str] = "LOCKED"
STATE_ACCESS_DENIED: Final[str] = "ACCESS_DENIED"
STATE_INCOMPLETE: Final[str] = "INCOMPLETE"
STATE_UNSUPPORTED: Final[str] = "UNSUPPORTED"
STATE_ERROR: Final[str] = "ERROR"

MAX_ROOTS_HARD: Final[int] = 128
DEFAULT_MAX_ROOTS: Final[int] = 64
BITLOCKER_PROBE_TIMEOUT_SEC: Final[float] = 4.0

WINDOWS_MARKERS: Final[tuple[str, ...]] = (
    "Windows",
    "Windows/System32",
    "Windows/System32/config/SYSTEM",
    "Windows/System32/config/SOFTWARE",
    "Windows/System32/ntoskrnl.exe",
)


@dataclass(frozen=True)
class DiscoveryLimits:
    max_roots: int = DEFAULT_MAX_ROOTS
    probe_children: bool = True
    max_children_per_root: int = 32
    bitlocker_probe_timeout_sec: float = BITLOCKER_PROBE_TIMEOUT_SEC

    def validate(self) -> None:
        if not (1 <= int(self.max_roots) <= MAX_ROOTS_HARD):
            raise ValueError("B5-0 max_roots outside bounded limit")
        if not (0 <= int(self.max_children_per_root) <= 128):
            raise ValueError("B5-0 max_children_per_root outside bounded limit")
        if not (0.5 <= float(self.bitlocker_probe_timeout_sec) <= 15.0):
            raise ValueError("B5-0 bitlocker probe timeout outside bounded limit")


@dataclass(frozen=True)
class CandidateRecord:
    root: str
    normalized_root: str
    discovery_source: str
    state: str
    reason: str
    markers_present: tuple[str, ...]
    markers_missing: tuple[str, ...]
    target_fingerprint: str
    bitlocker: dict
    write_attempted: bool
    elapsed_ms: float

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


def _canonical_path_text(path: Path) -> str:
    try:
        return str(path.resolve(strict=False))
    except Exception:
        return os.path.abspath(os.fspath(path))


def _drive_letter_root(path: Path) -> str | None:
    if os.name != "nt":
        return None
    text = _canonical_path_text(path)
    drive, _ = os.path.splitdrive(text)
    if len(drive) == 2 and drive[1] == ":":
        return drive.upper() + "\\"
    return None


def _live_system_root() -> str | None:
    if os.name != "nt":
        return None
    drive = os.environ.get("SystemDrive", "").strip().rstrip("\\/")
    if len(drive) == 2 and drive[1] == ":":
        return drive.upper() + "\\"
    return None


def _is_live_system_root(path: Path) -> bool:
    live = _live_system_root()
    if not live:
        return False
    try:
        candidate = os.path.normcase(os.path.abspath(os.fspath(path))).rstrip("\\/")
        live_norm = os.path.normcase(os.path.abspath(live)).rstrip("\\/")
        return candidate == live_norm
    except Exception:
        return False


def enumerate_windows_volume_roots(*, max_roots: int = DEFAULT_MAX_ROOTS) -> list[Path]:
    if not (1 <= int(max_roots) <= MAX_ROOTS_HARD):
        raise ValueError("B5-0 max_roots outside bounded limit")
    if os.name != "nt":
        return []
    buffer_len = 4096
    buffer = ctypes.create_unicode_buffer(buffer_len)
    count = int(ctypes.windll.kernel32.GetLogicalDriveStringsW(buffer_len, buffer))
    if count <= 0 or count >= buffer_len:
        return []
    roots = [Path(item) for item in buffer[:count].split("\x00") if item]
    roots = sorted(roots, key=lambda p: str(p).casefold())
    return roots[:max_roots]


def _probe_bitlocker_windows(root: Path, *, timeout_sec: float) -> dict:
    drive = _drive_letter_root(root)
    if os.name != "nt" or drive is None:
        return {"provider": "not_applicable", "available": False, "locked": None, "reason": "non_windows_or_non_drive_root"}

    ps = (
        "$ErrorActionPreference='Stop';"
        "$d='" + drive.replace("'", "''") + "';"
        "$v=Get-CimInstance -Namespace 'root/CIMV2/Security/MicrosoftVolumeEncryption' "
        "-ClassName Win32_EncryptableVolume -Filter (\"DriveLetter='\" + $d.TrimEnd('\\') + \"'\") -ErrorAction Stop | Select-Object -First 1;"
        "if($null -eq $v){'{\"available\":false,\"reason\":\"no_encryptable_volume_record\"}'}else{"
        "[ordered]@{available=$true;LockStatus=[int]$v.LockStatus;ProtectionStatus=[int]$v.ProtectionStatus;ConversionStatus=[int]$v.ConversionStatus}|ConvertTo-Json -Compress}"
    )
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True,
            text=True,
            timeout=float(timeout_sec),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        elapsed_ms = round((time.perf_counter() - started) * 1000.0, 3)
        stdout = (completed.stdout or "").strip()
        if completed.returncode != 0:
            return {
                "provider": "cim_bitlocker",
                "available": False,
                "locked": None,
                "reason": "provider_query_failed",
                "exit_code": int(completed.returncode),
                "stderr": (completed.stderr or "").strip()[-500:],
                "elapsed_ms": elapsed_ms,
            }
        try:
            payload = json.loads(stdout) if stdout else {}
        except Exception as exc:
            return {
                "provider": "cim_bitlocker",
                "available": False,
                "locked": None,
                "reason": f"provider_output_unreadable:{type(exc).__name__}",
                "exit_code": int(completed.returncode),
                "elapsed_ms": elapsed_ms,
            }
        if not bool(payload.get("available")):
            return {
                "provider": "cim_bitlocker",
                "available": False,
                "locked": None,
                "reason": str(payload.get("reason") or "provider_record_unavailable"),
                "exit_code": int(completed.returncode),
                "elapsed_ms": elapsed_ms,
            }
        lock_status = int(payload.get("LockStatus", -1))
        return {
            "provider": "cim_bitlocker",
            "available": True,
            "locked": lock_status == 1,
            "lock_status": lock_status,
            "protection_status": int(payload.get("ProtectionStatus", -1)),
            "conversion_status": int(payload.get("ConversionStatus", -1)),
            "exit_code": int(completed.returncode),
            "elapsed_ms": elapsed_ms,
        }
    except subprocess.TimeoutExpired:
        return {
            "provider": "cim_bitlocker",
            "available": False,
            "locked": None,
            "reason": "provider_timeout",
            "timeout_sec": float(timeout_sec),
            "elapsed_ms": round((time.perf_counter() - started) * 1000.0, 3),
        }
    except Exception as exc:
        return {
            "provider": "cim_bitlocker",
            "available": False,
            "locked": None,
            "reason": f"provider_exception:{type(exc).__name__}:{exc}",
            "elapsed_ms": round((time.perf_counter() - started) * 1000.0, 3),
        }


def _marker_inventory(root: Path) -> tuple[tuple[str, ...], tuple[str, ...]]:
    present: list[str] = []
    missing: list[str] = []
    for rel in WINDOWS_MARKERS:
        try:
            path = root.joinpath(*rel.split("/"))
            exists = path.is_dir() if rel in {"Windows", "Windows/System32"} else path.is_file()
        except PermissionError:
            raise
        except OSError:
            exists = False
        (present if exists else missing).append(rel)
    return tuple(present), tuple(missing)


def _classify_exception(exc: BaseException, bitlocker: dict) -> tuple[str, str]:
    if bitlocker.get("locked") is True:
        return STATE_LOCKED, "bitlocker_volume_locked"
    if isinstance(exc, PermissionError):
        return STATE_ACCESS_DENIED, "permission_denied"
    winerror = int(getattr(exc, "winerror", 0) or 0)
    errno = int(getattr(exc, "errno", 0) or 0)
    if winerror in {5} or errno in {13}:
        return STATE_ACCESS_DENIED, f"access_denied_error:{winerror or errno}"
    if winerror in {21, 32, 33}:
        return STATE_LOCKED, f"volume_not_ready_or_locked_error:{winerror}"
    return STATE_ERROR, f"{type(exc).__name__}:{exc}"


def classify_candidate(
    root_in: Path,
    *,
    discovery_source: str,
    bitlocker_probe: Callable[[Path], dict] | None = None,
    bitlocker_timeout_sec: float = BITLOCKER_PROBE_TIMEOUT_SEC,
) -> CandidateRecord:
    started = time.perf_counter()
    root = Path(root_in)
    normalized = _canonical_path_text(root)

    if _is_live_system_root(root):
        return CandidateRecord(
            root=str(root), normalized_root=normalized, discovery_source=discovery_source,
            state=STATE_UNSUPPORTED, reason="live_system_volume_refused", markers_present=(), markers_missing=WINDOWS_MARKERS,
            target_fingerprint="", bitlocker={"provider": "skipped", "available": False, "locked": None, "reason": "live_system_volume"},
            write_attempted=False, elapsed_ms=round((time.perf_counter() - started) * 1000.0, 3),
        )

    bitlocker_probe = bitlocker_probe or (lambda p: _probe_bitlocker_windows(p, timeout_sec=bitlocker_timeout_sec))
    try:
        bitlocker = bitlocker_probe(root)
    except Exception as exc:
        bitlocker = {"provider": "probe_exception", "available": False, "locked": None, "reason": f"{type(exc).__name__}:{exc}"}

    try:
        if bitlocker.get("locked") is True:
            return CandidateRecord(
                root=str(root), normalized_root=normalized, discovery_source=discovery_source,
                state=STATE_LOCKED, reason="bitlocker_volume_locked", markers_present=(), markers_missing=WINDOWS_MARKERS,
                target_fingerprint="", bitlocker=bitlocker, write_attempted=False,
                elapsed_ms=round((time.perf_counter() - started) * 1000.0, 3),
            )
        resolved = root.resolve(strict=True)
        normalized = str(resolved)
        if not resolved.is_dir():
            return CandidateRecord(str(root), normalized, discovery_source, STATE_UNSUPPORTED, "not_a_directory", (), WINDOWS_MARKERS, "", bitlocker, False, round((time.perf_counter() - started) * 1000.0, 3))
        if _is_reparse_or_symlink(resolved):
            return CandidateRecord(str(root), normalized, discovery_source, STATE_UNSUPPORTED, "root_symlink_or_reparse_refused", (), WINDOWS_MARKERS, "", bitlocker, False, round((time.perf_counter() - started) * 1000.0, 3))

        present, missing = _marker_inventory(resolved)
        if not present:
            state, reason, fingerprint = STATE_UNSUPPORTED, "no_windows_markers", ""
        elif missing:
            state, reason, fingerprint = STATE_INCOMPLETE, "windows_markers_incomplete", ""
        else:
            rr6.validate_offline_windows_root(resolved)
            fingerprint = rr6.target_fingerprint(resolved)
            state, reason = STATE_READY, "validated_by_rr6_target_contract"
        return CandidateRecord(
            root=str(root), normalized_root=normalized, discovery_source=discovery_source, state=state, reason=reason,
            markers_present=present, markers_missing=missing, target_fingerprint=fingerprint, bitlocker=bitlocker,
            write_attempted=False, elapsed_ms=round((time.perf_counter() - started) * 1000.0, 3),
        )
    except Exception as exc:
        state, reason = _classify_exception(exc, bitlocker)
        return CandidateRecord(
            root=str(root), normalized_root=normalized, discovery_source=discovery_source, state=state, reason=reason,
            markers_present=(), markers_missing=WINDOWS_MARKERS, target_fingerprint="", bitlocker=bitlocker,
            write_attempted=False, elapsed_ms=round((time.perf_counter() - started) * 1000.0, 3),
        )


def _expand_explicit_root(root: Path, limits: DiscoveryLimits) -> list[tuple[Path, str]]:
    items: list[tuple[Path, str]] = [(root, "explicit")]
    if not limits.probe_children or limits.max_children_per_root <= 0:
        return items
    try:
        resolved = root.resolve(strict=True)
        if not resolved.is_dir() or _is_reparse_or_symlink(resolved):
            return items
        children: list[Path] = []
        with os.scandir(resolved) as entries:
            for entry in entries:
                if len(children) >= limits.max_children_per_root:
                    break
                try:
                    p = Path(entry.path)
                    if entry.is_dir(follow_symlinks=False) and not entry.is_symlink() and not _is_reparse_or_symlink(p):
                        children.append(p)
                except OSError:
                    continue
        for child in sorted(children, key=lambda p: str(p).casefold()):
            items.append((child, "explicit_child"))
    except OSError:
        pass
    return items


def discover_targets(
    explicit_roots: Iterable[Path] = (),
    *,
    include_windows_volumes: bool = True,
    limits: DiscoveryLimits | None = None,
    bitlocker_probe: Callable[[Path], dict] | None = None,
) -> dict:
    limits = limits or DiscoveryLimits()
    limits.validate()
    started = time.perf_counter()
    seed = f"{time.time_ns()}|{os.getpid()}|{os.name}"
    session_id = "B50-" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16].upper()
    correlation_id = hashlib.sha256((session_id + "|target-discovery").encode("utf-8")).hexdigest()[:24]

    queued: list[tuple[Path, str]] = []
    for root in explicit_roots:
        queued.extend(_expand_explicit_root(Path(root), limits))
        if len(queued) >= limits.max_roots:
            break
    if include_windows_volumes and len(queued) < limits.max_roots:
        for volume in enumerate_windows_volume_roots(max_roots=limits.max_roots - len(queued)):
            queued.append((volume, "windows_volume"))

    dedup: dict[str, tuple[Path, str]] = {}
    for path, source in queued:
        key = _canonical_path_text(path).casefold()
        if key not in dedup:
            dedup[key] = (path, source)
        if len(dedup) >= limits.max_roots:
            break

    records = [
        classify_candidate(path, discovery_source=source, bitlocker_probe=bitlocker_probe, bitlocker_timeout_sec=limits.bitlocker_probe_timeout_sec)
        for path, source in sorted(dedup.values(), key=lambda item: _canonical_path_text(item[0]).casefold())
    ]
    counts = {state: sum(1 for item in records if item.state == state) for state in (STATE_READY, STATE_LOCKED, STATE_ACCESS_DENIED, STATE_INCOMPLETE, STATE_UNSUPPORTED, STATE_ERROR)}
    return {
        "schema": RESULT_SCHEMA,
        "profile": PROFILE,
        "session_id": session_id,
        "correlation_id": correlation_id,
        "created_utc": _utc_now(),
        "limits": asdict(limits),
        "roots_considered": len(records),
        "counts": counts,
        "candidates": [item.to_record() for item in records],
        "safety": {
            "read_only_discovery": True,
            "write_attempted": False,
            "unlock_attempted": False,
            "mount_mutation": False,
            "format_disk": False,
            "partition_write": False,
            "bcd_write": False,
            "filesystem_repair": False,
            "target_execution": False,
            "service_install": False,
            "driver_install": False,
            "network_required": False,
            "cloud_required": False,
        },
        "elapsed_ms": round((time.perf_counter() - started) * 1000.0, 3),
    }


def write_discovery_result(result: dict, output_path: Path) -> Path:
    output = output_path.resolve(strict=False)
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=output.name + ".", suffix=".tmp", dir=str(output.parent))
    os.close(fd)
    temp = Path(temp_name)
    try:
        temp.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(temp, output)
    finally:
        temp.unlink(missing_ok=True)
    return output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel Beta5 B5-0 read-only real-world target discovery")
    parser.add_argument("roots", nargs="*")
    parser.add_argument("--no-windows-volumes", action="store_true")
    parser.add_argument("--no-child-probe", action="store_true")
    parser.add_argument("--max-roots", type=int, default=DEFAULT_MAX_ROOTS)
    parser.add_argument("--max-children-per-root", type=int, default=32)
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    try:
        result = discover_targets(
            [Path(p) for p in args.roots],
            include_windows_volumes=not args.no_windows_volumes,
            limits=DiscoveryLimits(
                max_roots=args.max_roots,
                probe_children=not args.no_child_probe,
                max_children_per_root=args.max_children_per_root,
            ),
        )
        if args.output:
            write_discovery_result(result, Path(args.output))
        print(json.dumps(result, indent=2))
        return 0
    except Exception as exc:
        print(json.dumps({
            "passed": False,
            "profile": PROFILE,
            "stage": "target_discovery",
            "reason": f"{type(exc).__name__}: {exc}",
        }, indent=2))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import shutil
import stat
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Final, Iterable

PROFILE: Final[str] = "v0.11.0-beta.3-rr2"
DRIVE_REMOVABLE: Final[int] = 2
MAX_FILES_HARD: Final[int] = 20_000
MAX_TOTAL_BYTES_HARD: Final[int] = 4 * 1024 * 1024 * 1024


@dataclass(frozen=True)
class UsbPrepareLimits:
    max_files: int = 10_000
    max_total_bytes: int = 2 * 1024 * 1024 * 1024

    def validate(self) -> None:
        if not (1 <= int(self.max_files) <= MAX_FILES_HARD):
            raise ValueError("RR2 max_files outside bounded limit")
        if not (1 <= int(self.max_total_bytes) <= MAX_TOTAL_BYTES_HARD):
            raise ValueError("RR2 max_total_bytes outside bounded limit")


@dataclass(frozen=True)
class UsbManifestRecord:
    relative_path: str
    size: int
    sha256: str

    def to_record(self) -> dict:
        return asdict(self)


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_reparse_or_symlink(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        st = path.stat(follow_symlinks=False)
        attrs = getattr(st, "st_file_attributes", 0)
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        return bool(attrs & reparse_flag)
    except OSError:
        return True


def _iter_payload_files(root: Path, *, max_files: int) -> Iterable[Path]:
    emitted = 0
    stack = [root]
    while stack:
        current = stack.pop()
        with os.scandir(current) as entries:
            dirs: list[Path] = []
            files: list[Path] = []
            for entry in entries:
                p = Path(entry.path)
                try:
                    if entry.is_symlink() or _is_reparse_or_symlink(p):
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        dirs.append(p)
                    elif entry.is_file(follow_symlinks=False):
                        files.append(p)
                except OSError:
                    continue
            for file_path in sorted(files, key=lambda p: p.name.casefold()):
                emitted += 1
                if emitted > max_files:
                    raise ValueError("RR2 payload exceeds max_files")
                yield file_path
            for directory in sorted(dirs, key=lambda p: p.name.casefold(), reverse=True):
                stack.append(directory)


def _drive_root(path: Path) -> str:
    anchor = path.resolve().anchor
    return anchor or str(path.resolve())


def _windows_drive_type(path: Path) -> int | None:
    if os.name != "nt":
        return None
    root = _drive_root(path)
    return int(ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(root)))


def _is_system_volume(path: Path) -> bool:
    system_drive = os.environ.get("SystemDrive", "").rstrip("\\/").casefold()
    drive = path.resolve().drive.rstrip("\\/").casefold()
    return bool(system_drive and drive and system_drive == drive)


def _assert_no_overlap(source: Path, destination: Path) -> None:
    src = source.resolve()
    dst = destination.resolve()
    try:
        dst.relative_to(src)
        raise ValueError("RR2 destination may not be inside source payload")
    except ValueError as exc:
        if str(exc).startswith("RR2 destination"):
            raise
    try:
        src.relative_to(dst)
        raise ValueError("RR2 source payload may not be inside destination")
    except ValueError as exc:
        if str(exc).startswith("RR2 source payload"):
            raise


def _validate_destination(destination: Path, *, simulation: bool) -> None:
    if not destination.exists() or not destination.is_dir():
        raise ValueError("RR2 destination must be an existing directory")
    if _is_reparse_or_symlink(destination):
        raise ValueError("RR2 destination may not be a symlink/reparse point")
    if any(destination.iterdir()):
        raise ValueError("RR2 destination must be empty; existing media content is never deleted")
    resolved = destination.resolve()
    if resolved == Path(resolved.anchor):
        raise ValueError("RR2 refuses writing directly to a filesystem root")
    if not simulation:
        if os.name != "nt":
            raise ValueError("RR2 real-media preparation currently requires Windows")
        if _is_system_volume(resolved):
            raise ValueError("RR2 refuses the Windows system volume")
        drive_type = _windows_drive_type(resolved)
        if drive_type != DRIVE_REMOVABLE:
            raise ValueError(f"RR2 destination drive is not removable (drive_type={drive_type})")


def _write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _append_audit(path: Path, record: dict) -> None:
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def prepare_rescue_usb(
    source_payload: Path,
    destination: Path,
    *,
    simulation: bool = False,
    limits: UsbPrepareLimits | None = None,
) -> dict:
    limits = limits or UsbPrepareLimits()
    limits.validate()
    source = source_payload.resolve(strict=True)
    if not source.is_dir():
        raise ValueError("RR2 source_payload must be an existing directory")
    _validate_destination(destination, simulation=simulation)
    _assert_no_overlap(source, destination)

    session_seed = f"{source}|{destination.resolve()}|{time.time_ns()}|{os.getpid()}"
    session_id = "RR2-" + hashlib.sha256(session_seed.encode("utf-8")).hexdigest()[:16].upper()
    correlation_id = hashlib.sha256((session_id + "|usb").encode("utf-8")).hexdigest()[:20]
    started = time.perf_counter()
    audit_path = destination / "rescue-usb-audit.jsonl"

    def audit(stage: str, status: str, reason: str, **extra: object) -> None:
        _append_audit(
            audit_path,
            {
                "profile": PROFILE,
                "session_id": session_id,
                "correlation_id": correlation_id,
                "stage": stage,
                "status": status,
                "reason": reason,
                "source": str(source),
                "destination": str(destination.resolve()),
                "elapsed_ms": round((time.perf_counter() - started) * 1000.0, 3),
                **extra,
            },
        )

    audit("prepare_start", "ok", "validated_non_destructive_destination", simulation=simulation)
    payload_root = destination / "payload"
    payload_root.mkdir()
    records: list[UsbManifestRecord] = []
    total_bytes = 0
    try:
        for src in _iter_payload_files(source, max_files=limits.max_files):
            rel = src.relative_to(source)
            st = src.stat(follow_symlinks=False)
            if not stat.S_ISREG(st.st_mode):
                continue
            total_bytes += int(st.st_size)
            if total_bytes > limits.max_total_bytes:
                raise ValueError("RR2 payload exceeds max_total_bytes")
            dst = payload_root / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst, follow_symlinks=False)
            source_hash = _sha256_file(src)
            copied_hash = _sha256_file(dst)
            if source_hash != copied_hash:
                raise RuntimeError(f"RR2 copy verification mismatch: {rel}")
            records.append(UsbManifestRecord(str(rel).replace("\\", "/"), int(st.st_size), copied_hash))

        manifest = {
            "profile": PROFILE,
            "session_id": session_id,
            "correlation_id": correlation_id,
            "created_utc": _utc_now(),
            "simulation": bool(simulation),
            "source_payload": str(source),
            "destination": str(destination.resolve()),
            "limits": asdict(limits),
            "summary": {"files": len(records), "total_bytes": total_bytes},
            "records": [record.to_record() for record in records],
            "safety": {
                "format_disk": False,
                "partition_write": False,
                "boot_sector_write": False,
                "bootloader_install": False,
                "bcd_write": False,
                "firmware_write": False,
                "registry_write": False,
                "target_filesystem_write": False,
                "file_delete": False,
                "repair_engine_enabled": False,
                "quarantine_execution_enabled": False,
                "recovery_certification_enabled": False,
                "network_required": False,
                "cloud_required": False,
            },
        }
        _write_json(destination / "rescue-usb-manifest.json", manifest)
        verification = verify_rescue_usb(destination)
        if not verification["passed"]:
            raise RuntimeError("RR2 post-copy verification failed: " + "; ".join(verification["errors"]))
        audit("prepare_complete", "ok", "payload_copied_and_verified", files=len(records), total_bytes=total_bytes)
        return {**manifest, "verification": verification}
    except Exception as exc:
        audit("prepare_fail", "fail", f"{type(exc).__name__}: {exc}", files=len(records), total_bytes=total_bytes)
        raise


def verify_rescue_usb(destination: Path) -> dict:
    root = destination.resolve(strict=True)
    manifest_path = root / "rescue-usb-manifest.json"
    payload_root = root / "payload"
    errors: list[str] = []
    if not manifest_path.is_file():
        return {"profile": PROFILE, "passed": False, "errors": ["manifest_missing"], "checked": 0}
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"profile": PROFILE, "passed": False, "errors": [f"manifest_unreadable:{type(exc).__name__}"], "checked": 0}
    if manifest.get("profile") != PROFILE:
        errors.append("profile_mismatch")
    expected: dict[str, dict] = {str(item["relative_path"]): item for item in manifest.get("records", [])}
    actual_paths: set[str] = set()
    checked = 0
    if not payload_root.is_dir():
        errors.append("payload_missing")
    else:
        try:
            for path in _iter_payload_files(payload_root, max_files=MAX_FILES_HARD):
                rel = str(path.relative_to(payload_root)).replace("\\", "/")
                actual_paths.add(rel)
                item = expected.get(rel)
                if item is None:
                    errors.append(f"unexpected_file:{rel}")
                    continue
                checked += 1
                if int(path.stat().st_size) != int(item.get("size", -1)):
                    errors.append(f"size_mismatch:{rel}")
                    continue
                if _sha256_file(path) != str(item.get("sha256", "")):
                    errors.append(f"sha256_mismatch:{rel}")
        except Exception as exc:
            errors.append(f"verification_error:{type(exc).__name__}:{exc}")
    missing = sorted(set(expected) - actual_paths)
    errors.extend(f"missing_file:{item}" for item in missing)
    return {"profile": PROFILE, "passed": not errors, "errors": errors, "checked": checked, "expected": len(expected)}


def discover_offline_windows(roots: Iterable[Path], *, max_candidates: int = 32) -> list[dict]:
    if not (1 <= int(max_candidates) <= 128):
        raise ValueError("RR2 max_candidates outside bounded limit")
    candidates: list[dict] = []
    for root_in in roots:
        if len(candidates) >= max_candidates:
            break
        try:
            root = Path(root_in).resolve(strict=True)
        except OSError:
            continue
        if not root.is_dir() or _is_reparse_or_symlink(root):
            continue
        probe_roots = [root]
        try:
            with os.scandir(root) as entries:
                for entry in entries:
                    if len(probe_roots) >= max_candidates:
                        break
                    try:
                        p = Path(entry.path)
                        if entry.is_dir(follow_symlinks=False) and not entry.is_symlink() and not _is_reparse_or_symlink(p):
                            probe_roots.append(p)
                    except OSError:
                        continue
        except OSError:
            pass
        for candidate in probe_roots:
            system_hive = candidate / "Windows" / "System32" / "config" / "SYSTEM"
            kernel = candidate / "Windows" / "System32" / "ntoskrnl.exe"
            if system_hive.is_file() and kernel.is_file():
                candidates.append(
                    {
                        "root": str(candidate),
                        "system_hive_present": True,
                        "kernel_present": True,
                        "write_attempted": False,
                    }
                )
                if len(candidates) >= max_candidates:
                    break
    return candidates


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel RR2 Rescue USB safe preparation/verification")
    sub = parser.add_subparsers(dest="command", required=True)
    prepare = sub.add_parser("prepare")
    prepare.add_argument("--source", required=True)
    prepare.add_argument("--destination", required=True)
    prepare.add_argument("--simulation", action="store_true")
    prepare.add_argument("--max-files", type=int, default=10_000)
    prepare.add_argument("--max-total-bytes", type=int, default=2 * 1024 * 1024 * 1024)
    verify = sub.add_parser("verify")
    verify.add_argument("--destination", required=True)
    discover = sub.add_parser("discover")
    discover.add_argument("roots", nargs="+")
    discover.add_argument("--max-candidates", type=int, default=32)
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            result = prepare_rescue_usb(
                Path(args.source),
                Path(args.destination),
                simulation=bool(args.simulation),
                limits=UsbPrepareLimits(max_files=args.max_files, max_total_bytes=args.max_total_bytes),
            )
            print(json.dumps({"passed": True, "profile": PROFILE, "summary": result["summary"]}, indent=2))
            return 0
        if args.command == "verify":
            result = verify_rescue_usb(Path(args.destination))
            print(json.dumps(result, indent=2))
            return 0 if result["passed"] else 3
        result = {"profile": PROFILE, "passed": True, "candidates": discover_offline_windows([Path(p) for p in args.roots], max_candidates=args.max_candidates)}
        print(json.dumps(result, indent=2))
        return 0
    except Exception as exc:
        print(json.dumps({"passed": False, "profile": PROFILE, "stage": args.command, "reason": f"{type(exc).__name__}: {exc}"}, indent=2))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

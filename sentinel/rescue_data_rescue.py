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
from typing import Final, Iterable

PROFILE: Final[str] = "v0.11.0-beta.3-rr5"
INTEL_SCHEMA: Final[str] = "bc-sentinel-offline-intel-v1"
MAX_FILES_HARD: Final[int] = 100_000
MAX_TOTAL_BYTES_HARD: Final[int] = 512 * 1024 * 1024 * 1024
MAX_FILE_BYTES_HARD: Final[int] = 16 * 1024 * 1024 * 1024
MAX_DEPTH_HARD: Final[int] = 64

PASSIVE_EXTENSIONS: Final[frozenset[str]] = frozenset(
    {
        ".txt", ".md", ".csv", ".tsv", ".rtf",
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".tif", ".tiff", ".heic",
        ".mp3", ".wav", ".flac", ".m4a", ".aac", ".ogg",
        ".mp4", ".mov", ".avi", ".mkv", ".webm",
        ".pdf", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp",
    }
)
ACTIVE_OR_RISKY_EXTENSIONS: Final[frozenset[str]] = frozenset(
    {
        ".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".drv", ".ocx", ".msi", ".msix", ".appx",
        ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta",
        ".lnk", ".url", ".reg", ".chm", ".jar",
        ".docm", ".dotm", ".xlsm", ".xltm", ".xlam", ".pptm", ".ppsm", ".potm",
        ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".iso", ".img", ".vhd", ".vhdx",
    }
)


@dataclass(frozen=True)
class RescueLimits:
    max_files: int = 20_000
    max_total_bytes: int = 128 * 1024 * 1024 * 1024
    max_file_bytes: int = 4 * 1024 * 1024 * 1024
    max_depth: int = 32

    def validate(self) -> None:
        if not (1 <= int(self.max_files) <= MAX_FILES_HARD):
            raise ValueError("RR5 max_files outside bounded limit")
        if not (1 <= int(self.max_total_bytes) <= MAX_TOTAL_BYTES_HARD):
            raise ValueError("RR5 max_total_bytes outside bounded limit")
        if not (1 <= int(self.max_file_bytes) <= MAX_FILE_BYTES_HARD):
            raise ValueError("RR5 max_file_bytes outside bounded limit")
        if not (1 <= int(self.max_depth) <= MAX_DEPTH_HARD):
            raise ValueError("RR5 max_depth outside bounded limit")


@dataclass(frozen=True)
class RescueRecord:
    relative_path: str
    size: int
    sha256: str
    disposition: str
    destination_relative_path: str
    status: str
    reason: str
    ioc_name: str = ""

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
        attrs = int(getattr(st, "st_file_attributes", 0) or 0)
        reparse = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
        return bool(attrs & reparse)
    except OSError:
        return True


def _is_inside(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def validate_offline_windows_root(root: Path) -> Path:
    resolved = root.resolve(strict=True)
    if not resolved.is_dir() or _is_reparse_or_symlink(resolved):
        raise ValueError("RR5 offline source root invalid")
    system_hive = resolved / "Windows" / "System32" / "config" / "SYSTEM"
    kernel = resolved / "Windows" / "System32" / "ntoskrnl.exe"
    if not system_hive.is_file() or not kernel.is_file():
        raise ValueError("RR5 source is not a validated offline Windows root")
    return resolved


def _safe_relative_selection(value: str) -> str:
    text = str(value or "").replace("\\", "/").strip().strip("/")
    if not text or text.startswith("/") or ":" in text:
        raise ValueError("RR5 include path invalid")
    parts = text.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError("RR5 include path traversal refused")
    if parts[0].casefold() != "users" or len(parts) < 2:
        raise ValueError("RR5 first checkpoint only permits explicit selections under Users/<profile>")
    return "/".join(parts)


def _resolve_selected(root: Path, relative: str) -> Path:
    rel = Path(relative.replace("/", os.sep))
    candidate = root / rel
    if not candidate.exists():
        raise ValueError(f"RR5 selected path missing: {relative}")
    current = root
    for part in rel.parts:
        current = current / part
        if _is_reparse_or_symlink(current):
            raise ValueError(f"RR5 selected path traverses symlink/reparse point: {relative}")
    return candidate


def _validate_destination(destination: Path, root: Path) -> Path:
    dest = destination.resolve()
    if _is_inside(dest, root) or _is_inside(root, dest):
        raise ValueError("RR5 destination/source overlap refused")
    parent = dest.parent
    parent.mkdir(parents=True, exist_ok=True)
    if _is_reparse_or_symlink(parent):
        raise ValueError("RR5 destination parent symlink/reparse refused")
    if dest.exists():
        if not dest.is_dir() or _is_reparse_or_symlink(dest):
            raise ValueError("RR5 destination must be a normal directory")
        if any(dest.iterdir()):
            raise ValueError("RR5 destination must be empty")
    else:
        dest.mkdir()
    return dest.resolve(strict=True)


def load_approved_intel_catalog(path: Path | None) -> dict[str, dict]:
    if path is None:
        return {}
    raw = json.loads(path.read_text(encoding="utf-8-sig"))
    if raw.get("schema") != INTEL_SCHEMA or raw.get("approved") is not True:
        raise ValueError("RR5 intel catalog must use approved bc-sentinel-offline-intel-v1 schema")
    out: dict[str, dict] = {}
    entries = raw.get("sha256", [])
    if not isinstance(entries, list):
        raise ValueError("RR5 intel catalog sha256 must be a list")
    for item in entries:
        if not isinstance(item, dict):
            raise ValueError("RR5 intel catalog entry must be an object")
        value = str(item.get("value") or "").strip().casefold()
        if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
            raise ValueError("RR5 intel catalog contains invalid SHA-256")
        out[value] = {
            "name": str(item.get("name") or "approved_hash_ioc"),
            "source": str(item.get("source") or "local_approved_catalog"),
        }
    return out


def _iter_selected_files(root: Path, selections: list[str], *, limits: RescueLimits) -> Iterable[Path]:
    seen: dict[str, str] = {}
    emitted = 0
    for selection in selections:
        normalized = _safe_relative_selection(selection)
        selected = _resolve_selected(root, normalized)
        if selected.is_file():
            candidates = [(selected, 0)]
        elif selected.is_dir():
            candidates = [(selected, 0)]
        else:
            continue
        stack = list(candidates)
        while stack:
            current, depth = stack.pop()
            if depth > limits.max_depth:
                raise ValueError("RR5 traversal exceeded max_depth")
            if current.is_file():
                rel = str(current.relative_to(root)).replace("\\", "/")
                key = rel.casefold()
                previous = seen.get(key)
                if previous is not None and previous != rel:
                    raise ValueError(f"RR5 case-insensitive source alias collision: {previous} <> {rel}")
                if previous is None:
                    seen[key] = rel
                    emitted += 1
                    if emitted > limits.max_files:
                        raise ValueError("RR5 extraction exceeds max_files")
                    yield current
                continue
            try:
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
                    for file_path in sorted(files, key=lambda p: p.name.casefold(), reverse=True):
                        stack.append((file_path, depth + 1))
                    for directory in sorted(dirs, key=lambda p: p.name.casefold(), reverse=True):
                        stack.append((directory, depth + 1))
            except OSError:
                continue


def _disposition_for(path: Path, sha256: str, intel: dict[str, dict]) -> tuple[str, str, str]:
    hit = intel.get(sha256.casefold())
    if hit:
        return "containment", "approved_sha256_ioc_match", str(hit.get("name") or "approved_hash_ioc")
    suffix = path.suffix.casefold()
    if suffix in PASSIVE_EXTENSIONS:
        return "rescued-data", "passive_extension_allowlist", ""
    if suffix in ACTIVE_OR_RISKY_EXTENSIONS:
        return "containment", "active_or_risky_extension", ""
    return "containment", "unknown_extension_review_required", ""


def _copy_stable(source: Path, destination: Path, expected_hash: str, before_stat: os.stat_result) -> tuple[bool, str]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=destination.name + ".", suffix=".rr5tmp", dir=str(destination.parent))
    os.close(fd)
    temp = Path(temp_name)
    try:
        with source.open("rb") as src, temp.open("wb") as dst:
            for chunk in iter(lambda: src.read(1024 * 1024), b""):
                dst.write(chunk)
        after_stat = source.stat(follow_symlinks=False)
        after_hash = _sha256_file(source)
        if (
            int(after_stat.st_size) != int(before_stat.st_size)
            or int(getattr(after_stat, "st_mtime_ns", 0)) != int(getattr(before_stat, "st_mtime_ns", 0))
            or after_hash != expected_hash
        ):
            return False, "source_changed_during_extraction"
        copied_hash = _sha256_file(temp)
        if copied_hash != expected_hash:
            return False, "destination_hash_mismatch"
        if destination.exists():
            return False, "destination_collision"
        os.replace(temp, destination)
        return True, "copied_and_verified"
    finally:
        try:
            temp.unlink(missing_ok=True)
        except OSError:
            pass


def rescue_selected_data(
    source_root: Path,
    destination_root: Path,
    includes: list[str],
    *,
    limits: RescueLimits | None = None,
    intel_catalog: Path | None = None,
) -> dict:
    limits = limits or RescueLimits()
    limits.validate()
    root = validate_offline_windows_root(source_root)
    if not includes:
        raise ValueError("RR5 requires at least one explicit --include selection")
    destination = _validate_destination(destination_root, root)
    intel = load_approved_intel_catalog(intel_catalog)
    session_seed = f"{root}|{destination}|{time.time_ns()}|{os.getpid()}"
    session_id = "RR5-" + hashlib.sha256(session_seed.encode("utf-8")).hexdigest()[:16].upper()
    correlation_id = hashlib.sha256((session_id + "|data-rescue").encode("utf-8")).hexdigest()[:20]
    started = time.perf_counter()
    audit_path = destination / "rr5-audit.jsonl"

    def audit(stage: str, status: str, reason: str, **extra: object) -> None:
        record = {
            "profile": PROFILE,
            "session_id": session_id,
            "correlation_id": correlation_id,
            "stage": stage,
            "status": status,
            "reason": reason,
            "source": str(root),
            "destination": str(destination),
            "elapsed_ms": round((time.perf_counter() - started) * 1000.0, 3),
            **extra,
        }
        with audit_path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")

    audit("rescue_start", "ok", "explicit_selection_validated", includes=includes)
    records: list[RescueRecord] = []
    total_bytes = 0
    copied = 0
    contained = 0
    errors = 0
    skipped = 0
    try:
        for source in _iter_selected_files(root, includes, limits=limits):
            rel = str(source.relative_to(root)).replace("\\", "/")
            try:
                if _is_reparse_or_symlink(source):
                    skipped += 1
                    records.append(RescueRecord(rel, 0, "", "containment", "", "skipped", "symlink_or_reparse_refused"))
                    continue
                before_stat = source.stat(follow_symlinks=False)
                size = int(before_stat.st_size)
                if size > limits.max_file_bytes:
                    skipped += 1
                    records.append(RescueRecord(rel, size, "", "containment", "", "skipped", "file_too_large"))
                    continue
                total_bytes += size
                if total_bytes > limits.max_total_bytes:
                    raise ValueError("RR5 extraction exceeds max_total_bytes")
                source_hash = _sha256_file(source)
                disposition, reason, ioc_name = _disposition_for(source, source_hash, intel)
                destination_relative = f"{disposition}/{rel}"
                target = destination / Path(destination_relative.replace("/", os.sep))
                ok, copy_reason = _copy_stable(source, target, source_hash, before_stat)
                if not ok:
                    errors += 1
                    records.append(RescueRecord(rel, size, source_hash, disposition, destination_relative, "error", copy_reason, ioc_name))
                    audit("item_error", "fail", copy_reason, relative_path=rel, sha256=source_hash, bytes=size, disposition=disposition)
                    continue
                copied += 1
                if disposition == "containment":
                    contained += 1
                records.append(RescueRecord(rel, size, source_hash, disposition, destination_relative, "copied", reason, ioc_name))
                audit("item_copied", "ok", reason, relative_path=rel, sha256=source_hash, bytes=size, disposition=disposition, ioc_name=ioc_name)
            except Exception as exc:
                errors += 1
                records.append(RescueRecord(rel, 0, "", "containment", "", "error", f"{type(exc).__name__}: {exc}"))
                audit("item_error", "fail", f"{type(exc).__name__}: {exc}", relative_path=rel)

        manifest = {
            "profile": PROFILE,
            "session_id": session_id,
            "correlation_id": correlation_id,
            "created_utc": _utc_now(),
            "source_root": str(root),
            "destination_root": str(destination),
            "includes": list(includes),
            "limits": asdict(limits),
            "summary": {
                "records": len(records),
                "copied": copied,
                "contained": contained,
                "skipped": skipped,
                "errors": errors,
                "total_source_bytes_considered": total_bytes,
            },
            "records": [record.to_record() for record in records],
            "safety": {
                "source_read_only": True,
                "source_file_execution": False,
                "source_dll_loading": False,
                "source_shell_execution": False,
                "source_delete": False,
                "source_registry_write": False,
                "source_boot_write": False,
                "repair_engine_execution": False,
                "automatic_restore_to_clean_host": False,
                "recovery_certification_enabled": False,
                "network_required": False,
                "cloud_required": False,
            },
        }
        manifest_path = destination / "rr5-rescue-manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        audit("rescue_complete", "ok" if errors == 0 else "partial", "extraction_finished", copied=copied, contained=contained, skipped=skipped, errors=errors, total_bytes=total_bytes)
        return manifest
    except Exception as exc:
        audit("rescue_fail", "fail", f"{type(exc).__name__}: {exc}", copied=copied, contained=contained, skipped=skipped, errors=errors, total_bytes=total_bytes)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel RR5 Safe Data Rescue")
    parser.add_argument("--source", required=True)
    parser.add_argument("--destination", required=True)
    parser.add_argument("--include", action="append", dest="includes", default=[])
    parser.add_argument("--intel-catalog")
    parser.add_argument("--max-files", type=int, default=20_000)
    parser.add_argument("--max-total-bytes", type=int, default=128 * 1024 * 1024 * 1024)
    parser.add_argument("--max-file-bytes", type=int, default=4 * 1024 * 1024 * 1024)
    parser.add_argument("--max-depth", type=int, default=32)
    args = parser.parse_args()
    try:
        result = rescue_selected_data(
            Path(args.source),
            Path(args.destination),
            list(args.includes),
            limits=RescueLimits(args.max_files, args.max_total_bytes, args.max_file_bytes, args.max_depth),
            intel_catalog=Path(args.intel_catalog) if args.intel_catalog else None,
        )
        print(json.dumps({"passed": result["summary"]["errors"] == 0, "profile": PROFILE, "summary": result["summary"]}, indent=2))
        return 0 if result["summary"]["errors"] == 0 else 3
    except Exception as exc:
        print(json.dumps({"passed": False, "profile": PROFILE, "stage": "safe_data_rescue", "reason": f"{type(exc).__name__}: {exc}"}, indent=2))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

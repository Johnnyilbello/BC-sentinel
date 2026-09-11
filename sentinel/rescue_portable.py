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

from .rescue_contract import (
    RescueExecutionContext,
    RescueSafetyPolicy,
    RescueSessionManifest,
)

PROFILE: Final[str] = "v0.11.0-beta.3-rr1"
MAX_FILE_BYTES: Final[int] = 64 * 1024 * 1024
MAX_ITEMS: Final[int] = 10_000
DEFAULT_MAX_ITEMS: Final[int] = 2_000
DEFAULT_MAX_FILE_BYTES: Final[int] = 32 * 1024 * 1024


@dataclass(frozen=True)
class PortableLimits:
    max_items: int = DEFAULT_MAX_ITEMS
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES

    def validate(self) -> None:
        if not (1 <= int(self.max_items) <= MAX_ITEMS):
            raise ValueError("RR1 max_items outside bounded limit")
        if not (1 <= int(self.max_file_bytes) <= MAX_FILE_BYTES):
            raise ValueError("RR1 max_file_bytes outside bounded limit")


@dataclass(frozen=True)
class PortableEvidenceRecord:
    relative_path: str
    size: int
    sha256: str
    status: str
    reason: str = ""

    def to_record(self) -> dict:
        return asdict(self)


def _hash_file(path: Path, *, max_file_bytes: int) -> PortableEvidenceRecord:
    try:
        st = path.stat()
    except OSError as exc:
        return PortableEvidenceRecord(str(path), 0, "", "error", f"stat:{type(exc).__name__}")
    if not stat.S_ISREG(st.st_mode):
        return PortableEvidenceRecord(str(path), int(st.st_size), "", "skipped", "not_regular_file")
    if int(st.st_size) > int(max_file_bytes):
        return PortableEvidenceRecord(str(path), int(st.st_size), "", "skipped", "file_too_large")
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        return PortableEvidenceRecord(str(path), int(st.st_size), "", "error", f"read:{type(exc).__name__}")
    return PortableEvidenceRecord(str(path), int(st.st_size), digest.hexdigest(), "hashed")


def _iter_files(root: Path, *, max_items: int) -> Iterable[Path]:
    emitted = 0
    stack = [root]
    while stack and emitted < max_items:
        current = stack.pop()
        try:
            with os.scandir(current) as entries:
                dirs: list[Path] = []
                files: list[Path] = []
                for entry in entries:
                    try:
                        if entry.is_symlink():
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            dirs.append(Path(entry.path))
                        elif entry.is_file(follow_symlinks=False):
                            files.append(Path(entry.path))
                    except OSError:
                        continue
                for file_path in sorted(files, key=lambda p: p.name.casefold()):
                    if emitted >= max_items:
                        break
                    emitted += 1
                    yield file_path
                for directory in sorted(dirs, key=lambda p: p.name.casefold(), reverse=True):
                    stack.append(directory)
        except OSError:
            continue


def _atomic_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    os.close(fd)
    temp = Path(temp_name)
    try:
        temp.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        os.replace(temp, path)
    finally:
        try:
            temp.unlink(missing_ok=True)
        except OSError:
            pass


def _relative_display(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def run_portable_acquisition(
    target_root: Path,
    output_dir: Path,
    *,
    limits: PortableLimits | None = None,
) -> dict:
    policy = RescueSafetyPolicy()
    policy.validate()
    limits = limits or PortableLimits()
    limits.validate()

    target = target_root.resolve(strict=True)
    if not target.is_dir():
        raise ValueError("RR1 target_root must be an existing directory")
    output = output_dir.resolve()
    try:
        output.relative_to(target)
        raise ValueError("RR1 evidence output must not be inside the target tree")
    except ValueError as exc:
        if str(exc).startswith("RR1 evidence output"):
            raise

    session_seed = f"{target}|{time.time_ns()}|{os.getpid()}"
    session_id = "RR1-" + hashlib.sha256(session_seed.encode("utf-8")).hexdigest()[:16].upper()
    correlation_id = hashlib.sha256((session_id + "|portable").encode("utf-8")).hexdigest()[:20]
    fingerprint = hashlib.sha256(str(target).casefold().encode("utf-8")).hexdigest()
    manifest = RescueSessionManifest(
        session_id=session_id,
        correlation_id=correlation_id,
        execution_context=RescueExecutionContext.COMPROMISED_WINDOWS,
        target_fingerprint=fingerprint,
        created_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    )

    records: list[dict] = []
    hashed = skipped = errors = 0
    for path in _iter_files(target, max_items=limits.max_items):
        result = _hash_file(path, max_file_bytes=limits.max_file_bytes)
        result = PortableEvidenceRecord(
            relative_path=_relative_display(path, target),
            size=result.size,
            sha256=result.sha256,
            status=result.status,
            reason=result.reason,
        )
        records.append(result.to_record())
        if result.status == "hashed":
            hashed += 1
        elif result.status == "skipped":
            skipped += 1
        else:
            errors += 1

    payload = {
        "profile": PROFILE,
        "mode": "portable_read_only_acquisition",
        "manifest": manifest.to_record(),
        "target_root": str(target),
        "output_dir": str(output),
        "limits": asdict(limits),
        "summary": {
            "enumerated": len(records),
            "hashed": hashed,
            "skipped": skipped,
            "errors": errors,
            "truncated_by_max_items": len(records) >= limits.max_items,
        },
        "records": records,
        "safety": {
            "installation_required": False,
            "service_install": False,
            "driver_install": False,
            "registry_write": False,
            "boot_write": False,
            "target_filesystem_write": False,
            "file_delete": False,
            "process_kill": False,
            "network_required": False,
            "cloud_required": False,
            "repair_engine_enabled": False,
            "quarantine_execution_enabled": False,
            "recovery_certification_enabled": False,
        },
    }
    _atomic_json(output / "rr1-evidence.json", payload)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel RR1 portable read-only evidence acquisition")
    parser.add_argument("--target", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--max-items", type=int, default=DEFAULT_MAX_ITEMS)
    parser.add_argument("--max-file-bytes", type=int, default=DEFAULT_MAX_FILE_BYTES)
    args = parser.parse_args()
    try:
        result = run_portable_acquisition(
            Path(args.target),
            Path(args.output),
            limits=PortableLimits(max_items=args.max_items, max_file_bytes=args.max_file_bytes),
        )
        print(json.dumps({"passed": True, "profile": PROFILE, "summary": result["summary"]}, indent=2))
        return 0
    except Exception as exc:
        print(json.dumps({"passed": False, "profile": PROFILE, "error": f"{type(exc).__name__}: {exc}"}, indent=2))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

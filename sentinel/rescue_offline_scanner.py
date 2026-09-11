from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Final, Iterable

PROFILE: Final[str] = "v0.11.0-beta.3-rr3"
MAX_FILES_HARD: Final[int] = 50_000
MAX_FILE_BYTES_HARD: Final[int] = 256 * 1024 * 1024
DEFAULT_MAX_FILES: Final[int] = 10_000
DEFAULT_MAX_FILE_BYTES: Final[int] = 64 * 1024 * 1024
EXECUTABLE_OR_SCRIPT_EXTENSIONS: Final[frozenset[str]] = frozenset(
    {
        ".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".drv", ".ocx",
        ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse",
        ".wsf", ".wsh", ".hta", ".lnk",
    }
)
SCRIPT_EXTENSIONS: Final[frozenset[str]] = frozenset(
    {".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta"}
)
LOLBIN_NAMES: Final[frozenset[str]] = frozenset(
    {
        "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
        "msiexec.exe", "wmic.exe", "cmstp.exe", "installutil.exe", "regasm.exe", "regsvcs.exe",
    }
)


@dataclass(frozen=True)
class OfflineScanLimits:
    max_files: int = DEFAULT_MAX_FILES
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES

    def validate(self) -> None:
        if not (1 <= int(self.max_files) <= MAX_FILES_HARD):
            raise ValueError("RR3 max_files outside bounded limit")
        if not (1 <= int(self.max_file_bytes) <= MAX_FILE_BYTES_HARD):
            raise ValueError("RR3 max_file_bytes outside bounded limit")


@dataclass(frozen=True)
class OfflineFinding:
    relative_path: str
    category: str
    size: int
    sha256: str
    status: str
    verdict: str
    reasons: tuple[str, ...] = field(default_factory=tuple)
    ioc_name: str = ""
    yara_matches: tuple[str, ...] = field(default_factory=tuple)
    automatic_action: bool = False

    def to_record(self) -> dict:
        record = asdict(self)
        record["reasons"] = list(self.reasons)
        record["yara_matches"] = list(self.yara_matches)
        return record


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
        reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
        return bool(attrs & reparse_flag)
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
    if not resolved.is_dir():
        raise ValueError("RR3 offline root must be an existing directory")
    if _is_reparse_or_symlink(resolved):
        raise ValueError("RR3 offline root may not be a symlink/reparse point")
    required = (
        resolved / "Windows" / "System32" / "config" / "SYSTEM",
        resolved / "Windows" / "System32" / "ntoskrnl.exe",
    )
    missing = [str(path.relative_to(resolved)) for path in required if not path.is_file()]
    if missing:
        raise ValueError("RR3 offline root markers missing: " + ", ".join(missing))
    return resolved


def load_approved_intel_catalog(path: Path | None) -> dict[str, dict]:
    if path is None:
        return {}
    raw = json.loads(path.read_text(encoding="utf-8"))
    if raw.get("schema") != "bc-sentinel-offline-intel-v1":
        raise ValueError("RR3 intel catalog schema mismatch")
    if raw.get("approved") is not True:
        raise ValueError("RR3 intel catalog is not explicitly approved")
    entries = raw.get("sha256", [])
    if not isinstance(entries, list):
        raise ValueError("RR3 intel catalog sha256 must be a list")
    out: dict[str, dict] = {}
    for item in entries:
        if not isinstance(item, dict):
            raise ValueError("RR3 intel catalog entry must be an object")
        value = str(item.get("value") or "").strip().casefold()
        if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
            raise ValueError("RR3 intel catalog contains invalid SHA-256")
        out[value] = {
            "name": str(item.get("name") or "approved_hash_ioc"),
            "source": str(item.get("source") or "local_approved_catalog"),
        }
    return out


def _compile_yara(rule_path: Path | None):
    if rule_path is None:
        return None, "not_requested"
    try:
        import yara  # type: ignore
    except Exception as exc:
        return None, f"unavailable:{type(exc).__name__}"
    try:
        return yara.compile(filepath=str(rule_path)), "available"
    except Exception as exc:
        raise ValueError(f"RR3 YARA compile failed: {type(exc).__name__}: {exc}") from exc


def _candidate_roots(root: Path) -> list[tuple[str, Path]]:
    roots: list[tuple[str, Path]] = [
        ("system32", root / "Windows" / "System32"),
        ("drivers", root / "Windows" / "System32" / "drivers"),
        ("syswow64", root / "Windows" / "SysWOW64"),
        ("programdata_startup", root / "ProgramData" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"),
    ]
    users = root / "Users"
    if users.is_dir() and not _is_reparse_or_symlink(users):
        try:
            with os.scandir(users) as entries:
                for entry in entries:
                    try:
                        if not entry.is_dir(follow_symlinks=False) or entry.is_symlink():
                            continue
                        user_root = Path(entry.path)
                        if _is_reparse_or_symlink(user_root):
                            continue
                        roots.extend(
                            [
                                ("user_startup", user_root / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"),
                                ("user_temp", user_root / "AppData" / "Local" / "Temp"),
                            ]
                        )
                    except OSError:
                        continue
        except OSError:
            pass
    return roots


def _iter_candidate_files(root: Path, *, max_files: int) -> Iterable[tuple[str, Path]]:
    emitted = 0
    seen: set[str] = set()
    for category, scan_root in _candidate_roots(root):
        if emitted >= max_files:
            break
        if not scan_root.is_dir() or _is_reparse_or_symlink(scan_root):
            continue
        stack = [scan_root]
        while stack and emitted < max_files:
            current = stack.pop()
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
                            elif entry.is_file(follow_symlinks=False) and p.suffix.casefold() in EXECUTABLE_OR_SCRIPT_EXTENSIONS:
                                files.append(p)
                        except OSError:
                            continue
                    for path in sorted(files, key=lambda p: p.name.casefold()):
                        key = str(path.resolve()).casefold()
                        if key in seen:
                            continue
                        seen.add(key)
                        emitted += 1
                        yield category, path
                        if emitted >= max_files:
                            break
                    for directory in sorted(dirs, key=lambda p: p.name.casefold(), reverse=True):
                        stack.append(directory)
            except OSError:
                continue


def _heuristic_reasons(path: Path, category: str, root: Path) -> list[str]:
    reasons: list[str] = []
    suffix = path.suffix.casefold()
    name = path.name.casefold()
    relative = str(path.relative_to(root)).replace("/", "\\").casefold()
    if category in {"programdata_startup", "user_startup"}:
        reasons.append("startup_location_artifact")
        if suffix in SCRIPT_EXTENSIONS:
            reasons.append("startup_script")
    if category == "user_temp" and suffix in EXECUTABLE_OR_SCRIPT_EXTENSIONS:
        reasons.append("executable_or_script_in_user_temp")
    if name in LOLBIN_NAMES and "\\windows\\system32\\" not in relative and "\\windows\\syswow64\\" not in relative:
        reasons.append("lolbin_name_outside_windows_system_directory")
    parts = name.split(".")
    if len(parts) >= 3 and ("." + parts[-2]) in {".pdf", ".doc", ".docx", ".jpg", ".png", ".txt"}:
        reasons.append("double_extension_lure")
    return reasons


def _yara_matches(rules, path: Path) -> tuple[str, ...]:
    if rules is None:
        return ()
    try:
        matches = rules.match(filepath=str(path), timeout=2)
        return tuple(sorted(str(match.rule) for match in matches))
    except Exception as exc:
        return (f"__YARA_ERROR__:{type(exc).__name__}",)


def _registry_hive_metadata(root: Path, *, max_file_bytes: int) -> list[dict]:
    candidates: list[tuple[str, Path]] = []
    config = root / "Windows" / "System32" / "config"
    for name in ("SYSTEM", "SOFTWARE", "SAM", "SECURITY", "DEFAULT"):
        candidates.append((f"system:{name}", config / name))
    users = root / "Users"
    if users.is_dir() and not _is_reparse_or_symlink(users):
        try:
            with os.scandir(users) as entries:
                for entry in entries:
                    try:
                        if entry.is_dir(follow_symlinks=False) and not entry.is_symlink():
                            user_root = Path(entry.path)
                            if not _is_reparse_or_symlink(user_root):
                                candidates.append((f"user:{entry.name}:NTUSER.DAT", user_root / "NTUSER.DAT"))
                    except OSError:
                        continue
        except OSError:
            pass
    out: list[dict] = []
    for label, path in candidates:
        if not path.is_file() or _is_reparse_or_symlink(path):
            continue
        try:
            size = int(path.stat().st_size)
            digest = _sha256_file(path) if size <= max_file_bytes else ""
            out.append(
                {
                    "label": label,
                    "relative_path": str(path.relative_to(root)).replace("\\", "/"),
                    "size": size,
                    "sha256": digest,
                    "status": "hashed" if digest else "metadata_only_file_too_large",
                    "write_attempted": False,
                }
            )
        except OSError as exc:
            out.append(
                {
                    "label": label,
                    "relative_path": str(path),
                    "size": 0,
                    "sha256": "",
                    "status": f"error:{type(exc).__name__}",
                    "write_attempted": False,
                }
            )
    return out


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


def _append_audit(path: Path, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def scan_offline_windows(
    offline_root: Path,
    output_dir: Path,
    *,
    limits: OfflineScanLimits | None = None,
    intel_catalog: Path | None = None,
    yara_rules: Path | None = None,
) -> dict:
    limits = limits or OfflineScanLimits()
    limits.validate()
    root = validate_offline_windows_root(offline_root)
    output = output_dir.resolve()
    if _is_inside(output, root):
        raise ValueError("RR3 output directory must be outside the offline target")
    catalog = load_approved_intel_catalog(intel_catalog)
    rules, yara_status = _compile_yara(yara_rules)

    seed = f"{root}|{output}|{time.time_ns()}|{os.getpid()}"
    session_id = "RR3-" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16].upper()
    correlation_id = hashlib.sha256((session_id + "|offline-scan").encode("utf-8")).hexdigest()[:20]
    started = time.perf_counter()
    audit_path = output / "rr3-audit.jsonl"

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
                "offline_root": str(root),
                "elapsed_ms": round((time.perf_counter() - started) * 1000.0, 3),
                **extra,
            },
        )

    audit("scan_start", "ok", "validated_offline_windows_root", yara_status=yara_status, intel_entries=len(catalog))
    findings: list[OfflineFinding] = []
    hashed = skipped = errors = ioc_hits = yara_hits = heuristic_hits = 0
    try:
        for category, path in _iter_candidate_files(root, max_files=limits.max_files):
            rel = str(path.relative_to(root)).replace("\\", "/")
            try:
                st = path.stat(follow_symlinks=False)
                size = int(st.st_size)
                if not stat.S_ISREG(st.st_mode):
                    skipped += 1
                    continue
                if size > limits.max_file_bytes:
                    findings.append(
                        OfflineFinding(rel, category, size, "", "skipped", "not_scanned", ("file_too_large",))
                    )
                    skipped += 1
                    continue
                digest = _sha256_file(path)
                hashed += 1
                reasons = _heuristic_reasons(path, category, root)
                ioc = catalog.get(digest.casefold())
                ymatches = _yara_matches(rules, path)
                yara_real = tuple(item for item in ymatches if not item.startswith("__YARA_ERROR__:"))
                yara_error = tuple(item for item in ymatches if item.startswith("__YARA_ERROR__:"))
                if ioc:
                    reasons.append("approved_sha256_ioc_match")
                    ioc_hits += 1
                if yara_real:
                    reasons.append("yara_rule_match")
                    yara_hits += 1
                if yara_error:
                    reasons.append(yara_error[0])
                if any(reason in reasons for reason in (
                    "startup_location_artifact", "startup_script", "executable_or_script_in_user_temp",
                    "lolbin_name_outside_windows_system_directory", "double_extension_lure",
                )):
                    heuristic_hits += 1
                verdict = "deterministic_ioc" if ioc else "yara_match" if yara_real else "review" if reasons else "observed"
                findings.append(
                    OfflineFinding(
                        relative_path=rel,
                        category=category,
                        size=size,
                        sha256=digest,
                        status="hashed",
                        verdict=verdict,
                        reasons=tuple(sorted(set(reasons))),
                        ioc_name=str(ioc.get("name") if ioc else ""),
                        yara_matches=yara_real,
                        automatic_action=False,
                    )
                )
            except OSError as exc:
                errors += 1
                findings.append(
                    OfflineFinding(rel, category, 0, "", "error", "unreadable", (f"{type(exc).__name__}:{exc}",))
                )

        hives = _registry_hive_metadata(root, max_file_bytes=limits.max_file_bytes)
        summary = {
            "enumerated": len(findings),
            "hashed": hashed,
            "skipped": skipped,
            "errors": errors,
            "ioc_hits": ioc_hits,
            "yara_hits": yara_hits,
            "heuristic_review_items": heuristic_hits,
            "registry_hives": len(hives),
            "truncated_by_max_files": len(findings) >= limits.max_files,
        }
        payload = {
            "profile": PROFILE,
            "mode": "offline_read_only_threat_scan",
            "session_id": session_id,
            "correlation_id": correlation_id,
            "created_utc": _utc_now(),
            "offline_root": str(root),
            "output_dir": str(output),
            "limits": asdict(limits),
            "intel": {
                "catalog_requested": intel_catalog is not None,
                "approved_sha256_entries": len(catalog),
                "yara_requested": yara_rules is not None,
                "yara_status": yara_status,
            },
            "summary": summary,
            "registry_hives": hives,
            "findings": [item.to_record() for item in findings],
            "safety": {
                "target_read_only": True,
                "target_file_execution": False,
                "target_dll_loading": False,
                "target_shell_execution": False,
                "registry_write": False,
                "boot_write": False,
                "target_filesystem_write": False,
                "file_delete": False,
                "process_kill": False,
                "quarantine_execution": False,
                "repair_engine_enabled": False,
                "recovery_certification_enabled": False,
                "network_required": False,
                "cloud_required": False,
                "automatic_action": False,
            },
        }
        _atomic_json(output / "rr3-offline-scan.json", payload)
        audit("scan_complete", "ok", "offline_scan_completed_read_only", **summary)
        return payload
    except Exception as exc:
        audit("scan_fail", "fail", f"{type(exc).__name__}: {exc}", findings=len(findings), hashed=hashed, errors=errors)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel RR3 offline read-only threat scanner")
    parser.add_argument("--root", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--intel-catalog")
    parser.add_argument("--yara-rules")
    parser.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES)
    parser.add_argument("--max-file-bytes", type=int, default=DEFAULT_MAX_FILE_BYTES)
    args = parser.parse_args()
    try:
        result = scan_offline_windows(
            Path(args.root),
            Path(args.output),
            limits=OfflineScanLimits(max_files=args.max_files, max_file_bytes=args.max_file_bytes),
            intel_catalog=Path(args.intel_catalog) if args.intel_catalog else None,
            yara_rules=Path(args.yara_rules) if args.yara_rules else None,
        )
        print(json.dumps({"passed": True, "profile": PROFILE, "summary": result["summary"]}, indent=2))
        return 0
    except Exception as exc:
        print(json.dumps({"passed": False, "profile": PROFILE, "stage": "offline_scan", "reason": f"{type(exc).__name__}: {exc}"}, indent=2))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

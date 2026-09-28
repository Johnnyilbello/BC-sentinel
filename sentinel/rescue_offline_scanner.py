from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import tempfile
import time
from contextvars import ContextVar
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Final, Iterable

from sentinel import static_pe_preflight

PROFILE: Final[str] = "v0.11.0-beta.3-rr3"
MAX_FILES_HARD: Final[int] = 50_000
MAX_FILE_BYTES_HARD: Final[int] = 256 * 1024 * 1024
MAX_TOTAL_BYTES_HARD: Final[int] = 16 * 1024 * 1024 * 1024
MAX_SECONDS_HARD: Final[int] = 24 * 60 * 60
MAX_RSS_BYTES_HARD: Final[int] = 16 * 1024 * 1024 * 1024
DEFAULT_MAX_FILES: Final[int] = 10_000
DEFAULT_MAX_FILE_BYTES: Final[int] = 64 * 1024 * 1024
MAX_INTEL_ENTRIES: Final[int] = 50_000
MAX_INTEL_TEXT_CHARS: Final[int] = 160
MAX_YARA_RULE_BYTES: Final[int] = 1024 * 1024
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
    max_total_bytes: int = 1024 * 1024 * 1024
    max_seconds: int = 600
    max_rss_bytes: int = 1024 * 1024 * 1024

    def validate(self) -> None:
        if (
            not isinstance(self.max_files, int)
            or isinstance(self.max_files, bool)
            or not (1 <= self.max_files <= MAX_FILES_HARD)
        ):
            raise ValueError("RR3 max_files outside bounded limit")
        if (
            not isinstance(self.max_file_bytes, int)
            or isinstance(self.max_file_bytes, bool)
            or not (1 <= self.max_file_bytes <= MAX_FILE_BYTES_HARD)
        ):
            raise ValueError("RR3 max_file_bytes outside bounded limit")
        for value, ceiling, name in (
            (self.max_total_bytes, MAX_TOTAL_BYTES_HARD, "max_total_bytes"),
            (self.max_seconds, MAX_SECONDS_HARD, "max_seconds"),
            (self.max_rss_bytes, MAX_RSS_BYTES_HARD, "max_rss_bytes"),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= ceiling:
                raise ValueError(f"RR3 {name} outside bounded limit")


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
    pe_metadata_decision: str = ""
    pe_metadata_reasons: tuple[str, ...] = field(default_factory=tuple)
    pe_sha256_matches: bool | None = None
    pe_clean_claimed: bool = False
    final_sha256_matches: bool | None = None
    automatic_action: bool = False

    def to_record(self) -> dict:
        record = asdict(self)
        record["reasons"] = list(self.reasons)
        record["yara_matches"] = list(self.yara_matches)
        record["pe_metadata_reasons"] = list(self.pe_metadata_reasons)
        return record


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


_READ_GUARD: ContextVar[Callable[[], None] | None] = ContextVar("offline_read_guard", default=None)
_TRAVERSAL_ISSUES: ContextVar[list[str] | None] = ContextVar("offline_traversal_issues", default=None)
_READ_LIMIT: ContextVar[int] = ContextVar("offline_read_limit", default=MAX_FILE_BYTES_HARD)


def _check_read() -> None:
    guard = _READ_GUARD.get()
    if guard is not None:
        guard()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    remaining = _READ_LIMIT.get()
    _check_read()
    _validate_local_path(path)
    with path.open("rb") as handle:
        while True:
            _check_read()
            chunk = handle.read(min(1024 * 1024, remaining + 1))
            if len(chunk) > remaining:
                raise OSError("file grew beyond bounded read limit")
            if not chunk:
                break
            remaining -= len(chunk)
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
    except (OSError, RuntimeError, ValueError):
        return False


def _validate_local_path(path: Path) -> None:
    # Inspect the original path, before resolve can erase junction provenance.
    absolute = Path(os.path.abspath(path))
    if str(absolute).startswith(("\\\\", "//")):
        raise ValueError("RR3 network/device paths are not permitted")
    if os.name == "nt":
        import ctypes
        if ctypes.windll.kernel32.GetDriveTypeW(str(absolute.anchor)) == 4:
            raise ValueError("RR3 network drives are not permitted")
    for part in (absolute, *absolute.parents):
        if part.is_symlink() or (part.exists() and _is_reparse_or_symlink(part)):
            raise ValueError("RR3 path may not contain a symlink/reparse point")


def validate_report_volume(root: Path, output: Path) -> None:
    existing = output
    while not existing.exists():
        existing = existing.parent
    if root.stat().st_dev == existing.stat().st_dev:
        raise ValueError("RR3 reports must be outside the examined volume")


def validate_offline_windows_root(root: Path) -> Path:
    _validate_local_path(root)
    try:
        resolved = root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError("RR3 offline root is unavailable") from exc
    if not resolved.is_dir():
        raise ValueError("RR3 offline root must be an existing directory")
    if _is_reparse_or_symlink(resolved):
        raise ValueError("RR3 offline root may not be a symlink/reparse point")
    live_windows = os.environ.get("SystemRoot")
    if live_windows and resolved == Path(live_windows).resolve().parent:
        raise ValueError("RR3 running Windows installation is not offline")
    required = (
        resolved / "Windows" / "System32" / "config" / "SYSTEM",
        resolved / "Windows" / "System32" / "ntoskrnl.exe",
    )
    for marker in required:
        _validate_local_path(marker)
    missing = [str(path.relative_to(resolved)) for path in required if not path.is_file()]
    if missing:
        raise ValueError("RR3 offline root markers missing: " + ", ".join(missing))
    return resolved


def _valid_intel_text(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value.strip())
        and len(value) <= MAX_INTEL_TEXT_CHARS
        and all(ord(ch) >= 32 and ch not in "\r\n" for ch in value)
    )


def load_approved_intel_catalog(path: Path | None) -> dict[str, dict]:
    if path is None:
        return {}
    try:
        _validate_local_path(path)
        with path.open("rb") as handle:
            data = handle.read(32 * 1024 * 1024 + 1)
        if len(data) > 32 * 1024 * 1024:
            raise ValueError("RR3 intel catalog exceeds byte limit")
        raw = json.loads(data.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("RR3 intel catalog unreadable or invalid JSON") from exc
    if not isinstance(raw, dict):
        raise ValueError("RR3 intel catalog must be an object")
    if raw.get("schema") != "bc-sentinel-offline-intel-v1":
        raise ValueError("RR3 intel catalog schema mismatch")
    if raw.get("approved") is not True:
        raise ValueError("RR3 intel catalog is not explicitly approved")
    entries = raw.get("sha256", [])
    if not isinstance(entries, list):
        raise ValueError("RR3 intel catalog sha256 must be a list")
    if len(entries) > MAX_INTEL_ENTRIES:
        raise ValueError("RR3 intel catalog entry limit exceeded")
    out: dict[str, dict] = {}
    for item in entries:
        if not isinstance(item, dict):
            raise ValueError("RR3 intel catalog entry must be an object")
        if "value" not in item or not set(item).issubset({"value", "name", "source"}):
            raise ValueError("RR3 intel catalog entry fields invalid")
        value_raw = item.get("value")
        if not isinstance(value_raw, str):
            raise ValueError("RR3 intel catalog contains invalid SHA-256")
        value = value_raw.strip().casefold()
        if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
            raise ValueError("RR3 intel catalog contains invalid SHA-256")
        if value in out:
            raise ValueError("RR3 intel catalog contains duplicate SHA-256")
        name = item.get("name", "approved_hash_ioc")
        source = item.get("source", "local_approved_catalog")
        if not _valid_intel_text(name):
            raise ValueError("RR3 intel catalog name invalid")
        if not _valid_intel_text(source):
            raise ValueError("RR3 intel catalog source invalid")
        out[value] = {
            "name": name.strip(),
            "source": source.strip(),
        }
    return out


def _compile_yara(rule_path: Path | None):
    if rule_path is None:
        return None, "not_requested"
    try:
        if (
            not rule_path.is_file()
            or _is_reparse_or_symlink(rule_path)
            or rule_path.stat().st_size > MAX_YARA_RULE_BYTES
        ):
            raise ValueError("RR3 YARA rule file invalid or outside bounded size")
    except OSError as exc:
        raise ValueError("RR3 YARA rule file unreadable") from exc
    try:
        import yara  # type: ignore
    except Exception as exc:
        return None, f"unavailable:{type(exc).__name__}"
    try:
        _validate_local_path(rule_path)
        with rule_path.open("rb") as handle:
            source = handle.read(MAX_YARA_RULE_BYTES + 1)
        if len(source) > MAX_YARA_RULE_BYTES:
            raise ValueError("YARA source exceeds byte limit")
        return yara.compile(source=source.decode("utf-8"), includes=False), "available"
    except Exception as exc:
        raise ValueError(f"RR3 YARA compile failed: {type(exc).__name__}: {exc}") from exc


def _traversal_issue(reason: str) -> None:
    issues = _TRAVERSAL_ISSUES.get()
    if issues is not None and reason not in issues:
        issues.append(reason)


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
                for index, entry in enumerate(entries):
                    _check_read()
                    if index >= MAX_FILES_HARD:
                        raise OSError("directory entry limit")
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
            _traversal_issue("directory_unreadable_or_interrupted")
    return roots


def _iter_candidate_files(root: Path, *, max_files: int) -> Iterable[tuple[str, Path]]:
    emitted = 0
    visited = 0
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
                        _check_read()
                        visited += 1
                        if visited > MAX_FILES_HARD * 2:
                            _traversal_issue("directory_entry_limit")
                            return
                        p = Path(entry.path)
                        try:
                            if entry.is_symlink() or _is_reparse_or_symlink(p):
                                _traversal_issue("reparse_or_unreadable_entry_skipped")
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
                _traversal_issue("directory_unreadable_or_interrupted")
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


class ArtifactChangedError(OSError):
    pass


def _yara_matches(rules, path: Path, *, expected_sha256: str | None = None) -> tuple[str, ...]:
    if rules is None:
        return ()
    try:
        _check_read()
        _validate_local_path(path)
        with path.open("rb") as handle:
            data = handle.read(_READ_LIMIT.get() + 1)
        if len(data) > _READ_LIMIT.get():
            raise OSError("YARA input exceeds bounded size")
        _check_read()
        if expected_sha256 is not None and hashlib.sha256(data).hexdigest() != expected_sha256:
            raise ArtifactChangedError("YARA snapshot differs from initial hash")
        matches = rules.match(data=data, timeout=2)
        return tuple(sorted(str(match.rule) for match in matches))
    except Exception as exc:
        return (f"__YARA_ERROR__:{type(exc).__name__}",)


def _registry_hive_metadata(root: Path, *, max_file_bytes: int, max_total_bytes: int = MAX_TOTAL_BYTES_HARD) -> list[dict]:
    candidates: list[tuple[str, Path]] = []
    config = root / "Windows" / "System32" / "config"
    for name in ("SYSTEM", "SOFTWARE", "SAM", "SECURITY", "DEFAULT"):
        candidates.append((f"system:{name}", config / name))
    users = root / "Users"
    if users.is_dir() and not _is_reparse_or_symlink(users):
        try:
            with os.scandir(users) as entries:
                for index, entry in enumerate(entries):
                    _check_read()
                    if index >= MAX_FILES_HARD:
                        _traversal_issue("hive_entry_limit")
                        break
                    try:
                        if entry.is_dir(follow_symlinks=False) and not entry.is_symlink():
                            user_root = Path(entry.path)
                            if not _is_reparse_or_symlink(user_root):
                                candidates.append((f"user:{entry.name}:NTUSER.DAT", user_root / "NTUSER.DAT"))
                    except OSError:
                        continue
        except OSError:
            _traversal_issue("hive_enumeration_incomplete")
    out: list[dict] = []
    for label, path in candidates:
        if not path.is_file() or _is_reparse_or_symlink(path):
            continue
        try:
            size = int(path.stat().st_size)
            digest = _sha256_file(path) if size <= min(max_file_bytes, max_total_bytes) else ""
            if digest:
                max_total_bytes -= size
            else:
                _traversal_issue("hive_byte_limit")
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
    _validate_local_path(path)
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
    _validate_local_path(path)
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
    cancel_check: Callable[[], bool] | None = None,
    progress_callback: Callable[[dict], None] | None = None,
    require_separate_volume: bool = True,
) -> dict:
    limits = limits or OfflineScanLimits()
    limits.validate()
    root = validate_offline_windows_root(offline_root)
    _validate_local_path(output_dir)
    output = output_dir.resolve()
    if _is_inside(output, root):
        raise ValueError("RR3 output directory must be outside the offline target")
    if require_separate_volume:
        validate_report_volume(root, output)
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
    pe_parsed = pe_review_items = pe_rejected_items = pe_unstable_items = 0
    static_snapshot_unstable_items = 0
    total_bytes = 0
    incomplete_reasons: list[str] = []
    import psutil
    process = psutil.Process()
    def guard() -> None:
        reason = (
            "cancelled" if cancel_check is not None and cancel_check() else
            "time_limit" if time.perf_counter() - started >= limits.max_seconds else
            "memory_limit" if process.memory_info().rss >= limits.max_rss_bytes else None
        )
        if reason:
            incomplete_reasons.append(reason)
            raise OSError(reason)

    issues_token = _TRAVERSAL_ISSUES.set(incomplete_reasons)
    guard_token = _READ_GUARD.set(guard)
    limit_token = _READ_LIMIT.set(limits.max_file_bytes)
    try:
        for category, path in _iter_candidate_files(root, max_files=limits.max_files):
            if cancel_check is not None and cancel_check():
                incomplete_reasons.append("cancelled")
                break
            if time.perf_counter() - started >= limits.max_seconds:
                incomplete_reasons.append("time_limit")
                break
            if process.memory_info().rss >= limits.max_rss_bytes:
                incomplete_reasons.append("memory_limit")
                break
            rel = str(path.relative_to(root)).replace("\\", "/")
            try:
                _validate_local_path(path)
                st = path.stat(follow_symlinks=False)
                size = int(st.st_size)
                if not stat.S_ISREG(st.st_mode):
                    skipped += 1
                    continue
                if size > limits.max_file_bytes:
                    incomplete_reasons.append("file_too_large")
                    findings.append(
                        OfflineFinding(rel, category, size, "", "skipped", "not_scanned", ("file_too_large",))
                    )
                    skipped += 1
                    continue
                if total_bytes + size > limits.max_total_bytes:
                    findings.append(OfflineFinding(rel, category, size, "", "skipped", "not_scanned", ("total_byte_limit",)))
                    skipped += 1
                    incomplete_reasons.append("total_byte_limit")
                    break
                total_bytes += size
                digest = _sha256_file(path)
                hashed += 1
                reasons = _heuristic_reasons(path, category, root)

                pe_decision = ""
                pe_reasons: tuple[str, ...] = ()
                pe_sha256_matches: bool | None = None
                pe_clean_claimed = False
                final_sha256_matches: bool | None = None
                artifact_unstable = False
                if path.suffix.casefold() in static_pe_preflight.SUPPORTED_PE_SUFFIXES:
                    pe_report = static_pe_preflight.inspect_pe_metadata(
                        path,
                        max_bytes=min(limits.max_file_bytes, static_pe_preflight.MAX_PE_BYTES),
                    )
                    pe_parsed += 1
                    pe_decision = pe_report.decision
                    pe_reasons = pe_report.reasons
                    if "pe_parser_unavailable" in pe_reasons:
                        incomplete_reasons.append("pe_parser_unavailable")
                    pe_clean_claimed = pe_report.clean_claimed
                    pe_sha256_matches = (
                        pe_report.sha256 == digest if pe_report.sha256 else None
                    )
                    if pe_report.decision == "REVIEW_REQUIRED":
                        pe_review_items += 1
                    elif pe_report.decision == "REJECTED":
                        pe_rejected_items += 1
                    reasons.extend(f"pe_metadata:{reason}" for reason in pe_report.reasons)
                    if pe_sha256_matches is False:
                        reasons.append("artifact_changed_during_static_scan")
                        artifact_unstable = True
                        pe_unstable_items += 1

                ioc = catalog.get(digest.casefold())
                ymatches = _yara_matches(rules, path, expected_sha256=digest)
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
                    incomplete_reasons.append("yara_analysis_error")
                    if "__YARA_ERROR__:ArtifactChangedError" in yara_error:
                        artifact_unstable = True
                        reasons.append("artifact_changed_during_static_scan")

                try:
                    final_digest = _sha256_file(path)
                except OSError:
                    reasons.append("artifact_unavailable_after_static_scan")
                    artifact_unstable = True
                    final_sha256_matches = False
                else:
                    final_sha256_matches = final_digest == digest
                    if final_sha256_matches is False:
                        reasons.append("artifact_changed_during_static_scan")
                        artifact_unstable = True

                if artifact_unstable:
                    static_snapshot_unstable_items += 1
                    incomplete_reasons.append("artifact_unstable")

                if any(reason in reasons for reason in (
                    "startup_location_artifact", "startup_script", "executable_or_script_in_user_temp",
                    "lolbin_name_outside_windows_system_directory", "double_extension_lure",
                )):
                    heuristic_hits += 1
                verdict = (
                    "review"
                    if artifact_unstable
                    else "deterministic_ioc"
                    if ioc
                    else "yara_match"
                    if yara_real
                    else "review"
                    if reasons
                    else "observed"
                )
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
                        pe_metadata_decision=pe_decision,
                        pe_metadata_reasons=pe_reasons,
                        pe_sha256_matches=pe_sha256_matches,
                        pe_clean_claimed=pe_clean_claimed,
                        final_sha256_matches=final_sha256_matches,
                        automatic_action=False,
                    )
                )
            except (OSError, ValueError) as exc:
                errors += 1
                findings.append(
                    OfflineFinding(rel, category, 0, "", "error", "unreadable", (f"{type(exc).__name__}:{exc}",))
                )
            if progress_callback is not None:
                progress_callback({"enumerated": len(findings), "hashed": hashed,
                                   "skipped": skipped, "errors": errors, "bytes_budgeted": total_bytes})

        hives = [] if incomplete_reasons else _registry_hive_metadata(
            root, max_file_bytes=limits.max_file_bytes,
            max_total_bytes=limits.max_total_bytes - total_bytes,
        )
        total_bytes += sum(item["size"] for item in hives if item["sha256"])
        if yara_status.startswith("unavailable:"):
            incomplete_reasons.append("yara_unavailable")
        if cancel_check is not None and cancel_check():
            incomplete_reasons.append("cancelled")
        if time.perf_counter() - started >= limits.max_seconds:
            incomplete_reasons.append("time_limit")
        if process.memory_info().rss >= limits.max_rss_bytes:
            incomplete_reasons.append("memory_limit")
        if errors or any(str(item["status"]).startswith("error:") for item in hives):
            incomplete_reasons.append("read_errors")
        if len(findings) >= limits.max_files:
            incomplete_reasons.append("file_count_limit")
        incomplete_reasons = list(dict.fromkeys(incomplete_reasons))
        summary = {
            "enumerated": len(findings),
            "hashed": hashed,
            "skipped": skipped,
            "errors": errors,
            "ioc_hits": ioc_hits,
            "yara_hits": yara_hits,
            "heuristic_review_items": heuristic_hits,
            "pe_parsed_items": pe_parsed,
            "pe_review_items": pe_review_items,
            "pe_rejected_items": pe_rejected_items,
            "pe_unstable_items": pe_unstable_items,
            "static_snapshot_unstable_items": static_snapshot_unstable_items,
            "registry_hives": len(hives),
            "bytes_budgeted": total_bytes,
            "incomplete_reasons": incomplete_reasons,
            "truncated_by_max_files": len(findings) >= limits.max_files,
        }
        payload = {
            "profile": PROFILE,
            "mode": "offline_read_only_threat_scan",
            "state": "incomplete" if incomplete_reasons else "completed",
            "clean_claimed": False,
            "coverage": "selected_windows_locations_and_extensions",
            "resource_enforcement": "cooperative_between_reads_and_files",
            "report_volume_enforced": require_separate_volume,
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
        audit("scan_complete", payload["state"], "offline_scan_completed_read_only", **summary)
        return payload
    except Exception as exc:
        audit("scan_fail", "fail", f"{type(exc).__name__}: {exc}", findings=len(findings), hashed=hashed, errors=errors)
        raise
    finally:
        _TRAVERSAL_ISSUES.reset(issues_token)
        _READ_GUARD.reset(guard_token)
        _READ_LIMIT.reset(limit_token)


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel RR3 offline read-only threat scanner")
    parser.add_argument("--root", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--intel-catalog")
    parser.add_argument("--yara-rules")
    parser.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES)
    parser.add_argument("--max-file-bytes", type=int, default=DEFAULT_MAX_FILE_BYTES)
    parser.add_argument("--max-total-bytes", type=int, default=1024 * 1024 * 1024)
    parser.add_argument("--max-seconds", type=int, default=600)
    parser.add_argument("--max-rss-bytes", type=int, default=1024 * 1024 * 1024)
    args = parser.parse_args()
    import signal
    from threading import Event
    interrupted = Event()
    signal.signal(signal.SIGINT, lambda signum, frame: interrupted.set())
    try:
        result = scan_offline_windows(
            Path(args.root),
            Path(args.output),
            limits=OfflineScanLimits(
                max_files=args.max_files, max_file_bytes=args.max_file_bytes,
                max_total_bytes=args.max_total_bytes, max_seconds=args.max_seconds,
                max_rss_bytes=args.max_rss_bytes,
            ),
            intel_catalog=Path(args.intel_catalog) if args.intel_catalog else None,
            yara_rules=Path(args.yara_rules) if args.yara_rules else None,
            cancel_check=interrupted.is_set,
            require_separate_volume=True,
        )
        complete = result["state"] == "completed"
        print(json.dumps({"passed": complete, "state": result["state"], "profile": PROFILE,
                          "summary": result["summary"]}, indent=2))
        return 0 if complete else 3
    except Exception as exc:
        print(json.dumps({"passed": False, "profile": PROFILE, "stage": "offline_scan", "reason": f"{type(exc).__name__}: {exc}"}, indent=2))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

"""B6-3.4 risk-prioritized Smart Scan scope and live file-by-file execution.

The historical StaticScanner remains authoritative for file inspection.  This
module changes only *which* files a consumer Smart Scan asks it to inspect and
how progress is exposed.  Full filesystem coverage is intentionally not claimed.

Safety properties:
- no remediation/quarantine/process-kill/write authority;
- no scan at import/provider construction time;
- symlinks are never followed during candidate discovery;
- unknown report semantics and per-file runtime failures fail closed;
- cancellation is propagated through a marker checked between files;
- COMPLETE means the declared risk-prioritized Smart Scan plan completed, not
  that every file on the machine was scanned.
"""

from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import subprocess
import tempfile
from threading import Event, Thread
from time import time
from typing import Any, Callable, Iterable, Mapping

from sentinel import home_smart_scan as smart
from sentinel.config import POTENTIALLY_EXECUTABLE

PROFILE = "v0.11.0-beta.6-b63.4-smart-scope"
PROVENANCE_SUFFIX = "+risk_prioritized_scan_file_v1"
MODE = "risk_prioritized_v1"

MAX_FILES_ENV = "BC_SENTINEL_SMART_SCAN_MAX_FILES"
MAX_TOTAL_BYTES_ENV = "BC_SENTINEL_SMART_SCAN_MAX_TOTAL_BYTES"
MAX_FILE_BYTES_ENV = "BC_SENTINEL_SMART_SCAN_MAX_FILE_BYTES"
RECENT_DAYS_ENV = "BC_SENTINEL_SMART_SCAN_RECENT_DAYS"

DEFAULT_MAX_FILES = 1200
DEFAULT_MAX_TOTAL_BYTES = 384 * 1024 * 1024
DEFAULT_MAX_FILE_BYTES = 128 * 1024 * 1024
DEFAULT_RECENT_DAYS = 180

_MACRO_EXTENSIONS = frozenset({".docm", ".xlsm", ".pptm", ".xlam", ".xll"})
_CONTAINER_EXTENSIONS = frozenset({".zip", ".rar", ".7z", ".iso", ".img", ".cab"})
_DOCUMENT_RISK_EXTENSIONS = frozenset({".doc", ".xls", ".rtf", ".chm", ".url"})
_RISK_EXTENSIONS = frozenset({ext.casefold() for ext in POTENTIALLY_EXECUTABLE}) | _MACRO_EXTENSIONS | _CONTAINER_EXTENSIONS | _DOCUMENT_RISK_EXTENSIONS
_SKIP_DIR_NAMES = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        "dist",
        "build",
        "site-packages",
    }
)

_SCAN_FILE_PROBE = r'''
import json
try:
    from sentinel.scanner import StaticScanner
    ok = callable(getattr(StaticScanner, "scan_file", None))
    print(json.dumps({"ok": bool(ok), "scanner": "sentinel.scanner.StaticScanner", "scan_file": bool(ok)}))
except Exception as exc:
    print(json.dumps({"ok": False, "error_type": type(exc).__name__, "error": str(exc)}))
    raise
'''

_SCAN_FILE_CHILD = r'''
from dataclasses import asdict, is_dataclass
import json
from pathlib import Path
import sys

manifest_path = Path(sys.argv[1])
cancel_path = Path(sys.argv[2])

def _jsonable(value, depth=0):
    if depth > 6:
        return repr(value)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Path):
        return str(value)
    if is_dataclass(value):
        return _jsonable(asdict(value), depth + 1)
    if isinstance(value, dict):
        return {str(k): _jsonable(v, depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(v, depth + 1) for v in value]
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        try:
            return _jsonable(to_dict(), depth + 1)
        except Exception:
            pass
    data = getattr(value, "__dict__", None)
    if isinstance(data, dict):
        return {str(k): _jsonable(v, depth + 1) for k, v in data.items() if not str(k).startswith("_")}
    return repr(value)

try:
    from sentinel.scanner import StaticScanner
    scanner = StaticScanner()
    files = json.loads(manifest_path.read_text(encoding="utf-8"))
    count = 0
    errors = 0
    cancelled = False
    for raw_path in files:
        if cancel_path.exists():
            cancelled = True
            break
        path = str(raw_path)
        try:
            report = scanner.scan_file(path)
            count += 1
            print(json.dumps({"type": "report", "payload": _jsonable(report)}, ensure_ascii=False), flush=True)
        except Exception as exc:
            errors += 1
            print(json.dumps({"type": "file_error", "path": path, "error_type": type(exc).__name__, "error": str(exc)}, ensure_ascii=False), flush=True)
    print(json.dumps({"type": "summary", "reports": count, "errors": errors, "cancelled": cancelled}), flush=True)
except Exception as exc:
    print(json.dumps({"type": "error", "error_type": type(exc).__name__, "error": str(exc)}), flush=True)
    raise
'''


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = str(os.getenv(name, "") or "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return max(minimum, min(maximum, value))


@dataclass(frozen=True)
class ScopePolicy:
    max_files: int = DEFAULT_MAX_FILES
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    recent_days: int = DEFAULT_RECENT_DAYS

    @classmethod
    def from_environment(cls) -> "ScopePolicy":
        return cls(
            max_files=_env_int(MAX_FILES_ENV, DEFAULT_MAX_FILES, 10, 10000),
            max_total_bytes=_env_int(MAX_TOTAL_BYTES_ENV, DEFAULT_MAX_TOTAL_BYTES, 16 * 1024 * 1024, 4 * 1024 * 1024 * 1024),
            max_file_bytes=_env_int(MAX_FILE_BYTES_ENV, DEFAULT_MAX_FILE_BYTES, 1024 * 1024, 2 * 1024 * 1024 * 1024),
            recent_days=_env_int(RECENT_DAYS_ENV, DEFAULT_RECENT_DAYS, 1, 3650),
        )

    def to_dict(self) -> dict:
        return {
            "mode": MODE,
            "max_files": self.max_files,
            "max_total_bytes": self.max_total_bytes,
            "max_file_bytes": self.max_file_bytes,
            "recent_days": self.recent_days,
            "full_filesystem_coverage": False,
        }


@dataclass(frozen=True)
class Candidate:
    path: Path
    root: Path
    size: int
    mtime: float
    score: int
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class ScopeGroup:
    root: Path
    selected: tuple[Candidate, ...]
    candidate_pool_count: int
    skipped_oversize: int
    skipped_budget: int
    walk_errors: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict:
        return {
            "root": str(self.root),
            "selected_count": len(self.selected),
            "selected_bytes": sum(item.size for item in self.selected),
            "candidate_pool_count": self.candidate_pool_count,
            "skipped_oversize": self.skipped_oversize,
            "skipped_budget": self.skipped_budget,
            "walk_error_count": len(self.walk_errors),
        }


@dataclass(frozen=True)
class ScopeSelection:
    groups: tuple[ScopeGroup, ...]
    policy: ScopePolicy

    @property
    def selected_count(self) -> int:
        return sum(len(group.selected) for group in self.groups)

    @property
    def candidate_pool_count(self) -> int:
        return sum(group.candidate_pool_count for group in self.groups)

    def to_dict(self) -> dict:
        return {
            "policy": self.policy.to_dict(),
            "selected_count": self.selected_count,
            "candidate_pool_count": self.candidate_pool_count,
            "groups": [group.to_dict() for group in self.groups],
        }


def _root_role(root: Path) -> str:
    text = str(root).replace("/", "\\").casefold()
    name = root.name.casefold()
    if name == "downloads":
        return "downloads"
    if name == "desktop":
        return "desktop"
    if name == "documents":
        return "documents"
    if name == "temp" or "\\appdata\\local\\temp" in text:
        return "temp"
    if name == "roaming" or "\\appdata\\roaming" in text:
        return "roaming"
    return "custom"


def _age_days(mtime: float, now: float) -> float:
    return max(0.0, (now - float(mtime)) / 86400.0)


def _score_candidate(path: Path, role: str, mtime: float, size: int, now: float) -> tuple[int, tuple[str, ...]]:
    ext = path.suffix.casefold()
    score = 0
    reasons: list[str] = []
    if ext in {item.casefold() for item in POTENTIALLY_EXECUTABLE}:
        score += 110
        reasons.append("executable_or_script")
    elif ext in _MACRO_EXTENSIONS:
        score += 100
        reasons.append("macro_document")
    elif ext in _CONTAINER_EXTENSIONS:
        score += 80
        reasons.append("archive_or_disk_image")
    elif ext in _DOCUMENT_RISK_EXTENSIONS:
        score += 70
        reasons.append("document_or_link_risk")

    role_score = {"temp": 80, "downloads": 70, "roaming": 60, "desktop": 50, "documents": 30, "custom": 40}.get(role, 20)
    score += role_score
    reasons.append(f"root:{role}")

    lower = str(path).replace("/", "\\").casefold()
    if "\\start menu\\programs\\startup\\" in lower or "\\startup\\" in lower:
        score += 180
        reasons.append("startup_persistence_path")

    age = _age_days(mtime, now)
    if age <= 7:
        score += 80
        reasons.append("modified_7d")
    elif age <= 30:
        score += 55
        reasons.append("modified_30d")
    elif age <= 90:
        score += 30
        reasons.append("modified_90d")
    elif age <= 180:
        score += 15
        reasons.append("modified_180d")

    if size <= 10 * 1024 * 1024:
        score += 10
    elif size >= 64 * 1024 * 1024:
        score -= 15

    parts = path.name.casefold().split(".")
    if len(parts) >= 3 and ext in {".exe", ".scr", ".com", ".js", ".vbs", ".lnk"}:
        score += 25
        reasons.append("double_extension")
    return score, tuple(reasons)


def _candidate_allowed(path: Path, role: str, stat_result: os.stat_result, policy: ScopePolicy, now: float) -> bool:
    ext = path.suffix.casefold()
    if ext not in _RISK_EXTENSIONS:
        return False
    lower = str(path).replace("/", "\\").casefold()
    persistence = "\\start menu\\programs\\startup\\" in lower or "\\startup\\" in lower
    if persistence:
        return True
    if role == "custom":
        return True
    return _age_days(stat_result.st_mtime, now) <= float(policy.recent_days)


def _discover_root(root: Path, policy: ScopePolicy, now: float) -> tuple[list[Candidate], int, list[str]]:
    role = _root_role(root)
    candidates: list[Candidate] = []
    skipped_oversize = 0
    errors: list[str] = []

    if root.is_file():
        paths: Iterable[Path] = (root,)
    else:
        collected: list[Path] = []

        def onerror(exc: OSError) -> None:
            errors.append(f"{type(exc).__name__}:{getattr(exc, 'filename', '')}")

        for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False, onerror=onerror):
            dirnames[:] = [name for name in dirnames if name.casefold() not in _SKIP_DIR_NAMES]
            base = Path(dirpath)
            for name in filenames:
                collected.append(base / name)
        paths = collected

    for path in paths:
        try:
            if path.is_symlink():
                continue
            stat_result = path.stat()
        except OSError as exc:
            errors.append(f"{type(exc).__name__}:{path}")
            continue
        if not path.is_file():
            continue
        if stat_result.st_size > policy.max_file_bytes:
            if path.suffix.casefold() in _RISK_EXTENSIONS:
                skipped_oversize += 1
            continue
        if not _candidate_allowed(path, role, stat_result, policy, now):
            continue
        score, reasons = _score_candidate(path, role, stat_result.st_mtime, stat_result.st_size, now)
        candidates.append(Candidate(path, root, int(stat_result.st_size), float(stat_result.st_mtime), score, reasons))

    candidates.sort(key=lambda item: (-item.score, -item.mtime, str(item.path).casefold()))
    return candidates, skipped_oversize, errors


def select_scope(roots: Iterable[Path], policy: ScopePolicy | None = None) -> ScopeSelection:
    policy = policy or ScopePolicy.from_environment()
    now = time()
    discovered: list[tuple[Path, list[Candidate], int, list[str]]] = []
    for raw_root in roots:
        root = Path(raw_root)
        pool, skipped_oversize, errors = _discover_root(root, policy, now)
        discovered.append((root, pool, skipped_oversize, errors))

    all_candidates = [item for _, pool, _, _ in discovered for item in pool]
    all_candidates.sort(key=lambda item: (-item.score, -item.mtime, str(item.path).casefold()))

    selected_paths: set[str] = set()
    used_bytes = 0
    for item in all_candidates:
        if len(selected_paths) >= policy.max_files:
            break
        if selected_paths and used_bytes + item.size > policy.max_total_bytes:
            continue
        if not selected_paths and item.size > policy.max_total_bytes:
            continue
        selected_paths.add(os.path.normcase(os.path.normpath(str(item.path))))
        used_bytes += item.size

    groups: list[ScopeGroup] = []
    for root, pool, skipped_oversize, errors in discovered:
        selected = tuple(item for item in pool if os.path.normcase(os.path.normpath(str(item.path))) in selected_paths)
        skipped_budget = max(0, len(pool) - len(selected))
        groups.append(
            ScopeGroup(
                root=root,
                selected=selected,
                candidate_pool_count=len(pool),
                skipped_oversize=skipped_oversize,
                skipped_budget=skipped_budget,
                walk_errors=tuple(errors[:20]),
            )
        )
    return ScopeSelection(tuple(groups), policy)


def _probe_scan_file(module: Any, base_provider: Any) -> tuple[bool, dict]:
    binding = getattr(base_provider, "_binding", None)
    if binding is None:
        return False, {"reason": "runtime_binding_missing"}
    try:
        proc = subprocess.run(
            [str(binding.python_executable), "-c", _SCAN_FILE_PROBE],
            cwd=str(binding.root),
            env=module._runtime_env(binding),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=20,
            check=False,
        )
    except Exception as exc:
        return False, {"reason": f"scan_file_probe_failed:{type(exc).__name__}", "detail": str(exc)}

    parsed: dict = {}
    for line in (proc.stdout or "").splitlines():
        try:
            item = json.loads(line)
        except Exception:
            continue
        if isinstance(item, dict) and "ok" in item:
            parsed = item
    ok = proc.returncode == 0 and parsed.get("ok") is True and parsed.get("scan_file") is True
    return ok, {"returncode": proc.returncode, "probe": parsed, "output_tail": (proc.stdout or "")[-2000:]}


class RiskPrioritizedStaticScannerProvider:
    def __init__(self, module: Any, base_provider: Any, scan_file_probe: Mapping[str, object]) -> None:
        self._module = module
        self._base = base_provider
        self._binding = getattr(base_provider, "_binding", None)
        self._scan_file_probe = dict(scan_file_probe)
        self._planned_files: dict[str, tuple[Path, ...]] = {}
        self._last_selection: ScopeSelection | None = None

    def capabilities(self) -> Mapping[str, object]:
        raw = dict(self._base.capabilities())
        raw.update(
            {
                "provider_profile": PROFILE,
                "provider_provenance": str(raw.get("provider_provenance") or "") + PROVENANCE_SUFFIX,
                "scope_mode": MODE,
                "full_filesystem_coverage": False,
                "scan_file_available": True,
                "scan_file_probe": dict(self._scan_file_probe),
            }
        )
        return raw

    def build_plan(self) -> smart.SmartScanPlan:
        roots = tuple(Path(item) for item in getattr(self._base, "_roots", ()))
        selection = select_scope(roots)
        self._last_selection = selection
        self._planned_files = {}
        caps = dict(self.capabilities())
        provenance = str(caps["provider_provenance"])
        checks: list[smart.SmartScanCheck] = []
        for index, group in enumerate(selection.groups, start=1):
            check_id = f"smart_scope_{index:02d}"
            files = tuple(item.path for item in group.selected)
            self._planned_files[check_id] = files
            checks.append(
                smart.SmartScanCheck(
                    check_id=check_id,
                    label=f"Priority Smart Scan — {group.root}",
                    purpose="Inspect the highest-risk recent executable, script, persistence, macro and container candidates in this configured root.",
                    available=True,
                    provenance=provenance,
                    work_units=max(1, len(files)),
                    raw={**group.to_dict(), "scope_mode": MODE, "full_filesystem_coverage": False},
                )
            )
        return smart.SmartScanPlan(
            provider_name=str(caps.get("provider_name") or "BC Sentinel StaticScanner live adapter"),
            provider_profile=PROFILE,
            provider_provenance=provenance,
            checks=tuple(checks),
            raw=selection.to_dict(),
        )

    def _run_group(
        self,
        check: smart.SmartScanCheck,
        files: tuple[Path, ...],
        cancel_check: Callable[[], bool],
        report_progress: Callable[[int, int], None],
    ) -> smart.SmartScanCheckResult:
        if self._binding is None:
            return smart.SmartScanCheckResult(check.check_id, smart.CHECK_FAILED, "Pinned runtime binding disappeared before execution.")
        if not files:
            return smart.SmartScanCheckResult(
                check_id=check.check_id,
                status=smart.CHECK_COMPLETED,
                summary="No priority file candidates were present in this Smart Scan root.",
                evidence={"root": str(check.raw.get("root") or ""), "reports": 0, "scope_mode": MODE},
            )

        findings: list[smart.SmartScanFinding] = []
        recognized_reports = 0
        unrecognized_reports = 0
        report_count = 0
        file_errors: list[dict] = []
        output_tail: list[str] = []
        runtime_error: dict = {}
        summary: dict = {}

        with tempfile.TemporaryDirectory(prefix="BCSentinel-B634-") as temp_dir:
            temp = Path(temp_dir)
            manifest = temp / "files.json"
            cancel_path = temp / "cancel.request"
            manifest.write_text(json.dumps([str(path) for path in files], ensure_ascii=False), encoding="utf-8")
            watcher_stop = Event()

            def watch_cancel() -> None:
                while not watcher_stop.wait(0.10):
                    try:
                        if cancel_check():
                            cancel_path.touch(exist_ok=True)
                            return
                    except Exception:
                        cancel_path.touch(exist_ok=True)
                        return

            watcher = Thread(target=watch_cancel, name="BCS-B634-CancelWatch", daemon=True)
            watcher.start()
            try:
                proc = subprocess.Popen(
                    [str(self._binding.python_executable), "-c", _SCAN_FILE_CHILD, str(manifest), str(cancel_path)],
                    cwd=str(self._binding.root),
                    env=self._module._runtime_env(self._binding),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                )
                assert proc.stdout is not None
                for raw_line in proc.stdout:
                    line = raw_line.rstrip("\r\n")
                    if line:
                        output_tail.append(line)
                        output_tail = output_tail[-20:]
                    try:
                        item = json.loads(line)
                    except Exception:
                        continue
                    if not isinstance(item, dict):
                        continue
                    kind = item.get("type")
                    if kind == "report":
                        report_count += 1
                        payload = self._module._safe_payload(item.get("payload"))
                        finding, recognized = self._module._finding_from_report(check.check_id, payload, report_count)
                        if recognized:
                            recognized_reports += 1
                        else:
                            unrecognized_reports += 1
                        if finding is not None:
                            findings.append(finding)
                        report_progress(report_count, len(files))
                    elif kind == "file_error":
                        file_errors.append(item)
                        report_progress(report_count + len(file_errors), len(files))
                    elif kind == "summary":
                        summary = item
                    elif kind == "error":
                        runtime_error = item
                returncode = proc.wait()
            except Exception as exc:
                return smart.SmartScanCheckResult(
                    check_id=check.check_id,
                    status=smart.CHECK_FAILED,
                    summary="Priority Smart Scan subprocess failed to execute.",
                    findings=tuple(findings),
                    evidence={"error": f"{type(exc).__name__}: {exc}", "output_tail": output_tail[-10:]},
                )
            finally:
                watcher_stop.set()
                watcher.join(timeout=1.0)

        cancelled = cancel_check() or bool(summary.get("cancelled"))
        if cancelled:
            return smart.SmartScanCheckResult(
                check_id=check.check_id,
                status=smart.CHECK_CANCELLED,
                summary="Priority Smart Scan cancelled by the user.",
                findings=tuple(findings),
                evidence={"reports": report_count, "planned_files": len(files), "scope_mode": MODE},
            )
        if returncode != 0 or runtime_error or not summary:
            return smart.SmartScanCheckResult(
                check_id=check.check_id,
                status=smart.CHECK_FAILED,
                summary="Priority Smart Scan runtime did not complete this scope cleanly.",
                findings=tuple(findings),
                evidence={"returncode": returncode, "runtime_error": runtime_error, "output_tail": output_tail[-10:]},
            )
        if file_errors:
            return smart.SmartScanCheckResult(
                check_id=check.check_id,
                status=smart.CHECK_FAILED,
                summary="Some planned priority files could not be inspected.",
                findings=tuple(findings),
                evidence={"reports": report_count, "planned_files": len(files), "file_errors": file_errors[:20], "scope_mode": MODE},
            )
        if unrecognized_reports:
            return smart.SmartScanCheckResult(
                check_id=check.check_id,
                status=smart.CHECK_FAILED,
                summary="The historical scanner returned report data that cannot be classified safely.",
                findings=tuple(findings),
                evidence={"reports": report_count, "recognized_reports": recognized_reports, "unrecognized_reports": unrecognized_reports, "scope_mode": MODE},
            )
        if report_count != len(files):
            return smart.SmartScanCheckResult(
                check_id=check.check_id,
                status=smart.CHECK_FAILED,
                summary="Priority Smart Scan did not produce evidence for every planned file.",
                findings=tuple(findings),
                evidence={"reports": report_count, "planned_files": len(files), "scope_mode": MODE},
            )
        return smart.SmartScanCheckResult(
            check_id=check.check_id,
            status=smart.CHECK_COMPLETED,
            summary=f"Priority Smart Scan inspected {report_count} selected files in this root.",
            findings=tuple(findings),
            evidence={
                "reports": report_count,
                "recognized_reports": recognized_reports,
                "planned_files": len(files),
                "scope_mode": MODE,
                "full_filesystem_coverage": False,
            },
        )

    def run(
        self,
        plan: smart.SmartScanPlan,
        progress_callback: Callable[[smart.SmartScanProgress], None],
        cancel_check: Callable[[], bool],
    ) -> smart.SmartScanProviderResult:
        plan.validate()
        if set(self._planned_files) != {check.check_id for check in plan.checks}:
            raise RuntimeError("smart_scope_plan_not_owned_by_provider")

        total_checks = len(plan.checks)
        total_files = sum(len(self._planned_files[check.check_id]) for check in plan.checks)
        completed_files = 0
        results: list[smart.SmartScanCheckResult] = []

        for index, check in enumerate(plan.checks):
            files = self._planned_files[check.check_id]
            if cancel_check():
                results.append(smart.SmartScanCheckResult(check.check_id, smart.CHECK_CANCELLED, "Smart Scan cancelled before this scope started."))
                for rest in plan.checks[index + 1 :]:
                    results.append(smart.SmartScanCheckResult(rest.check_id, smart.CHECK_SKIPPED, "Skipped after user cancellation."))
                break

            start_percent = int((completed_files / max(total_files, 1)) * 100) if total_files else int((index / max(total_checks, 1)) * 100)
            progress_callback(
                smart.SmartScanProgress(start_percent, index, total_checks, check.check_id, f"Selecting and scanning priority files in {check.raw.get('root', check.label)}")
            )

            last_emitted = -1

            def report_progress(done_in_group: int, total_in_group: int) -> None:
                nonlocal last_emitted
                done = completed_files + min(done_in_group, total_in_group)
                percent = int((done / max(total_files, 1)) * 100) if total_files else start_percent
                if percent != last_emitted:
                    last_emitted = percent
                    progress_callback(
                        smart.SmartScanProgress(percent, index, total_checks, check.check_id, f"Priority files inspected: {done}/{max(total_files, 1)}")
                    )

            result = self._run_group(check, files, cancel_check, report_progress)
            results.append(result)
            completed_files += len(files)
            completed_checks = index + 1
            percent = int((completed_files / max(total_files, 1)) * 100) if total_files else int((completed_checks / max(total_checks, 1)) * 100)
            progress_callback(smart.SmartScanProgress(percent, completed_checks, total_checks, check.check_id, result.summary))
            if result.status == smart.CHECK_CANCELLED:
                for rest in plan.checks[index + 1 :]:
                    results.append(smart.SmartScanCheckResult(rest.check_id, smart.CHECK_SKIPPED, "Skipped after user cancellation."))
                break

        selection = self._last_selection.to_dict() if self._last_selection else {}
        return smart.SmartScanProviderResult(
            check_results=tuple(results),
            raw_evidence={
                "scope": selection,
                "scan_file_probe": dict(self._scan_file_probe),
                "full_filesystem_coverage": False,
                "automatic_quarantine": False,
                "automatic_repair": False,
                "automatic_destructive_action": False,
            },
        )


def wrap_provider(module: Any, base_provider: Any) -> Any:
    """Use the B6-3.4 provider only when the pinned runtime exposes scan_file.

    Older/synthetic runtimes that only expose scan_paths keep the B6-3.2 provider
    unchanged.  This preserves fail-closed compatibility while allowing the real
    verified runtime to use the faster targeted Smart Scan path.
    """

    base_caps = dict(base_provider.capabilities())
    if not (base_caps.get("available") is True and base_caps.get("accepted") is True):
        return base_provider
    ok, evidence = _probe_scan_file(module, base_provider)
    if not ok:
        return base_provider
    return RiskPrioritizedStaticScannerProvider(module, base_provider, evidence)

from __future__ import annotations

"""B6-3.2 adapter for the verified historical Windows StaticScanner runtime.

The modern Home/orchestration code remains in this repository.  The historical
full Windows runtime can stay in its original directory: this adapter invokes
that runtime in a separate Python process and calls only the already-existing
read-only ``sentinel.scanner.StaticScanner.scan_paths`` API.

No scan is started at import/factory time.  The external runtime is accepted
only when its scanner.py SHA-256 is explicitly pinned, so an arbitrary path
cannot silently become executable code.
"""

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from threading import Event, Thread
from typing import Callable, Iterable, Mapping

from sentinel.config import Settings
from sentinel import home_smart_scan as smart

RUNTIME_ROOT_ENV = "BC_SENTINEL_FULL_RUNTIME_ROOT"
SCANNER_SHA_ENV = "BC_SENTINEL_FULL_RUNTIME_SCANNER_SHA256"
RUNTIME_PYTHON_ENV = "BC_SENTINEL_FULL_RUNTIME_PYTHON"
SMART_SCAN_ROOTS_ENV = "BC_SENTINEL_SMART_SCAN_ROOTS"

PROVIDER_NAME = "BC Sentinel StaticScanner live adapter"
PROVIDER_PROFILE = "v0.11.0-beta.6-b63.2-static-scanner"
PROVIDER_PROVENANCE = "pinned_full_runtime:sentinel.scanner.StaticScanner.scan_paths"

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")

_CHILD = r'''
from dataclasses import asdict, is_dataclass
import json
import os
from pathlib import Path
import sys

root = sys.argv[1]
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
    count = 0
    for report in scanner.scan_paths([root], cancelled=lambda: cancel_path.exists()):
        count += 1
        print(json.dumps({"type": "report", "payload": _jsonable(report)}, ensure_ascii=False), flush=True)
    print(json.dumps({"type": "summary", "reports": count, "cancelled": cancel_path.exists()}), flush=True)
except Exception as exc:
    print(json.dumps({"type": "error", "error_type": type(exc).__name__, "error": str(exc)}), flush=True)
    raise
'''

_PROBE = r'''
import json
try:
    from sentinel.scanner import StaticScanner
    ok = callable(getattr(StaticScanner, "scan_paths", None))
    print(json.dumps({"ok": bool(ok), "scanner": "sentinel.scanner.StaticScanner", "scan_paths": bool(ok)}))
except Exception as exc:
    print(json.dumps({"ok": False, "error_type": type(exc).__name__, "error": str(exc)}))
    raise
'''


@dataclass(frozen=True)
class RuntimeBinding:
    root: Path
    sentinel_dir: Path
    scanner_path: Path
    scanner_sha256: str
    python_executable: Path

    def to_dict(self) -> dict:
        return {
            "root": str(self.root),
            "sentinel_dir": str(self.sentinel_dir),
            "scanner_path": str(self.scanner_path),
            "scanner_sha256": self.scanner_sha256,
            "python_executable": str(self.python_executable),
        }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _normalize_runtime_root(raw: str) -> tuple[Path, Path]:
    root = Path(raw).expanduser().resolve()
    sentinel_dir = root if root.name.casefold() == "sentinel" else root / "sentinel"
    return root, sentinel_dir


def _resolve_binding() -> tuple[RuntimeBinding | None, str]:
    raw_root = str(os.getenv(RUNTIME_ROOT_ENV, "") or "").strip()
    if not raw_root:
        return None, "runtime_root_not_configured"
    expected = str(os.getenv(SCANNER_SHA_ENV, "") or "").strip().lower()
    if not _SHA256_RE.fullmatch(expected):
        return None, "scanner_sha256_pin_missing_or_invalid"

    try:
        root, sentinel_dir = _normalize_runtime_root(raw_root)
    except Exception:
        return None, "runtime_root_invalid"
    scanner_path = sentinel_dir / "scanner.py"
    if not scanner_path.is_file():
        return None, "runtime_scanner_missing"
    actual = _sha256(scanner_path)
    if actual.lower() != expected:
        return None, "runtime_scanner_sha256_mismatch"

    python_raw = str(os.getenv(RUNTIME_PYTHON_ENV, "") or "").strip()
    python_executable = Path(python_raw).expanduser().resolve() if python_raw else Path(sys.executable).resolve()
    if not python_executable.is_file():
        return None, "runtime_python_missing"

    return RuntimeBinding(root, sentinel_dir, scanner_path, actual, python_executable), "binding_verified"


def _runtime_env(binding: RuntimeBinding) -> dict[str, str]:
    env = dict(os.environ)
    current = str(env.get("PYTHONPATH", "") or "")
    env["PYTHONPATH"] = str(binding.root) + (os.pathsep + current if current else "")
    env["PYTHONNOUSERSITE"] = "1"
    return env


def _probe_binding(binding: RuntimeBinding) -> tuple[bool, dict]:
    try:
        proc = subprocess.run(
            [str(binding.python_executable), "-c", _PROBE],
            cwd=str(binding.root),
            env=_runtime_env(binding),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=20,
            check=False,
        )
    except Exception as exc:
        return False, {"reason": f"runtime_probe_failed:{type(exc).__name__}", "detail": str(exc)}

    parsed: dict = {}
    for line in (proc.stdout or "").splitlines():
        try:
            item = json.loads(line)
        except Exception:
            continue
        if isinstance(item, dict) and "ok" in item:
            parsed = item
    ok = proc.returncode == 0 and parsed.get("ok") is True and parsed.get("scan_paths") is True
    return ok, {
        "returncode": proc.returncode,
        "probe": parsed,
        "output_tail": (proc.stdout or "")[-3000:],
    }


def _scan_roots() -> tuple[Path, ...]:
    configured = str(os.getenv(SMART_SCAN_ROOTS_ENV, "") or "").strip()
    raw: Iterable[str]
    if configured:
        raw = [item for item in configured.split(os.pathsep) if item.strip()]
    else:
        raw = Settings.defaults().monitored_dirs

    result: list[Path] = []
    seen: set[str] = set()
    for item in raw:
        try:
            path = Path(str(item)).expanduser().resolve()
        except Exception:
            continue
        try:
            if not path.exists():
                continue
        except OSError:
            continue
        key = os.path.normcase(os.path.normpath(str(path)))
        if key in seen:
            continue
        seen.add(key)
        result.append(path)
    return tuple(result)


def _safe_payload(value: object) -> dict:
    return dict(value) if isinstance(value, dict) else {"value": value}


def _first(payload: Mapping[str, object], *keys: str) -> object:
    for key in keys:
        if key in payload:
            return payload[key]
    return None


def _nonempty(value: object) -> bool:
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, (str, bytes, list, tuple, set, frozenset, dict)):
        return len(value) > 0
    return True


def _report_evidence(payload: Mapping[str, object]) -> tuple[bool, bool, str, str, str]:
    """Return (recognized, finding, severity, title, reason) without guessing clean."""
    collection_keys = ("detections", "signals", "threats", "matches", "yara_matches", "findings")
    boolean_keys = ("detected", "malicious", "is_malicious", "suspicious", "is_suspicious", "infected")
    verdict_keys = ("verdict", "classification", "decision", "status")

    recognized = any(key in payload for key in (*collection_keys, *boolean_keys, *verdict_keys))
    collections = [payload.get(key) for key in collection_keys if key in payload]
    finding = any(_nonempty(value) for value in collections)
    finding = finding or any(bool(payload.get(key)) for key in boolean_keys if key in payload)

    verdict = str(_first(payload, *verdict_keys) or "").strip().casefold()
    threat_tokens = ("malicious", "infected", "threat", "suspicious", "blocked", "danger")
    clean_tokens = ("clean", "benign", "allowed", "safe", "no_threat", "no threat")
    if verdict:
        if any(token in verdict for token in threat_tokens):
            finding = True
        elif any(token in verdict for token in clean_tokens):
            recognized = True

    explicit_severity = str(_first(payload, "severity", "risk", "level") or "").strip().upper()
    if explicit_severity in smart.SEVERITIES:
        severity = explicit_severity
    elif "critical" in verdict:
        severity = smart.SEVERITY_CRITICAL
    elif finding and ("malicious" in verdict or "infected" in verdict or collections):
        severity = smart.SEVERITY_HIGH
    elif finding:
        severity = smart.SEVERITY_MEDIUM
    else:
        severity = smart.SEVERITY_INFO

    name = str(_first(payload, "threat_name", "name", "signature", "rule") or "").strip()
    title = name or ("Static scanner finding" if finding else "Static scanner report")
    reason = str(_first(payload, "reason", "message", "verdict", "classification") or "").strip()
    if finding and not reason:
        reason = "The existing StaticScanner returned explicit detection evidence."
    return recognized, finding, severity, title, reason


def _finding_from_report(check_id: str, payload: Mapping[str, object], ordinal: int) -> tuple[smart.SmartScanFinding | None, bool]:
    recognized, is_finding, severity, title, reason = _report_evidence(payload)
    if not recognized:
        return None, False
    if not is_finding:
        return None, True
    path = str(_first(payload, "path", "file_path", "filename") or "")
    indicator = str(_first(payload, "sha256", "hash", "indicator") or "")
    finding = smart.SmartScanFinding(
        finding_id=f"STATIC-{check_id.upper()}-{ordinal:06d}",
        title=title,
        severity=severity,
        category="static_malware_scan",
        reason=reason,
        source_check_id=check_id,
        path=path,
        indicator=indicator,
        evidence={"scanner_report": dict(payload)},
    )
    finding.validate()
    return finding, True


class StaticScannerLiveProvider:
    def __init__(self) -> None:
        self._binding, self._binding_reason = _resolve_binding()
        self._probe_ok = False
        self._probe_evidence: dict = {}
        if self._binding is not None:
            self._probe_ok, self._probe_evidence = _probe_binding(self._binding)
        self._roots = _scan_roots()

    def capabilities(self) -> Mapping[str, object]:
        available = bool(self._binding is not None and self._probe_ok and self._roots)
        reason = "accepted_pinned_static_scanner_runtime" if available else self._binding_reason
        if self._binding is not None and not self._probe_ok:
            reason = "runtime_static_scanner_probe_failed"
        elif self._binding is not None and self._probe_ok and not self._roots:
            reason = "smart_scan_roots_unavailable"
        return {
            "available": available,
            "accepted": available,
            "provider_name": PROVIDER_NAME,
            "provider_profile": PROVIDER_PROFILE,
            "provider_provenance": PROVIDER_PROVENANCE,
            "reason": reason,
            "automatic_quarantine": False,
            "automatic_repair": False,
            "automatic_destructive_action": False,
            "runtime_binding": self._binding.to_dict() if self._binding else {},
            "runtime_probe": dict(self._probe_evidence),
            "roots": [str(path) for path in self._roots],
        }

    def build_plan(self) -> smart.SmartScanPlan:
        checks = tuple(
            smart.SmartScanCheck(
                check_id=f"static_root_{index:02d}",
                label=f"Static malware scan — {root}",
                purpose="Scan this configured quick-scan root with the existing BC Sentinel StaticScanner.",
                available=bool(self._binding is not None and self._probe_ok),
                provenance=PROVIDER_PROVENANCE,
                work_units=1,
                raw={"root": str(root)},
            )
            for index, root in enumerate(self._roots, start=1)
        )
        if not checks:
            checks = (
                smart.SmartScanCheck(
                    check_id="static_runtime",
                    label="Static malware scan runtime",
                    purpose="Verify the pinned full-runtime scanner and at least one scan root.",
                    available=False,
                    provenance=PROVIDER_PROVENANCE,
                    work_units=0,
                    raw={"reason": self.capabilities().get("reason", "unavailable")},
                ),
            )
        return smart.SmartScanPlan(
            provider_name=PROVIDER_NAME,
            provider_profile=PROVIDER_PROFILE,
            provider_provenance=PROVIDER_PROVENANCE,
            checks=checks,
            raw={"runtime": self._binding.to_dict() if self._binding else {}, "roots": [str(p) for p in self._roots]},
        )

    def _run_root(self, check: smart.SmartScanCheck, cancel_check: Callable[[], bool]) -> smart.SmartScanCheckResult:
        if self._binding is None or not self._probe_ok:
            return smart.SmartScanCheckResult(
                check_id=check.check_id,
                status=smart.CHECK_UNAVAILABLE,
                summary="Pinned StaticScanner runtime is unavailable.",
                evidence={"capabilities": dict(self.capabilities())},
            )
        root = Path(str(check.raw.get("root") or ""))
        if not root.exists():
            return smart.SmartScanCheckResult(
                check_id=check.check_id,
                status=smart.CHECK_FAILED,
                summary="Configured scan root disappeared before execution.",
                evidence={"root": str(root)},
            )

        findings: list[smart.SmartScanFinding] = []
        recognized_reports = 0
        unrecognized_reports = 0
        report_count = 0
        output_tail: list[str] = []
        error_payload: dict = {}
        summary_seen = False

        with tempfile.TemporaryDirectory(prefix="BCSentinel-B63-") as temp_dir:
            cancel_path = Path(temp_dir) / "cancel.request"
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

            watcher = Thread(target=watch_cancel, name="BCS-B63-CancelWatch", daemon=True)
            watcher.start()
            try:
                proc = subprocess.Popen(
                    [str(self._binding.python_executable), "-c", _CHILD, str(root), str(cancel_path)],
                    cwd=str(self._binding.root),
                    env=_runtime_env(self._binding),
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
                        output_tail = output_tail[-30:]
                    try:
                        item = json.loads(line)
                    except Exception:
                        continue
                    if not isinstance(item, dict):
                        continue
                    kind = item.get("type")
                    if kind == "report":
                        report_count += 1
                        payload = _safe_payload(item.get("payload"))
                        finding, recognized = _finding_from_report(check.check_id, payload, report_count)
                        if recognized:
                            recognized_reports += 1
                        else:
                            unrecognized_reports += 1
                        if finding is not None:
                            findings.append(finding)
                    elif kind == "summary":
                        summary_seen = True
                    elif kind == "error":
                        error_payload = item
                returncode = proc.wait()
            except Exception as exc:
                return smart.SmartScanCheckResult(
                    check_id=check.check_id,
                    status=smart.CHECK_FAILED,
                    summary="StaticScanner subprocess failed to execute.",
                    evidence={"root": str(root), "error": f"{type(exc).__name__}: {exc}"},
                )
            finally:
                watcher_stop.set()
                watcher.join(timeout=1.0)

        cancelled = cancel_check()
        if cancelled:
            return smart.SmartScanCheckResult(
                check_id=check.check_id,
                status=smart.CHECK_CANCELLED,
                summary="Static malware scan cancelled by the user.",
                findings=tuple(findings),
                evidence={"root": str(root), "reports": report_count, "output_tail": output_tail[-10:]},
            )
        if returncode != 0 or error_payload or not summary_seen:
            return smart.SmartScanCheckResult(
                check_id=check.check_id,
                status=smart.CHECK_FAILED,
                summary="StaticScanner did not complete this root cleanly.",
                findings=tuple(findings),
                evidence={
                    "root": str(root),
                    "returncode": returncode,
                    "runtime_error": error_payload,
                    "summary_seen": summary_seen,
                    "output_tail": output_tail[-10:],
                },
            )
        if unrecognized_reports:
            return smart.SmartScanCheckResult(
                check_id=check.check_id,
                status=smart.CHECK_FAILED,
                summary="StaticScanner returned report data that the B6-3 adapter cannot classify safely.",
                findings=tuple(findings),
                evidence={
                    "root": str(root),
                    "reports": report_count,
                    "recognized_reports": recognized_reports,
                    "unrecognized_reports": unrecognized_reports,
                },
            )
        return smart.SmartScanCheckResult(
            check_id=check.check_id,
            status=smart.CHECK_COMPLETED,
            summary=f"StaticScanner completed {report_count} auditable file reports for this root.",
            findings=tuple(findings),
            evidence={
                "root": str(root),
                "reports": report_count,
                "recognized_reports": recognized_reports,
                "scanner_sha256": self._binding.scanner_sha256,
            },
        )

    def run(
        self,
        plan: smart.SmartScanPlan,
        progress_callback: Callable[[smart.SmartScanProgress], None],
        cancel_check: Callable[[], bool],
    ) -> smart.SmartScanProviderResult:
        plan.validate()
        results: list[smart.SmartScanCheckResult] = []
        total = len(plan.checks)
        for index, check in enumerate(plan.checks):
            if cancel_check():
                results.append(
                    smart.SmartScanCheckResult(
                        check_id=check.check_id,
                        status=smart.CHECK_CANCELLED,
                        summary="Smart Scan cancelled before this root started.",
                    )
                )
                for rest in plan.checks[index + 1 :]:
                    results.append(
                        smart.SmartScanCheckResult(
                            check_id=rest.check_id,
                            status=smart.CHECK_SKIPPED,
                            summary="Skipped after user cancellation.",
                        )
                    )
                break
            progress_callback(
                smart.SmartScanProgress(
                    percent=int((index / max(total, 1)) * 100),
                    completed_checks=index,
                    total_checks=total,
                    current_check_id=check.check_id,
                    message=f"Scanning {check.raw.get('root', check.label)}",
                )
            )
            result = self._run_root(check, cancel_check)
            results.append(result)
            completed = index + 1
            progress_callback(
                smart.SmartScanProgress(
                    percent=int((completed / max(total, 1)) * 100),
                    completed_checks=completed,
                    total_checks=total,
                    current_check_id=check.check_id,
                    message=result.summary,
                )
            )
            if result.status == smart.CHECK_CANCELLED:
                for rest in plan.checks[index + 1 :]:
                    results.append(
                        smart.SmartScanCheckResult(
                            check_id=rest.check_id,
                            status=smart.CHECK_SKIPPED,
                            summary="Skipped after user cancellation.",
                        )
                    )
                break

        return smart.SmartScanProviderResult(
            check_results=tuple(results),
            raw_evidence={
                "runtime_binding": self._binding.to_dict() if self._binding else {},
                "runtime_probe": dict(self._probe_evidence),
                "roots": [str(path) for path in self._roots],
                "automatic_quarantine": False,
                "automatic_repair": False,
                "automatic_destructive_action": False,
            },
        )


def create_provider() -> StaticScannerLiveProvider:
    """Factory consumed by the fixed fail-closed B6-3 provider loader."""
    return StaticScannerLiveProvider()

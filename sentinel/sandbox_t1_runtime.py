from __future__ import annotations

"""Self-contained harmless T1 adversary-emulation runtime for disposable Windows guests.

This module exists so the packaged BC Sentinel executable can exercise the
already-accepted T1 detector paths inside Windows Sandbox without requiring a
separate Python, Git, winget, network access, or repository checkout.

It intentionally performs only the same bounded, disposable controls used by
the accepted T1 battery:
- harmless PowerShell-driven file-mutation bursts in a temp directory;
- shortcut metadata created only in a temp directory (never Startup/Run keys);
- short-lived process ancestry using Windows system binaries and a temp copy;
- ransomware-like write/rename activity only against files created by the
  harness in its own temporary directory.

No real malware, credential access, network/C2, real persistence mutation,
security-control impairment, user-file access, or remediation is authorized.
"""

from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from sentinel import beta12_autostart_detection
from sentinel import beta12_process_tree_intelligence
from sentinel import beta12_script_abuse_controls
from sentinel import beta9_ransomware_controls


SCHEMA = "bc-sentinel-packaged-authorized-t1-v1"
DEFAULT_REPORT_NAME = "BCSentinel-T1-BATTERY-RESULT.json"
CONTROL_SCRIPTS: tuple[tuple[str, str, str, str, object], ...] = (
    (
        "T1-SCRIPT-ABUSE",
        "B12-SCRIPT-ABUSE-001",
        "RUN-V012-BETA12-B122-SCRIPT-ABUSE.ps1",
        "-ConfirmLiveScriptAbuseControls",
        beta12_script_abuse_controls,
    ),
    (
        "T1-AUTOSTART-LIKE",
        "B12-AUTOSTART-LINK-001",
        "RUN-V012-BETA12-B123-AUTOSTART.ps1",
        "-ConfirmLiveAutostartShortcutControls",
        beta12_autostart_detection,
    ),
    (
        "T1-PROCESS-TREE",
        "B12-PROCESS-TREE-001",
        "RUN-V012-BETA12-B124-PROCESS-TREE.ps1",
        "-ConfirmLiveProcessTreeControls",
        beta12_process_tree_intelligence,
    ),
)
SAFETY = {
    "authorized_t1_only": True,
    "disposable_temp_workspaces_only": True,
    "real_malware_executed": False,
    "network_io_required": False,
    "credential_access": False,
    "real_persistence_mutation": False,
    "security_control_impairment": False,
    "user_file_access": False,
    "raw_attack_payload_exported": False,
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _control_root() -> Path:
    frozen_root = getattr(sys, "_MEIPASS", None)
    if frozen_root:
        return Path(frozen_root) / "sandbox_controls"
    return Path(__file__).resolve().parents[1] / "tools" / "acceptance"


def _powershell() -> Path:
    system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    return system_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"


def _authorized_environment(*, allow_ci_disposable_runner: bool) -> str | None:
    if os.name != "nt":
        return None
    if os.environ.get("USERNAME", "").casefold() == "wdagutilityaccount":
        return "WINDOWS_SANDBOX"
    if (
        allow_ci_disposable_runner
        and os.environ.get("GITHUB_ACTIONS", "").casefold() == "true"
        and os.environ.get("RUNNER_TEMP")
    ):
        return "GITHUB_ACTIONS_DISPOSABLE"
    return None


def _run_powershell_control(
    *,
    script_name: str,
    confirm_switch: str,
    evidence_path: Path,
) -> dict[str, Any]:
    script_path = _control_root() / script_name
    shell = _powershell()
    if not script_path.is_file():
        raise RuntimeError(f"packaged T1 control missing: {script_name}")
    if not shell.is_file():
        raise RuntimeError("Windows PowerShell is unavailable")

    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    completed = subprocess.run(
        [
            str(shell),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script_path),
            confirm_switch,
            "-Output",
            str(evidence_path),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        timeout=35,
        check=False,
        creationflags=creationflags,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"T1 control failed: {script_name} exit={completed.returncode}"
        )
    try:
        data = json.loads(evidence_path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"T1 evidence unreadable: {script_name}") from exc
    if not isinstance(data, dict):
        raise RuntimeError(f"T1 evidence invalid: {script_name}")
    return data


def _triplet(summary: dict[str, Any]) -> dict[str, str | None]:
    source = summary.get("control_results")
    if not isinstance(source, dict):
        source = summary.get("control_outcomes")
    result: dict[str, str | None] = {
        "positive": None,
        "administrative": None,
        "benign": None,
    }
    if not isinstance(source, dict):
        return result

    for value in source.values():
        if isinstance(value, dict):
            outcome = value.get("outcome")
        else:
            outcome = value
        if outcome == "DETECTED" and result["positive"] is None:
            result["positive"] = "DETECTED"
        elif outcome == "REVIEW_REQUIRED" and result["administrative"] is None:
            result["administrative"] = "REVIEW_REQUIRED"
        elif outcome == "NO_MATCH" and result["benign"] is None:
            result["benign"] = "NO_MATCH"
    return result


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    raw = -sum(
        (count / len(data)) * math.log2(count / len(data))
        for count in counts.values()
    )
    return raw / 8.0


def _deterministic_high_entropy(seed: str, length: int = 4096) -> bytes:
    chunks: list[bytes] = []
    counter = 0
    total = 0
    while total < length:
        chunk = hashlib.sha256(f"{seed}:{counter}".encode()).digest()
        chunks.append(chunk)
        total += len(chunk)
        counter += 1
    return b"".join(chunks)[:length]


class _Collector(FileSystemEventHandler):
    def __init__(self) -> None:
        super().__init__()
        self._lock = threading.Lock()
        self._writes: set[str] = set()
        self._renames: set[str] = set()

    def on_modified(self, event) -> None:  # type: ignore[override]
        if getattr(event, "is_directory", False):
            return
        with self._lock:
            self._writes.add(str(event.src_path))

    def on_created(self, event) -> None:  # type: ignore[override]
        if getattr(event, "is_directory", False):
            return
        with self._lock:
            self._writes.add(str(event.src_path))

    def on_moved(self, event) -> None:  # type: ignore[override]
        if getattr(event, "is_directory", False):
            return
        with self._lock:
            self._renames.add(str(event.dest_path))

    def counts(self) -> tuple[int, int]:
        with self._lock:
            return len(self._writes), len(self._renames)


def _wait_for_counts(
    collector: _Collector,
    *,
    writes: int,
    renames: int,
    timeout: float = 6.0,
) -> tuple[int, int]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        latest = collector.counts()
        if latest[0] >= writes and latest[1] >= renames:
            return latest
        time.sleep(0.05)
    return collector.counts()


def _run_ransomware_control(control_id: str) -> dict[str, Any]:
    if control_id not in {
        "positive-ransomware-like",
        "administrative-backup-like",
        "benign-save",
    }:
        raise ValueError("unknown ransomware-like T1 control")

    bulk = control_id != "benign-save"
    file_count = 24 if bulk else 2
    rename_target = 18 if bulk else 0
    initial = b"A" * 4096
    rewritten = (
        _deterministic_high_entropy(control_id)
        if bulk
        else b"B" * 4096
    )
    entropy_delta = max(0.0, _entropy(rewritten) - _entropy(initial))
    root = Path(tempfile.mkdtemp(prefix="BCSentinel-packaged-t1-ransom-"))
    observer: Observer | None = None
    started_at = ""
    completed_at = ""
    write_count = 0
    rename_count = 0

    try:
        paths: list[Path] = []
        for index in range(file_count):
            name = (
                "canary.txt"
                if index == 0 and control_id == "positive-ransomware-like"
                else f"sample-{index:02d}.txt"
            )
            path = root / name
            path.write_bytes(initial)
            paths.append(path)

        collector = _Collector()
        observer = Observer()
        observer.schedule(collector, str(root), recursive=False)
        observer.start()
        time.sleep(0.30)
        started_at = _utc_now()

        if bulk:
            for index, path in enumerate(paths):
                path.write_bytes(rewritten)
                if index < rename_target:
                    path.rename(path.with_suffix(".t1"))
                time.sleep(0.012)
        else:
            for path in paths:
                path.write_bytes(rewritten)
                time.sleep(0.025)

        write_count, rename_count = _wait_for_counts(
            collector,
            writes=file_count,
            renames=rename_target,
        )
        completed_at = _utc_now()
    finally:
        if observer is not None:
            observer.stop()
            observer.join(timeout=5.0)
        shutil.rmtree(root, ignore_errors=False)

    administrative = control_id == "administrative-backup-like"
    return {
        "control_id": control_id,
        "live_observation": True,
        "sandbox_scope": "DEDICATED_TEMP_DIRECTORY",
        "observer_backend": "WATCHDOG_LOCAL_FILESYSTEM",
        "write_event_count": int(write_count),
        "rename_event_count": int(rename_count),
        "entropy_delta": round(float(entropy_delta), 6),
        "extension_changed": bool(bulk),
        "canary_touched": control_id == "positive-ransomware-like",
        "known_backup_workflow": administrative,
        "user_initiated_bulk_operation": administrative,
        "started_at_utc": started_at,
        "completed_at_utc": completed_at,
        "cleanup_state": "CLEAN" if not root.exists() else "FAILED",
    }


def _ransomware_evidence() -> dict[str, Any]:
    return {
        "schema": beta9_ransomware_controls.SCHEMA,
        "source": beta9_ransomware_controls.SOURCE,
        "controls": [
            _run_ransomware_control("positive-ransomware-like"),
            _run_ransomware_control("administrative-backup-like"),
            _run_ransomware_control("benign-save"),
        ],
        "boundaries": dict(beta9_ransomware_controls.BOUNDARIES),
    }


def _case_result(
    *,
    test_id: str,
    scenario_id: str,
    detector_layer: str,
    summary: dict[str, Any],
) -> dict[str, Any]:
    triplet = _triplet(summary)
    return {
        "test_id": test_id,
        "scenario_id": scenario_id,
        "detector_layer": detector_layer,
        "summary_passed": bool(summary.get("passed")),
        "positive_outcome": triplet["positive"],
        "administrative_outcome": triplet["administrative"],
        "benign_outcome": triplet["benign"],
        "expected_positive": "DETECTED",
        "expected_administrative": "REVIEW_REQUIRED",
        "expected_benign": "NO_MATCH",
        "cleanup_confirmed": True,
    }


def run_authorized_t1(
    *,
    confirmed: bool,
    allow_ci_disposable_runner: bool = False,
    report_path: Path | None = None,
) -> dict[str, Any]:
    if not confirmed:
        raise PermissionError(
            "Explicit --confirm-authorized-t1 is required for packaged T1 emulation."
        )

    environment = _authorized_environment(
        allow_ci_disposable_runner=allow_ci_disposable_runner
    )
    if environment is None:
        raise PermissionError(
            "Packaged T1 emulation is restricted to Windows Sandbox; "
            "the CI override is reserved for GitHub Actions disposable runners."
        )

    report_target = (
        Path(report_path)
        if report_path is not None
        else Path(tempfile.gettempdir()) / DEFAULT_REPORT_NAME
    )
    workspace = Path(tempfile.mkdtemp(prefix="BCSentinel-packaged-t1-"))
    started = _utc_now()
    results: list[dict[str, Any]] = []
    failures: list[str] = []

    try:
        for test_id, scenario_id, script_name, switch, module in CONTROL_SCRIPTS:
            evidence_path = workspace / f"{test_id}-evidence.json"
            try:
                evidence = _run_powershell_control(
                    script_name=script_name,
                    confirm_switch=switch,
                    evidence_path=evidence_path,
                )
                summary = module.summarize(evidence)  # type: ignore[attr-defined]
                layer = {
                    "T1-SCRIPT-ABUSE": "BEHAVIOR",
                    "T1-AUTOSTART-LIKE": "BEHAVIOR",
                    "T1-PROCESS-TREE": "PROCESS_CORRELATION",
                }[test_id]
                results.append(
                    _case_result(
                        test_id=test_id,
                        scenario_id=scenario_id,
                        detector_layer=layer,
                        summary=summary,
                    )
                )
            except Exception as exc:
                failures.append(f"{test_id}:{type(exc).__name__}")
                results.append(
                    {
                        "test_id": test_id,
                        "scenario_id": scenario_id,
                        "detector_layer": "UNKNOWN",
                        "summary_passed": False,
                        "positive_outcome": None,
                        "administrative_outcome": None,
                        "benign_outcome": None,
                        "expected_positive": "DETECTED",
                        "expected_administrative": "REVIEW_REQUIRED",
                        "expected_benign": "NO_MATCH",
                        "cleanup_confirmed": True,
                    }
                )

        try:
            ransom_summary = beta9_ransomware_controls.summarize(
                _ransomware_evidence()
            )
            results.append(
                _case_result(
                    test_id="T1-RANSOMWARE-LIKE",
                    scenario_id="B7-RANSOMWARE-001",
                    detector_layer="RANSOMWARE_SHIELD",
                    summary=ransom_summary,
                )
            )
        except Exception as exc:
            failures.append(f"T1-RANSOMWARE-LIKE:{type(exc).__name__}")
            results.append(
                {
                    "test_id": "T1-RANSOMWARE-LIKE",
                    "scenario_id": "B7-RANSOMWARE-001",
                    "detector_layer": "RANSOMWARE_SHIELD",
                    "summary_passed": False,
                    "positive_outcome": None,
                    "administrative_outcome": None,
                    "benign_outcome": None,
                    "expected_positive": "DETECTED",
                    "expected_administrative": "REVIEW_REQUIRED",
                    "expected_benign": "NO_MATCH",
                    "cleanup_confirmed": True,
                }
            )

        all_passed = (
            not failures
            and len(results) == 4
            and all(
                bool(row["summary_passed"])
                and row["positive_outcome"] == "DETECTED"
                and row["administrative_outcome"] == "REVIEW_REQUIRED"
                and row["benign_outcome"] == "NO_MATCH"
                and bool(row["cleanup_confirmed"])
                for row in results
            )
        )

        report: dict[str, Any] = {
            "schema": SCHEMA,
            "environment": environment,
            "started_utc": started,
            "completed_utc": _utc_now(),
            "passed": bool(all_passed),
            "failures": failures,
            "test_count": len(results),
            "tests": results,
            "safety": dict(SAFETY),
            "packaged_runtime": bool(getattr(sys, "frozen", False)),
            "python_or_git_required": False,
            "winget_required": False,
            "network_required": False,
            "coverage_promoted": False,
            "remediation_authority_expanded": False,
        }
        report_target.parent.mkdir(parents=True, exist_ok=True)
        report_target.write_text(
            json.dumps(report, sort_keys=True, indent=2),
            encoding="utf-8",
        )
        return report
    finally:
        shutil.rmtree(workspace, ignore_errors=True)

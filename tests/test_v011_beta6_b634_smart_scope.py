from __future__ import annotations

import hashlib
from pathlib import Path
from threading import Thread
import time

from sentinel import home_smart_scan as smart
from sentinel import smart_scan_live_provider as live
from sentinel import smart_scan_runtime_compat as compat
from sentinel import smart_scan_scope as scope

compat.apply(live)


def _write_runtime(root: Path, body: str) -> str:
    sentinel = root / "sentinel"
    sentinel.mkdir(parents=True)
    (sentinel / "__init__.py").write_text("", encoding="utf-8")
    scanner = sentinel / "scanner.py"
    scanner.write_text(body, encoding="utf-8")
    return hashlib.sha256(scanner.read_bytes()).hexdigest()


def _configure(monkeypatch, runtime: Path, digest: str, scan_root: Path) -> None:
    monkeypatch.setenv(live.RUNTIME_ROOT_ENV, str(runtime))
    monkeypatch.setenv(live.SCANNER_SHA_ENV, digest)
    monkeypatch.setenv(live.SMART_SCAN_ROOTS_ENV, str(scan_root))
    monkeypatch.setenv(scope.MAX_FILES_ENV, "100")
    monkeypatch.setenv(scope.MAX_TOTAL_BYTES_ENV, str(64 * 1024 * 1024))
    monkeypatch.setenv(scope.MAX_FILE_BYTES_ENV, str(16 * 1024 * 1024))
    monkeypatch.setenv(scope.RECENT_DAYS_ENV, "365")


def test_scope_prioritizes_risky_files_and_skips_build_noise(tmp_path) -> None:
    root = tmp_path / "Downloads"
    root.mkdir()
    (root / "recent.ps1").write_text("Write-Output ok", encoding="utf-8")
    (root / "notes.txt").write_text("plain text", encoding="utf-8")
    ignored = root / "node_modules" / "package"
    ignored.mkdir(parents=True)
    (ignored / "tool.exe").write_bytes(b"MZfixture")

    selection = scope.select_scope(
        (root,),
        scope.ScopePolicy(max_files=50, max_total_bytes=8 * 1024 * 1024, max_file_bytes=4 * 1024 * 1024, recent_days=365),
    )

    selected = [item.path.name for item in selection.groups[0].selected]
    assert selected == ["recent.ps1"]
    assert selection.groups[0].candidate_pool_count == 1
    assert selection.policy.to_dict()["full_filesystem_coverage"] is False


def test_scope_budget_selects_highest_risk_first(tmp_path) -> None:
    root = tmp_path / "Downloads"
    root.mkdir()
    (root / "payload.exe").write_bytes(b"MZ")
    (root / "archive.zip").write_bytes(b"PK")
    selection = scope.select_scope(
        (root,),
        scope.ScopePolicy(max_files=1, max_total_bytes=1024 * 1024, max_file_bytes=1024 * 1024, recent_days=365),
    )
    assert len(selection.groups[0].selected) == 1
    assert selection.groups[0].selected[0].path.name == "payload.exe"
    assert selection.groups[0].skipped_budget == 1


def test_real_provider_uses_scan_file_not_broad_scan_paths(tmp_path, monkeypatch) -> None:
    runtime = tmp_path / "runtime"
    scan_root = tmp_path / "Downloads"
    scan_root.mkdir()
    (scan_root / "fixture.ps1").write_text("Write-Output ok", encoding="utf-8")
    (scan_root / "ignore.txt").write_text("not part of smart scope", encoding="utf-8")
    digest = _write_runtime(
        runtime,
        """
class StaticScanner:
    def scan_paths(self, roots, cancelled=None):
        raise AssertionError('broad scan_paths must not run in B6-3.4')
    def scan_file(self, path):
        return {
            'path': str(path),
            'sha256': 'abc123',
            'assessment': {'score': 0, 'level': 'SAFE', 'reasons': [], 'signals': [], 'confidence': 1.0}
        }
""".strip() + "\n",
    )
    _configure(monkeypatch, runtime, digest, scan_root)

    provider = live.create_provider()
    caps = dict(provider.capabilities())
    assert caps["provider_profile"] == scope.PROFILE
    assert caps["scope_mode"] == scope.MODE
    assert caps["full_filesystem_coverage"] is False

    progress: list[int] = []
    result = smart.SmartScanCoordinator(provider).run_sync(lambda item: progress.append(item.percent))
    assert result.state == smart.STATE_COMPLETED_CLEAN
    assert result.coverage == smart.COVERAGE_COMPLETE
    assert result.completed_checks == result.total_checks == 1
    assert result.plan.raw["selected_count"] == 1
    assert result.check_results[0].evidence["planned_files"] == 1
    assert progress == sorted(progress)
    assert progress[-1] == 100


def test_scope_scan_preserves_historical_finding(tmp_path, monkeypatch) -> None:
    runtime = tmp_path / "runtime"
    scan_root = tmp_path / "Temp"
    scan_root.mkdir()
    (scan_root / "fixture.exe").write_bytes(b"MZfixture")
    digest = _write_runtime(
        runtime,
        """
class StaticScanner:
    def scan_paths(self, roots, cancelled=None):
        return iter(())
    def scan_file(self, path):
        return {
            'path': str(path),
            'sha256': 'feedbeef',
            'assessment': {
                'score': 90,
                'level': 'HIGH',
                'reasons': ['Controlled fixture evidence.'],
                'signals': [{'key': 'fixture_high', 'reason': 'Controlled fixture evidence.'}],
                'confidence': 0.9
            }
        }
""".strip() + "\n",
    )
    _configure(monkeypatch, runtime, digest, scan_root)

    result = smart.SmartScanCoordinator(live.create_provider()).run_sync()
    assert result.state == smart.STATE_COMPLETED_FINDINGS
    assert result.coverage == smart.COVERAGE_COMPLETE
    assert len(result.findings) == 1
    assert result.findings[0].severity == smart.SEVERITY_HIGH
    assert result.findings[0].indicator == "feedbeef"


def test_scope_scan_fails_closed_on_per_file_error(tmp_path, monkeypatch) -> None:
    runtime = tmp_path / "runtime"
    scan_root = tmp_path / "Downloads"
    scan_root.mkdir()
    (scan_root / "fixture.exe").write_bytes(b"MZfixture")
    digest = _write_runtime(
        runtime,
        """
class StaticScanner:
    def scan_paths(self, roots, cancelled=None):
        return iter(())
    def scan_file(self, path):
        raise PermissionError('controlled fixture refusal')
""".strip() + "\n",
    )
    _configure(monkeypatch, runtime, digest, scan_root)

    result = smart.SmartScanCoordinator(live.create_provider()).run_sync()
    assert result.state == smart.STATE_INCOMPLETE
    assert result.coverage == smart.COVERAGE_INCOMPLETE
    assert result.state != smart.STATE_COMPLETED_CLEAN


def test_scope_live_cancellation_stops_between_files(tmp_path, monkeypatch) -> None:
    runtime = tmp_path / "runtime"
    scan_root = tmp_path / "Downloads"
    scan_root.mkdir()
    for index in range(8):
        (scan_root / f"fixture-{index}.exe").write_bytes(b"MZfixture")
    digest = _write_runtime(
        runtime,
        """
import time
class StaticScanner:
    def scan_paths(self, roots, cancelled=None):
        return iter(())
    def scan_file(self, path):
        time.sleep(0.15)
        return {
            'path': str(path),
            'assessment': {'score': 0, 'level': 'SAFE', 'reasons': [], 'signals': []}
        }
""".strip() + "\n",
    )
    _configure(monkeypatch, runtime, digest, scan_root)

    coordinator = smart.SmartScanCoordinator(live.create_provider())
    holder: dict[str, object] = {}

    def run() -> None:
        holder["result"] = coordinator.run_sync()

    worker = Thread(target=run)
    worker.start()
    deadline = time.time() + 3.0
    while coordinator.state != smart.STATE_RUNNING and time.time() < deadline:
        time.sleep(0.01)
    assert coordinator.request_cancel() is True
    worker.join(timeout=5.0)
    assert not worker.is_alive()
    result = holder["result"]
    assert result.state == smart.STATE_CANCELLED
    assert result.coverage == smart.COVERAGE_INCOMPLETE


def test_scope_guard_excludes_exact_pinned_runtime_from_plan(tmp_path, monkeypatch) -> None:
    scan_root = tmp_path / "Downloads"
    scan_root.mkdir()
    runtime = scan_root / "BC_Sentinel_pinned_runtime"
    outside = scan_root / "outside.ps1"
    outside.write_text("Write-Output outside", encoding="utf-8")

    digest = _write_runtime(
        runtime,
        """
from pathlib import Path
RUNTIME_ROOT = Path(__file__).resolve().parents[1]
class StaticScanner:
    def scan_paths(self, roots, cancelled=None):
        raise AssertionError('broad scan_paths must not run in B6-3.4')
    def scan_file(self, path):
        target = Path(path).resolve()
        if target == RUNTIME_ROOT or RUNTIME_ROOT in target.parents:
            raise ValueError('BC Sentinel self-managed path excluded from normal scanning.')
        return {
            'path': str(path),
            'sha256': 'outside-safe',
            'assessment': {'score': 0, 'level': 'SAFE', 'reasons': [], 'signals': [], 'confidence': 1.0}
        }
""".strip() + "\n",
    )
    (runtime / "self-managed.ps1").write_text("Write-Output self-managed", encoding="utf-8")
    _configure(monkeypatch, runtime, digest, scan_root)

    provider = live.create_provider()
    caps = dict(provider.capabilities())
    assert caps["scope_guard"] == "exclude_pinned_runtime_root_v1"
    assert caps["self_managed_runtime_excluded"] is True

    result = smart.SmartScanCoordinator(provider).run_sync()
    assert result.state == smart.STATE_COMPLETED_CLEAN
    assert result.coverage == smart.COVERAGE_COMPLETE
    assert result.plan.raw["selected_count"] == 1
    assert result.plan.raw["excluded_candidate_count"] >= 1
    assert result.plan.raw["scope_guard"] == "exclude_pinned_runtime_root_v1"
    assert result.check_results[0].evidence["planned_files"] == 1

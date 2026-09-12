from __future__ import annotations

import hashlib
import json
from pathlib import Path

from sentinel import home_smart_scan as smart
from sentinel import smart_scan_live_provider as live


def _write_runtime(root: Path, body: str) -> tuple[Path, str]:
    sentinel = root / "sentinel"
    sentinel.mkdir(parents=True)
    (sentinel / "__init__.py").write_text("", encoding="utf-8")
    scanner = sentinel / "scanner.py"
    scanner.write_text(body, encoding="utf-8")
    digest = hashlib.sha256(scanner.read_bytes()).hexdigest()
    return scanner, digest


def _configure(monkeypatch, runtime: Path, digest: str, scan_root: Path) -> None:
    monkeypatch.setenv(live.RUNTIME_ROOT_ENV, str(runtime))
    monkeypatch.setenv(live.SCANNER_SHA_ENV, digest)
    monkeypatch.setenv(live.SMART_SCAN_ROOTS_ENV, str(scan_root))


def test_adapter_fails_closed_without_runtime_pin(monkeypatch) -> None:
    monkeypatch.delenv(live.RUNTIME_ROOT_ENV, raising=False)
    monkeypatch.delenv(live.SCANNER_SHA_ENV, raising=False)
    provider = live.create_provider()
    caps = dict(provider.capabilities())
    assert caps["available"] is False
    assert caps["accepted"] is False
    assert caps["reason"] == "runtime_root_not_configured"
    assert caps["automatic_quarantine"] is False
    assert caps["automatic_repair"] is False
    assert caps["automatic_destructive_action"] is False


def test_adapter_rejects_wrong_scanner_hash(tmp_path, monkeypatch) -> None:
    runtime = tmp_path / "runtime"
    scan_root = tmp_path / "scan"
    scan_root.mkdir()
    _write_runtime(runtime, "class StaticScanner:\n    def scan_paths(self, roots, cancelled=None):\n        return iter(())\n")
    _configure(monkeypatch, runtime, "0" * 64, scan_root)
    provider = live.create_provider()
    caps = dict(provider.capabilities())
    assert caps["available"] is False
    assert caps["reason"] == "runtime_scanner_sha256_mismatch"


def test_verified_runtime_clean_scan_is_complete(tmp_path, monkeypatch) -> None:
    runtime = tmp_path / "runtime"
    scan_root = tmp_path / "scan"
    scan_root.mkdir()
    (scan_root / "sample.ps1").write_text("Write-Output 'ok'", encoding="utf-8")
    _, digest = _write_runtime(
        runtime,
        """
class StaticScanner:
    def scan_paths(self, roots, cancelled=None):
        for root in roots:
            if cancelled and cancelled():
                return
            yield {"path": str(root) + "/sample.ps1", "detections": [], "verdict": "clean"}
""".strip()
        + "\n",
    )
    _configure(monkeypatch, runtime, digest, scan_root)

    provider = live.create_provider()
    caps = dict(provider.capabilities())
    assert caps["available"] is True
    assert caps["accepted"] is True

    coordinator = smart.SmartScanCoordinator(provider)
    result = coordinator.run_sync()
    assert result.state == smart.STATE_COMPLETED_CLEAN
    assert result.coverage == smart.COVERAGE_COMPLETE
    assert result.findings == ()
    assert result.automatic_quarantine is False
    assert result.automatic_repair is False
    assert result.automatic_destructive_action is False


def test_verified_runtime_detection_is_preserved(tmp_path, monkeypatch) -> None:
    runtime = tmp_path / "runtime"
    scan_root = tmp_path / "scan"
    scan_root.mkdir()
    _, digest = _write_runtime(
        runtime,
        """
class StaticScanner:
    def scan_paths(self, roots, cancelled=None):
        yield {
            "path": str(roots[0]) + "/fixture.exe",
            "detections": [{"name": "Fixture.Test"}],
            "verdict": "malicious",
            "sha256": "abc123"
        }
""".strip()
        + "\n",
    )
    _configure(monkeypatch, runtime, digest, scan_root)

    result = smart.SmartScanCoordinator(live.create_provider()).run_sync()
    assert result.state == smart.STATE_COMPLETED_FINDINGS
    assert result.coverage == smart.COVERAGE_COMPLETE
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.category == "static_malware_scan"
    assert finding.severity == smart.SEVERITY_HIGH
    assert finding.indicator == "abc123"


def test_unrecognized_runtime_report_never_becomes_clean(tmp_path, monkeypatch) -> None:
    runtime = tmp_path / "runtime"
    scan_root = tmp_path / "scan"
    scan_root.mkdir()
    _, digest = _write_runtime(
        runtime,
        """
class StaticScanner:
    def scan_paths(self, roots, cancelled=None):
        yield {"path": str(roots[0]) + "/unknown.bin", "opaque": "value"}
""".strip()
        + "\n",
    )
    _configure(monkeypatch, runtime, digest, scan_root)

    result = smart.SmartScanCoordinator(live.create_provider()).run_sync()
    assert result.state == smart.STATE_INCOMPLETE
    assert result.coverage == smart.COVERAGE_INCOMPLETE
    assert result.state != smart.STATE_COMPLETED_CLEAN


def test_runtime_import_failure_is_not_accepted(tmp_path, monkeypatch) -> None:
    runtime = tmp_path / "runtime"
    scan_root = tmp_path / "scan"
    scan_root.mkdir()
    _, digest = _write_runtime(runtime, "raise RuntimeError('broken runtime')\n")
    _configure(monkeypatch, runtime, digest, scan_root)
    provider = live.create_provider()
    caps = dict(provider.capabilities())
    assert caps["available"] is False
    assert caps["accepted"] is False
    assert caps["reason"] == "runtime_static_scanner_probe_failed"


def test_adapter_plan_exposes_exact_configured_scope(tmp_path, monkeypatch) -> None:
    runtime = tmp_path / "runtime"
    scan_a = tmp_path / "A"
    scan_b = tmp_path / "B"
    scan_a.mkdir()
    scan_b.mkdir()
    _, digest = _write_runtime(
        runtime,
        "class StaticScanner:\n    def scan_paths(self, roots, cancelled=None):\n        return iter(())\n",
    )
    monkeypatch.setenv(live.RUNTIME_ROOT_ENV, str(runtime))
    monkeypatch.setenv(live.SCANNER_SHA_ENV, digest)
    monkeypatch.setenv(live.SMART_SCAN_ROOTS_ENV, str(scan_a) + live.os.pathsep + str(scan_b))

    provider = live.create_provider()
    plan = provider.build_plan()
    assert [item.raw["root"] for item in plan.checks] == [str(scan_a.resolve()), str(scan_b.resolve())]
    assert all(item.provenance == live.PROVIDER_PROVENANCE for item in plan.checks)

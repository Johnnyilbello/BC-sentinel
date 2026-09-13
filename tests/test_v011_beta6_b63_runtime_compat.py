from __future__ import annotations

import hashlib
from pathlib import Path

from sentinel import home_smart_scan as smart
from sentinel import smart_scan_live_provider as live
from sentinel import smart_scan_runtime_compat as compat


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


def test_historical_safe_assessment_is_recognized_clean(tmp_path, monkeypatch) -> None:
    runtime = tmp_path / "runtime"
    scan_root = tmp_path / "scan"
    scan_root.mkdir()
    digest = _write_runtime(
        runtime,
        """
class StaticScanner:
    def scan_paths(self, roots, cancelled=None):
        yield {
            "path": str(roots[0]) + "/sample.exe",
            "sha256": "abc123",
            "assessment": {
                "score": 10,
                "level": "SAFE",
                "reasons": ["Harmless heuristic context."],
                "signals": [{"key": "fixture", "weight": 10, "reason": "Harmless heuristic context."}],
                "confidence": 0.35,
                "evidence_count": 1,
            },
        }
""".strip()
        + "\n",
    )
    _configure(monkeypatch, runtime, digest, scan_root)

    result = smart.SmartScanCoordinator(live.create_provider()).run_sync()
    assert result.state == smart.STATE_COMPLETED_CLEAN
    assert result.coverage == smart.COVERAGE_COMPLETE
    assert result.findings == ()


def test_historical_high_assessment_becomes_finding(tmp_path, monkeypatch) -> None:
    runtime = tmp_path / "runtime"
    scan_root = tmp_path / "scan"
    scan_root.mkdir()
    digest = _write_runtime(
        runtime,
        """
class StaticScanner:
    def scan_paths(self, roots, cancelled=None):
        yield {
            "path": str(roots[0]) + "/fixture.exe",
            "sha256": "feedbeef",
            "assessment": {
                "score": 90,
                "level": "HIGH",
                "reasons": ["Fixture suspicious evidence."],
                "signals": [{"key": "fixture_high", "weight": 90, "reason": "Fixture suspicious evidence."}],
                "confidence": 0.9,
                "evidence_count": 2,
            },
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
    assert finding.severity == smart.SEVERITY_HIGH
    assert finding.indicator == "feedbeef"
    assert "Fixture suspicious evidence" in finding.reason


def test_unknown_assessment_level_still_fails_closed(tmp_path, monkeypatch) -> None:
    runtime = tmp_path / "runtime"
    scan_root = tmp_path / "scan"
    scan_root.mkdir()
    digest = _write_runtime(
        runtime,
        """
class StaticScanner:
    def scan_paths(self, roots, cancelled=None):
        yield {
            "path": str(roots[0]) + "/unknown.exe",
            "assessment": {"score": 42, "level": "NEW_UNMAPPED_LEVEL"},
        }
""".strip()
        + "\n",
    )
    _configure(monkeypatch, runtime, digest, scan_root)

    result = smart.SmartScanCoordinator(live.create_provider()).run_sync()
    assert result.state == smart.STATE_INCOMPLETE
    assert result.coverage == smart.COVERAGE_INCOMPLETE
    assert result.state != smart.STATE_COMPLETED_CLEAN


def test_unicode_filename_cannot_crash_child_json_transport(tmp_path, monkeypatch) -> None:
    runtime = tmp_path / "runtime"
    scan_root = tmp_path / "scan"
    scan_root.mkdir()
    digest = _write_runtime(
        runtime,
        """
class StaticScanner:
    def scan_paths(self, roots, cancelled=None):
        yield {
            "path": str(roots[0]) + "/bad\\u201bname.exe",
            "assessment": {"score": 0, "level": "SAFE", "reasons": [], "signals": []},
        }
""".strip()
        + "\n",
    )
    _configure(monkeypatch, runtime, digest, scan_root)

    provider = live.create_provider()
    assert provider._binding is not None
    child_env = live._runtime_env(provider._binding)
    assert child_env["PYTHONIOENCODING"] == "ascii:backslashreplace"
    assert child_env["PYTHONUTF8"] == "1"

    result = smart.SmartScanCoordinator(provider).run_sync()
    assert result.state == smart.STATE_COMPLETED_CLEAN
    assert result.coverage == smart.COVERAGE_COMPLETE

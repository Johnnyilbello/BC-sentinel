from __future__ import annotations

import hashlib
import time
from pathlib import Path

import pytest

from sentinel import rescue_hostile_scenarios as b51


def make_windows(root: Path) -> Path:
    cfg = root / "Windows" / "System32" / "config"
    cfg.mkdir(parents=True)
    (cfg / "SYSTEM").write_bytes(b"SYSTEM")
    (cfg / "SOFTWARE").write_bytes(b"SOFTWARE")
    (root / "Windows" / "System32" / "ntoskrnl.exe").write_bytes(b"MZ KERNEL")
    return root


def tree_hashes(root: Path) -> dict[str, str]:
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in root.rglob("*") if p.is_file()}


def test_clean_target_is_healthy(tmp_path: Path) -> None:
    root = make_windows(tmp_path / "offline")
    before = tree_hashes(root)
    result = b51.assess_target(root)
    assert result["state"] == b51.STATE_HEALTHY
    assert result["target_contract_valid"] is True
    assert result["critical_missing"] == []
    assert result["safety"]["write_attempted"] is False
    assert tree_hashes(root) == before


def test_missing_critical_file_is_damaged(tmp_path: Path) -> None:
    root = make_windows(tmp_path / "offline")
    (root / "Windows" / "System32" / "config" / "SOFTWARE").unlink()
    result = b51.assess_target(root)
    assert result["state"] == b51.STATE_DAMAGED
    assert "Windows/System32/config/SOFTWARE" in result["critical_missing"]


def test_persistence_active_content_requires_review(tmp_path: Path) -> None:
    root = make_windows(tmp_path / "offline")
    startup = root / "ProgramData" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "StartUp"
    startup.mkdir(parents=True)
    (startup / "persist.ps1").write_text("Write-Output harmless", encoding="utf-8")
    result = b51.assess_target(root)
    assert result["state"] == b51.STATE_REVIEW
    assert result["counters"]["persistence_review_items"] == 1
    assert any("persistence_active_content_review" in row["reasons"] for row in result["records"])


def test_user_startup_double_extension_requires_review(tmp_path: Path) -> None:
    root = make_windows(tmp_path / "offline")
    startup = root / "Users" / "Alice" / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
    startup.mkdir(parents=True)
    (startup / "invoice.pdf.exe").write_bytes(b"MZ")
    result = b51.assess_target(root)
    assert result["state"] == b51.STATE_REVIEW
    assert result["counters"]["persistence_review_items"] == 1


def test_permission_error_is_access_restricted(tmp_path: Path) -> None:
    root = make_windows(tmp_path / "offline")
    target = root / "Windows" / "System32" / "config" / "SYSTEM"
    def reader(path: Path, _: int) -> bytes:
        if path == target:
            raise PermissionError("blocked")
        return path.read_bytes()
    result = b51.assess_target(root, reader=reader)
    assert result["state"] == b51.STATE_ACCESS_RESTRICTED
    assert result["counters"]["access_denied"] == 1


def test_os_error_is_io_degraded(tmp_path: Path) -> None:
    root = make_windows(tmp_path / "offline")
    target = root / "Windows" / "System32" / "config" / "SYSTEM"
    def reader(path: Path, _: int) -> bytes:
        if path == target:
            raise OSError(5, "io")
        return path.read_bytes()
    result = b51.assess_target(root, reader=reader)
    assert result["state"] == b51.STATE_IO_DEGRADED
    assert result["counters"]["io_errors"] == 1


def test_slow_read_is_io_degraded(tmp_path: Path) -> None:
    root = make_windows(tmp_path / "offline")
    def reader(path: Path, _: int) -> bytes:
        time.sleep(0.01)
        return path.read_bytes()
    result = b51.assess_target(root, limits=b51.AssessmentLimits(slow_read_ms=1.0), reader=reader)
    assert result["state"] == b51.STATE_IO_DEGRADED
    assert result["counters"]["slow_reads"] >= 1


def test_file_budget_truncates_without_write(tmp_path: Path) -> None:
    root = make_windows(tmp_path / "offline")
    tasks = root / "Windows" / "System32" / "Tasks"
    tasks.mkdir(parents=True)
    for i in range(10):
        (tasks / f"task{i}.cmd").write_text("echo x", encoding="utf-8")
    before = tree_hashes(root)
    result = b51.assess_target(root, limits=b51.AssessmentLimits(max_files=3))
    assert result["truncated_by_files"] is True
    assert result["counters"]["probed"] == 3
    assert tree_hashes(root) == before


def test_byte_budget_truncates(tmp_path: Path) -> None:
    root = make_windows(tmp_path / "offline")
    result = b51.assess_target(root, limits=b51.AssessmentLimits(max_total_bytes=1, sample_bytes=1))
    assert result["truncated_by_bytes"] is True


def test_output_inside_target_refused(tmp_path: Path) -> None:
    root = make_windows(tmp_path / "offline")
    result = b51.assess_target(root)
    with pytest.raises(ValueError, match="outside target"):
        b51.write_assessment(result, root / "report.json", root)


def test_output_outside_target_roundtrip(tmp_path: Path) -> None:
    root = make_windows(tmp_path / "offline")
    result = b51.assess_target(root)
    out = b51.write_assessment(result, tmp_path / "evidence" / "report.json", root)
    assert out.is_file()
    assert result["assessment_sha256"] in out.read_text(encoding="utf-8")


def test_symlink_root_refused_when_supported(tmp_path: Path) -> None:
    root = make_windows(tmp_path / "offline")
    link = tmp_path / "link"
    try:
        link.symlink_to(root, target_is_directory=True)
    except OSError:
        pytest.skip("symlink unavailable")
    with pytest.raises(ValueError):
        b51.assess_target(link)


def test_limits_are_bounded() -> None:
    with pytest.raises(ValueError):
        b51.AssessmentLimits(max_files=0).validate()
    with pytest.raises(ValueError):
        b51.AssessmentLimits(max_elapsed_sec=99).validate()


def test_assessment_hash_is_stable_for_same_core(tmp_path: Path) -> None:
    root = make_windows(tmp_path / "offline")
    a = b51.assess_target(root)
    b = b51.assess_target(root)
    assert a["assessment_sha256"] == b["assessment_sha256"]

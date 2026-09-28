from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

from sentinel import rescue_offline_scanner as scanner


def offline_tree(tmp_path: Path) -> Path:
    root = tmp_path / "offline"
    folder = root / "Windows" / "System32" / "config"
    folder.mkdir(parents=True)
    (folder / "SYSTEM").write_bytes(b"fixture-system")
    (root / "Windows" / "System32" / "ntoskrnl.exe").write_bytes(b"MZ-inert-synthetic")
    for index in range(3):
        (root / "Windows" / "System32" / f"fixture-{index}.exe").write_bytes(b"MZ-inert-synthetic")
    return root


@pytest.mark.parametrize("field,bad", [
    ("max_total_bytes", True), ("max_total_bytes", -1),
    ("max_seconds", "600"), ("max_seconds", 0),
    ("max_rss_bytes", 1.5), ("max_rss_bytes", 0),
])
def test_resource_limits_reject_type_confusion(field, bad):
    with pytest.raises(ValueError, match="bounded limit"):
        scanner.OfflineScanLimits(**{field: bad}).validate()


def test_cancel_preserves_target_and_persists_incomplete_report(tmp_path):
    root = offline_tree(tmp_path)
    original = {p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()}
    progress = []
    report = scanner.scan_offline_windows(
        root, tmp_path / "report", cancel_check=lambda: bool(progress),
        progress_callback=progress.append,
        require_separate_volume=False,
    )
    assert report["state"] == "incomplete"
    assert "cancelled" in report["summary"]["incomplete_reasons"]
    assert report["clean_claimed"] is False
    assert len(report["findings"]) < len(original)
    assert json.loads((tmp_path / "report" / "rr3-offline-scan.json").read_text())["state"] == "incomplete"
    assert {p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()} == original


def test_total_byte_budget_is_visible_as_incomplete(tmp_path):
    root = offline_tree(tmp_path)
    report = scanner.scan_offline_windows(
        root, tmp_path / "report",
        limits=scanner.OfflineScanLimits(max_total_bytes=20),
        require_separate_volume=False,
    )
    assert report["state"] == "incomplete"
    assert "total_byte_limit" in report["summary"]["incomplete_reasons"]
    assert any(row["verdict"] == "not_scanned" for row in report["findings"])


def test_output_inside_target_is_rejected_without_writes(tmp_path):
    root = offline_tree(tmp_path)
    with pytest.raises(ValueError, match="outside the offline target"):
        scanner.scan_offline_windows(root, root / "report", require_separate_volume=False)
    assert not (root / "report").exists()


def test_memory_budget_fails_closed(tmp_path):
    root = offline_tree(tmp_path)
    report = scanner.scan_offline_windows(
        root, tmp_path / "report", limits=scanner.OfflineScanLimits(max_rss_bytes=1)
    , require_separate_volume=False)
    assert report["state"] == "incomplete"
    assert "memory_limit" in report["summary"]["incomplete_reasons"]
    assert report["clean_claimed"] is False


def test_time_budget_fails_closed(tmp_path, monkeypatch):
    root = offline_tree(tmp_path)
    original = scanner._iter_candidate_files

    def delayed(*args, **kwargs):
        time.sleep(1.05)
        yield from original(*args, **kwargs)

    monkeypatch.setattr(scanner, "_iter_candidate_files", delayed)
    report = scanner.scan_offline_windows(
        root, tmp_path / "report", limits=scanner.OfflineScanLimits(max_seconds=1)
    , require_separate_volume=False)
    assert report["state"] == "incomplete"
    assert "time_limit" in report["summary"]["incomplete_reasons"]


def test_cli_rejects_same_volume_without_writes(tmp_path):
    root = offline_tree(tmp_path)
    command = [sys.executable, "-m", "sentinel.rescue_offline_scanner", "--root", str(root)]
    complete = subprocess.run(command + ["--output", str(tmp_path / "complete")], capture_output=True, text=True)
    assert complete.returncode == 2, complete.stderr
    assert "outside the examined volume" in json.loads(complete.stdout)["reason"]
    assert not (tmp_path / "complete").exists()


def test_packaged_entrypoint_offline_arguments_on_source(tmp_path):
    root = offline_tree(tmp_path)
    repo = Path(__file__).resolve().parents[1]
    env = {**os.environ, "PYTHONPATH": str(repo)}
    run = subprocess.run(
        [sys.executable, str(repo / "packaging" / "beta13_desktop_entry.py"),
         "--offline-root", str(root), "--offline-output", str(tmp_path / "out")],
        env=env, capture_output=True, text=True,
    )
    assert run.returncode == 2, run.stderr
    assert not (tmp_path / "out").exists()


def test_desktop_dialog_reports_scan_without_claiming_protection(tmp_path, monkeypatch):
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication
    from sentinel.offline_scan_dialog import OfflineScanDialog

    # Simulated separate volume: real same-volume rejection is tested above.
    monkeypatch.setattr(scanner, "validate_report_volume", lambda root, output: None)
    app = QApplication.instance() or QApplication([])
    root = offline_tree(tmp_path)
    dialog = OfflineScanDialog()
    dialog.root_edit.setText(str(root))
    dialog.output_edit.setText(str(tmp_path / "report"))
    dialog.start_button.click()
    deadline = time.monotonic() + 15
    while dialog._thread is not None and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.01)
    app.processEvents()
    assert dialog._thread is None
    assert "Scansione completata" in dialog.status.text()
    assert "Nessuna conclusione di file pulito" in dialog.findings.toPlainText()
    assert "protezione attiva" in dialog.layout().itemAt(0).widget().text()
    dialog.close()


def test_default_api_rejects_same_volume(tmp_path):
    root = offline_tree(tmp_path)
    with pytest.raises(ValueError, match="examined volume"):
        scanner.scan_offline_windows(root, tmp_path / "out", require_separate_volume=True)
    assert not (tmp_path / "out").exists()


def test_hash_rechecks_byte_limit_during_read(tmp_path):
    path = tmp_path / "growing.bin"
    path.write_bytes(b"x" * 32)
    token = scanner._READ_LIMIT.set(16)
    try:
        with pytest.raises(OSError, match="bounded read"):
            scanner._sha256_file(path)
    finally:
        scanner._READ_LIMIT.reset(token)


def test_oversized_file_is_incomplete(tmp_path):
    root = offline_tree(tmp_path)
    report = scanner.scan_offline_windows(root, tmp_path / "out",
        limits=scanner.OfflineScanLimits(max_file_bytes=1), require_separate_volume=False)
    assert report["state"] == "incomplete"
    assert "file_too_large" in report["summary"]["incomplete_reasons"]


def test_unc_rejected_before_filesystem_access():
    with pytest.raises(ValueError, match="network/device"):
        scanner.validate_offline_windows_root(Path(r"\\example.invalid\share"))


def test_yara_snapshot_must_match_initial_hash(tmp_path):
    import hashlib
    path = tmp_path / "fixture.exe"
    path.write_bytes(b"changed harmless data")
    class Rules:
        def match(self, **kwargs):
            pytest.fail("mismatched snapshot must not reach YARA")
    result = scanner._yara_matches(Rules(), path,
        expected_sha256=hashlib.sha256(b"original harmless data").hexdigest())
    assert result == ("__YARA_ERROR__:ArtifactChangedError",)


def test_yara_include_cannot_read_external_rule(tmp_path):
    source = tmp_path / "include.yar"
    source.write_text('include "external.yar"')
    with pytest.raises(ValueError, match="compile failed"):
        scanner._compile_yara(source)

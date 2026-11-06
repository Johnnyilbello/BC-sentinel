import hashlib
import json
from pathlib import Path

import pytest
from PySide6.QtCore import QEventLoop, QTimer
from PySide6.QtWidgets import QApplication

from sentinel.bc_scan import EICAR_SHA256, scan_folder
from sentinel.bc_scan_ui import BCScanPage


def test_eicar_digest_matches_standard_in_memory():
    # Build only in memory; do not write a file that other antivirus may quarantine.
    parts = [b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$", b"EICAR-STANDARD-", b"ANTIVIRUS-TEST-FILE!$H+H*"]
    assert hashlib.sha256(b"".join(parts)).hexdigest() == EICAR_SHA256


def catalog(tmp_path, payload):
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps({"schema": "bc-sentinel-offline-intel-v1", "approved": True,
        "sha256": [{"value": hashlib.sha256(payload).hexdigest(), "name": "fixture", "source": "test"}]}))
    return path


def test_hash_match_and_no_mutation(tmp_path):
    folder = tmp_path / "scan"
    folder.mkdir()
    sample = folder / "sample.txt"
    sample.write_bytes(b"harmless fixture")
    result = scan_folder(folder, catalog_path=catalog(tmp_path, b"harmless fixture"))
    assert result["files"] == 1 and result["skipped"] == 0
    assert result["findings"][0]["path"] == str(sample)
    assert sample.read_bytes() == b"harmless fixture"


def test_cancel_and_size_limit_are_disclosed(tmp_path, monkeypatch):
    import sentinel.bc_scan as module
    (tmp_path / "large").write_bytes(b"12345")
    monkeypatch.setattr(module, "MAX_BYTES", 4)
    assert scan_folder(tmp_path)["skipped"] == 1
    assert scan_folder(tmp_path, cancelled=lambda: True)["cancelled"]


def test_invalid_catalog_fails_closed(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('{}')
    with pytest.raises(ValueError):
        scan_folder(tmp_path, catalog_path=bad)


def test_ui_worker_scans_and_reenables_controls(tmp_path):
    app = QApplication.instance() or QApplication([])
    folder = tmp_path / "scan"
    folder.mkdir()
    (folder / "benign.txt").write_text("benign")
    page = BCScanPage()
    loop = QEventLoop()
    page.start_scan(str(folder))
    page.worker.finished.connect(loop.quit)
    QTimer.singleShot(10000, loop.quit)
    loop.exec()
    app.processEvents()
    assert page.worker is None
    assert page.last_result['files'] == 1
    assert page.start_button.isEnabled()
    assert "non garantisce" in page.report.toPlainText()
    page.close()

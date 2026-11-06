import time

from PySide6.QtWidgets import QApplication, QFileDialog, QPushButton

from sentinel import offline_scan_dialog as module


def test_all_offline_selectors_and_start_cancel_are_connected(tmp_path, monkeypatch):
    app = QApplication.instance() or QApplication([])
    dialog = module.OfflineScanDialog()
    monkeypatch.setattr(QFileDialog, "getExistingDirectory", lambda *a: str(tmp_path))
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *a: (str(tmp_path / "fixture.json"), ""))
    buttons = dialog.findChildren(QPushButton)
    for button in buttons[:4]:
        button.click()
    assert dialog.root_edit.text() == str(tmp_path)
    assert dialog.output_edit.text() == str(tmp_path)
    assert dialog.intel_edit.text().endswith("fixture.json")
    assert dialog.yara_edit.text().endswith("fixture.json")
    def scan(root, output, **kwargs):
        deadline = time.monotonic() + 5
        while not kwargs["cancel_check"]() and time.monotonic() < deadline:
            time.sleep(0.01)
        return {"findings": [], "state": "incomplete", "output_dir": str(output),
                "summary": {"incomplete_reasons": ["cancelled"]}}
    monkeypatch.setattr(module, "scan_offline_windows", scan)
    try:
        dialog.start_button.click()
        assert dialog.cancel_button.isEnabled()
        dialog.cancel_button.click()
        deadline = time.monotonic() + 5
        while dialog._thread is not None and time.monotonic() < deadline:
            app.processEvents()
            time.sleep(0.01)
        assert dialog._thread is None
        assert dialog.start_button.isEnabled()
        assert not dialog.cancel_button.isEnabled()
        assert "incompleta" in dialog.status.text()
    finally:
        dialog.close()

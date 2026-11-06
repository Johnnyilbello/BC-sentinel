from hashlib import sha256
import os

import pytest

from sentinel.bc_quarantine import BCQuarantine


pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows DPAPI and file handles required")


@pytest.fixture
def entry(tmp_path, monkeypatch):
    tmp_path = tmp_path.resolve()
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "appdata"))
    profile = tmp_path / "profile"
    docs = profile / "Documents"
    docs.mkdir(parents=True)
    target = docs / "fixture.txt"
    payload = b"BC Sentinel harmless vault fixture"
    target.write_bytes(payload)
    return BCQuarantine(tmp_path / "vault", user_profile=profile), target, payload


def test_isolation_encrypts_and_recovery_refuses_existing_destination(entry):
    vault, target, payload = entry
    digest = sha256(payload).hexdigest()
    result = vault.isolate(target, digest)
    assert not target.exists()
    assert payload not in next(vault.root.glob("*.bcq")).read_bytes()

    reopened = BCQuarantine(vault.root, user_profile=vault.user_profile)
    assert reopened.entries() == [result]
    target.write_bytes(b"existing document")
    with pytest.raises(FileExistsError):
        reopened.restore(result.token)
    assert target.read_bytes() == b"existing document"
    assert reopened.entries() == [result]

    target.unlink()
    reopened.restore(result.token)
    assert target.read_bytes() == payload
    assert not reopened.entries()


def test_hash_drift_and_alternate_stream_leave_original_intact(entry):
    vault, target, payload = entry
    with pytest.raises(ValueError, match="cambiato"):
        vault.isolate(target, "0" * 64)
    assert target.read_bytes() == payload and not vault.entries()
    stream = str(target) + ":Zone.Identifier"
    with open(stream, "wb") as handle:
        handle.write(b"[ZoneTransfer]\r\nZoneId=3\r\n")
    with pytest.raises(ValueError, match="flussi NTFS"):
        vault.isolate(target, sha256(payload).hexdigest())
    assert target.read_bytes() == payload and not vault.entries()
    with open(stream, "rb") as handle:
        assert b"ZoneId=3" in handle.read()


def test_ui_requires_confirmation_and_round_trips(entry, monkeypatch):
    from PySide6.QtWidgets import QApplication, QMessageBox
    from sentinel.bc_quarantine_ui import BCVaultPane

    app = QApplication.instance() or QApplication([])
    vault, target, payload = entry
    pane = BCVaultPane(vault.root)
    pane.vault = vault
    pane.add_finding({"isolate_path": str(target), "sha256": sha256(payload).hexdigest()})
    monkeypatch.setattr(QMessageBox, "question", lambda *_: QMessageBox.StandardButton.No)
    pane.isolate_button.click()
    assert target.exists() and not vault.entries()
    monkeypatch.setattr(QMessageBox, "question", lambda *_: QMessageBox.StandardButton.Yes)
    pane.isolate_button.click()
    assert not target.exists() and pane.restore_button.isEnabled()
    pane.restore_button.click()
    assert target.read_bytes() == payload and not pane.restore_button.isEnabled()
    pane.close()

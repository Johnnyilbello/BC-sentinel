from __future__ import annotations

from pathlib import Path

import pytest
pytest.importorskip("cryptography")

from sentinel import quarantine as qmod
from sentinel.database import Database


def _manager(tmp_path, monkeypatch):
    qdir = tmp_path / "q"
    qdir.mkdir()
    monkeypatch.setattr(qmod, "QUARANTINE_DIR", qdir)
    monkeypatch.setattr(qmod, "KEY_PATH", tmp_path / "key")
    return qmod.QuarantineManager(Database(tmp_path / "db.sqlite")), qdir


def test_restore_rejects_tampered_stored_path_outside_quarantine(tmp_path, monkeypatch):
    q, _ = _manager(tmp_path, monkeypatch)
    src = tmp_path / "sample.bin"
    src.write_bytes(b"harmless")
    item = q.quarantine(src, 90, "test")
    outside = tmp_path / "outside.bcsq"
    outside.write_bytes(b"not quarantine")
    q.db.execute("UPDATE quarantine SET stored_path=? WHERE id=?", (str(outside), item))
    with pytest.raises(ValueError, match="outside"):
        q.restore(item)


def test_restore_never_overwrites_existing_destination(tmp_path, monkeypatch):
    q, _ = _manager(tmp_path, monkeypatch)
    src = tmp_path / "sample.bin"
    src.write_bytes(b"payload")
    item = q.quarantine(src, 90, "test")
    destination = tmp_path / "existing.bin"
    destination.write_bytes(b"keep-me")
    with pytest.raises(FileExistsError):
        q.restore(item, destination)
    assert destination.read_bytes() == b"keep-me"


def test_quarantine_rejects_symlink_source(tmp_path, monkeypatch):
    q, _ = _manager(tmp_path, monkeypatch)
    target = tmp_path / "target.bin"
    target.write_bytes(b"payload")
    link = tmp_path / "link.bin"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlink unavailable")
    with pytest.raises(ValueError, match="symlink|reparse"):
        q.quarantine(link, 90, "test")

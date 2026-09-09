import pytest
pytest.importorskip("cryptography")
from sentinel import quarantine as qmod
from sentinel.database import Database

def test_quarantine_restore(tmp_path, monkeypatch):
    qdir=tmp_path/"q"
    qdir.mkdir()
    monkeypatch.setattr(qmod,"QUARANTINE_DIR",qdir)
    monkeypatch.setattr(qmod,"KEY_PATH",tmp_path/"key")
    db=Database(tmp_path/"db.sqlite")
    q=qmod.QuarantineManager(db)

    src=tmp_path/"suspect.bin"
    src.write_bytes(b"harmless test payload")
    item=q.quarantine(src,90,"test")
    assert not src.exists()
    assert len(q.list_items()) == 1

    restored=q.restore(item)
    assert restored.read_bytes()==b"harmless test payload"
    assert len(q.list_items()) == 0
    assert len(q.list_restored()) == 1

import pytest
pytest.importorskip("cryptography")
from sentinel import quarantine as qmod
from sentinel.database import Database

def make_manager(tmp_path, monkeypatch):
    qdir=tmp_path/"q"
    qdir.mkdir()
    monkeypatch.setattr(qmod,"QUARANTINE_DIR",qdir)
    monkeypatch.setattr(qmod,"KEY_PATH",tmp_path/"key")
    db=Database(tmp_path/"db.sqlite")
    return qmod.QuarantineManager(db), db

def test_quarantine_restore_syncs_detection(tmp_path, monkeypatch):
    q, db = make_manager(tmp_path, monkeypatch)

    src=tmp_path/"suspect.bin"
    src.write_bytes(b"harmless test payload")

    sha="dummy"
    # Use real hash from quarantine record by first adding after quarantine.
    item=q.quarantine(src,90,"test")
    row=db.execute("SELECT sha256 FROM quarantine WHERE id=?", (item,))[0]
    sha=row["sha256"]

    db.add_detection(str(tmp_path/"suspect.bin"), sha, 90, "CRITICAL", '["test"]', "quarantined", dedupe_minutes=0)
    assert db.latest_detection_action(sha) == "quarantined"

    restored=q.restore(item)
    assert restored.read_bytes()==b"harmless test payload"
    assert db.latest_detection_action(sha) == "restored"
    assert len(q.list_items()) == 0
    assert len(q.list_restored()) == 1

def test_quarantine_delete_syncs_detection(tmp_path, monkeypatch):
    q, db = make_manager(tmp_path, monkeypatch)

    src=tmp_path/"suspect2.bin"
    src.write_bytes(b"harmless payload 2")
    item=q.quarantine(src,95,"test")
    row=db.execute("SELECT sha256 FROM quarantine WHERE id=?", (item,))[0]
    sha=row["sha256"]

    db.add_detection(str(tmp_path/"suspect2.bin"), sha, 95, "CRITICAL", '["test"]', "quarantined", dedupe_minutes=0)
    q.delete_permanently(item)
    assert db.latest_detection_action(sha) == "deleted"

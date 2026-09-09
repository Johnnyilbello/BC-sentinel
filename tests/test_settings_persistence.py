from sentinel.database import Database


def test_setting_roundtrip(tmp_path):
    db = Database(tmp_path / "db.sqlite")
    assert db.get_setting("x") is None
    db.set_setting("x", "1")
    assert db.get_setting("x") == "1"
    db.set_setting("x", "2")
    assert db.get_setting("x") == "2"


def test_allowlist_list_remove(tmp_path):
    db = Database(tmp_path / "db.sqlite")
    db.add_allowlist("file", "C:/safe.exe")
    rows = db.list_allowlist()
    assert len(rows) == 1
    db.remove_allowlist(rows[0]["id"])
    assert db.list_allowlist() == []

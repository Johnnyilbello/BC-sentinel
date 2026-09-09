from sentinel.database import Database

def test_scan_history_persists_last_completed_scan(tmp_path):
    db = Database(tmp_path/"db.sqlite")
    scan_id = db.start_scan_record("quick")
    db.finish_scan_record(scan_id, 123, 2, False)

    row = db.get_last_completed_scan()
    assert row is not None
    assert row["kind"] == "quick"
    assert row["files_scanned"] == 123
    assert row["detections"] == 2
    assert row["cancelled"] == 0

def test_scan_history_cancelled_is_persisted(tmp_path):
    db = Database(tmp_path/"db.sqlite")
    scan_id = db.start_scan_record("full")
    db.finish_scan_record(scan_id, 50, 0, True)

    row = db.get_last_completed_scan()
    assert row["cancelled"] == 1

def test_settings_helpers(tmp_path):
    db = Database(tmp_path/"db.sqlite")
    assert db.get_setting("x") is None
    db.set_setting("x", "1")
    assert db.get_setting("x") == "1"

from sentinel.database import Database

def test_current_history_returns_only_newest_row_per_hash(tmp_path):
    db = Database(tmp_path/"db.sqlite")

    db.execute(
        "INSERT INTO detections(path,sha256,score,level,reasons_json,action) VALUES(?,?,?,?,?,?)",
        ("eicar.com","samehash",100,"CRITICAL","[]","quarantined")
    )
    db.execute(
        "INSERT INTO detections(path,sha256,score,level,reasons_json,action) VALUES(?,?,?,?,?,?)",
        ("eicar.com","samehash",100,"CRITICAL","[]","restored")
    )

    rows = db.current_detection_history()
    assert len(rows) == 1
    assert rows[0]["action"] == "restored"

def test_current_history_keeps_different_hashes(tmp_path):
    db = Database(tmp_path/"db.sqlite")

    db.execute(
        "INSERT INTO detections(path,sha256,score,level,reasons_json,action) VALUES(?,?,?,?,?,?)",
        ("a.exe","hash-a",90,"CRITICAL","[]","logged")
    )
    db.execute(
        "INSERT INTO detections(path,sha256,score,level,reasons_json,action) VALUES(?,?,?,?,?,?)",
        ("b.exe","hash-b",80,"HIGH","[]","quarantined")
    )

    rows = db.current_detection_history()
    assert len(rows) == 2

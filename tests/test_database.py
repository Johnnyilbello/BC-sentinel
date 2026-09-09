from sentinel.database import Database
import json

def test_allowlist(tmp_path):
    db=Database(tmp_path/"db.sqlite")
    f=tmp_path/"safe.exe"
    f.write_bytes(b"x")
    db.add_allowlist("file",str(f))
    assert db.is_allowlisted(str(f))

def test_safe_not_inserted_as_detection(tmp_path):
    db=Database(tmp_path/"db.sqlite")
    ok=db.add_detection("safe.bin","aaa",10,"SAFE","[]")
    assert not ok
    assert db.execute("SELECT * FROM detections") == []

def test_suspicious_detection_inserted_once(tmp_path):
    db=Database(tmp_path/"db.sqlite")
    assert db.add_detection("x.exe","abc",80,"HIGH",json.dumps(["x"]))
    assert not db.add_detection("x.exe","abc",80,"HIGH",json.dumps(["x"]))
    rows=db.execute("SELECT * FROM detections")
    assert len(rows) == 1

def test_cleanup_history(tmp_path):
    db=Database(tmp_path/"db.sqlite")
    db.execute(
        "INSERT INTO detections(path,sha256,score,level,reasons_json,action) VALUES(?,?,?,?,?,?)",
        ("safe.msi","s1",10,"SAFE","[]","logged")
    )
    db.execute(
        "INSERT INTO detections(path,sha256,score,level,reasons_json,action) VALUES(?,?,?,?,?,?)",
        ("eicar.com","e1",100,"CRITICAL","[]","logged")
    )
    db.execute(
        "INSERT INTO detections(path,sha256,score,level,reasons_json,action) VALUES(?,?,?,?,?,?)",
        ("eicar.com","e1",100,"CRITICAL","[]","quarantined")
    )
    db.execute(
        "INSERT INTO detections(path,sha256,score,level,reasons_json,action) VALUES(?,?,?,?,?,?)",
        (r"C:\Users\Me\Desktop\BC_Sentinel_v0_1_FIX3\test_scanner.py","legacy",100,"CRITICAL","[]","logged")
    )

    db.cleanup_detection_history()
    rows=db.execute("SELECT path,sha256,score FROM detections ORDER BY id")
    assert len(rows) == 1
    assert rows[0]["sha256"] == "e1"

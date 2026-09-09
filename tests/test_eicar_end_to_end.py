import pytest
pytest.importorskip("cryptography")
import sentinel.scanner as scanner_mod
from sentinel.scanner import StaticScanner
from sentinel.database import Database
from sentinel import quarantine as qmod

def test_simulated_eicar_detection_quarantine_restore_flow(tmp_path, monkeypatch):
    qdir=tmp_path/"q"; qdir.mkdir()
    monkeypatch.setattr(qmod,"QUARANTINE_DIR",qdir)
    monkeypatch.setattr(qmod,"KEY_PATH",tmp_path/"key")
    marker=b"BC-SENTINEL-HARMLESS-EICAR-E2E-SIMULATION"
    sample=tmp_path/"eicar-simulation.com"; sample.write_bytes(marker)
    monkeypatch.setattr(scanner_mod,"is_exact_eicar",lambda data: data.rstrip(b"\r\n") == marker)
    report=StaticScanner().scan_file(sample)
    assert report.assessment.score == 100
    assert report.assessment.level == "CRITICAL"
    db=Database(tmp_path/"db.sqlite")
    db.add_detection(report.path,report.sha256,report.assessment.score,report.assessment.level,'["EICAR simulation"]',"logged",dedupe_minutes=0)
    q=qmod.QuarantineManager(db)
    item_id=q.quarantine(sample,report.assessment.score,"Harmless EICAR simulation")
    db.update_detection_action(report.sha256,"quarantined")
    assert not sample.exists()
    restored=q.restore(item_id)
    assert restored.exists()
    assert restored.read_bytes() == marker
    assert db.latest_detection_action(report.sha256) == "restored"

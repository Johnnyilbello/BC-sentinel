from pathlib import Path

from sentinel.core.events import SecurityEvent
from sentinel.correlation_engine import BehavioralCorrelationEngine
from sentinel.database import Database
from sentinel.network_intelligence import NetworkReputationEngine
from sentinel.network_monitor import NetworkMonitor
from sentinel.reputation import AuthenticodeDetails, ReputationEngine


def network_event(process="sample.exe", path=r"C:\\Tools\\sample.exe", remote="8.8.8.8", port=443, **data):
    payload={"remote_addr":remote,"remote_port":port,"protocol":"TCP","state":"ESTABLISHED"}
    payload.update(data)
    return SecurityEvent(
        category="network", action="connect", source="test", pid=10,
        process_name=process, process_path=path, path=f"{remote}:{port}", data=payload,
    )


def test_private_endpoint_is_context_not_threat(tmp_path):
    engine=NetworkReputationEngine(Database(tmp_path/"db.sqlite"))
    result=engine.assess_event(network_event(remote="192.168.1.20"))
    assert result.address_class=="private"
    assert result.score_delta==0


def test_known_malicious_endpoint_has_strong_local_reputation(tmp_path):
    db=Database(tmp_path/"db.sqlite")
    db.upsert_endpoint_reputation(indicator="8.8.8.8",kind="ip",status="malicious",source="test",confidence=.99)
    result=NetworkReputationEngine(db).assess_event(network_event())
    assert result.status=="malicious"
    assert result.score_delta>=60
    assert any("malevol" in x.lower() for x in result.reasons)


def test_script_interpreter_global_connection_is_contextual_risk(tmp_path):
    engine=NetworkReputationEngine(Database(tmp_path/"db.sqlite"))
    result=engine.assess_event(network_event(process="powershell.exe",path=r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"))
    assert result.score_delta>=8
    assert any("interprete" in x.lower() for x in result.reasons)


def test_browser_https_connection_is_not_suspicious_by_itself(tmp_path):
    engine=NetworkReputationEngine(Database(tmp_path/"db.sqlite"))
    result=engine.assess_event(network_event(process="chrome.exe",path=r"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"))
    assert result.score_delta==0


def test_endpoint_observation_tracks_connection_and_process_prevalence(tmp_path):
    db=Database(tmp_path/"db.sqlite")
    engine=NetworkReputationEngine(db)
    engine.assess_event(network_event(process="a.exe",path=r"C:\\a.exe"))
    second=engine.assess_event(network_event(process="b.exe",path=r"C:\\b.exe"))
    assert second.connection_count==2
    assert second.process_count==2
    assert second.first_seen


def test_optional_provider_receives_only_hashed_indicator(tmp_path):
    class Provider:
        def __init__(self): self.calls=[]
        def lookup_indicator_hash(self,kind,indicator_sha256):
            self.calls.append((kind,indicator_sha256))
            return {"status":"suspicious","source":"unit","confidence":.8}
    provider=Provider()
    engine=NetworkReputationEngine(Database(tmp_path/"db.sqlite"),provider=provider)
    result=engine.assess_endpoint("8.8.4.4",process_key="x")
    assert result.status=="suspicious"
    assert provider.calls and provider.calls[0][0]=="ip"
    assert provider.calls[0][1] != "8.8.4.4"
    assert len(provider.calls[0][1])==64


def test_network_monitor_event_includes_process_identity_and_endpoint_context(tmp_path):
    engine=NetworkReputationEngine(Database(tmp_path/"db.sqlite"))
    mon=NetworkMonitor(intelligence=engine)
    event=mon._build_event(
        pid=12,local_text="10.0.0.2:50000",remote_host="8.8.8.8",remote_port=443,
        remote_text="8.8.8.8:443",protocol="TCP",state="ESTABLISHED",
        context={"process_name":"x.exe","process_path":r"C:\\x.exe","ppid":1,"create_time":1.2,
                 "cmdline":"x.exe","process_sha256":"a"*64,"signature_status":"Valid","signer":"CN=Test"},
    )
    assert event.data["process_sha256"]=="a"*64
    assert event.data["signer"]=="CN=Test"
    assert event.data["endpoint_class"]=="global"


def test_reputation_tracks_first_seen_and_local_path_prevalence(tmp_path):
    db=Database(tmp_path/"db.sqlite")
    engine=ReputationEngine(db)
    digest="b"*64
    last=None
    for i in range(5):
        p=tmp_path/f"copy{i}.bin"
        p.write_bytes(b"same")
        last=engine.assess_file(p,digest)
    assert last is not None
    assert last.path_count==5
    assert last.prevalence=="common"
    assert last.first_seen


def test_certificate_context_is_cached_with_file_reputation(tmp_path,monkeypatch):
    db=Database(tmp_path/"db.sqlite")
    p=tmp_path/"signed.exe"; p.write_bytes(b"MZ test")
    engine=ReputationEngine(db)
    calls={"n":0}
    def details(path):
        calls["n"]+=1
        return AuthenticodeDetails(status="Valid",publisher="CN=Vendor",issuer="CN=CA",thumbprint="ABC",valid_from="2026-01-01",valid_to="2027-01-01",timestamp_signer="CN=TSA")
    monkeypatch.setattr(engine,"_authenticode_details",details)
    first=engine.assess_file(p,"c"*64,force_signature=True)
    second=engine.assess_file(p,"c"*64,force_signature=True)
    assert calls["n"]==1
    assert first.issuer==second.issuer=="CN=CA"
    assert second.cached


def test_new_unsigned_download_gets_small_context_not_detection(tmp_path,monkeypatch):
    downloads=tmp_path/"Downloads"; downloads.mkdir()
    p=downloads/"new.exe"; p.write_bytes(b"MZ test")
    engine=ReputationEngine(Database(tmp_path/"db.sqlite"))
    monkeypatch.setattr(engine,"_authenticode",lambda path:("NotSigned",""))
    result=engine.assess_file(p,"d"*64,force_signature=True)
    assert 4 <= result.score_delta <= 12
    assert any("nuovo" in x.lower() for x in result.reasons)


def test_browser_repeated_endpoint_is_suppressed_in_behavioral_correlation():
    engine=BehavioralCorrelationEngine(window_seconds=60)
    last=None
    for i in range(6):
        last=engine.assess(SecurityEvent(category="network",action="connect",source="test",pid=9,process_name="chrome.exe",process_path=r"C:\\chrome.exe",path="8.8.8.8:443",data={"remote_addr":"8.8.8.8","remote_port":443},ts=100+i),[])
    assert last is not None
    assert not any("ripetitive" in x.lower() for x in last.reasons)


def test_network_database_persists_reputation_context(tmp_path):
    db=Database(tmp_path/"db.sqlite")
    event=network_event(endpoint_status="suspicious",endpoint_confidence=.7,endpoint_first_seen="2026-09-02",process_sha256="e"*64,signature_status="NotSigned",signer="")
    event.score=25
    db.record_network_event(event)
    row=db.execute("SELECT * FROM network_events ORDER BY id DESC LIMIT 1")[0]
    assert row["endpoint_status"]=="suspicious"
    assert row["process_sha256"]=="e"*64
    assert float(row["endpoint_confidence"])==.7


def test_telemetry_batch_persists_network_and_security_in_one_call(tmp_path):
    db=Database(tmp_path/"db.sqlite")
    event=network_event(endpoint_status="trusted",endpoint_confidence=.9,endpoint_first_seen="2026-09-02")
    n=db.record_telemetry_batch([event],[{
        "category":"behavioral_correlation","source_event_category":"network",
        "source_event_action":"connect","pid":10,"process_name":"sample.exe",
        "score_delta":8,"confidence":.6,"chain":"sample.exe","reasons":["test"],"data":{},
    }])
    assert n==1
    assert db.execute("SELECT COUNT(*) c FROM security_events")[0]["c"]==1
    assert db.execute("SELECT COUNT(*) c FROM network_events")[0]["c"]==1
    assert db.execute("SELECT COUNT(*) c FROM correlation_events")[0]["c"]==1


def test_v040_schema_migrates_network_reputation_columns(tmp_path):
    import sqlite3
    path=tmp_path/"legacy.sqlite"
    con=sqlite3.connect(path)
    con.execute("CREATE TABLE network_events(id INTEGER PRIMARY KEY, ts TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, pid INTEGER, process_name TEXT, process_path TEXT, local_addr TEXT, remote_addr TEXT, remote_port INTEGER, protocol TEXT, state TEXT, score INTEGER DEFAULT 0, reasons_json TEXT DEFAULT '[]')")
    con.execute("CREATE TABLE file_reputation(path TEXT PRIMARY KEY, mtime_ns INTEGER NOT NULL, size INTEGER NOT NULL, sha256 TEXT NOT NULL, signature_status TEXT NOT NULL DEFAULT '', publisher TEXT NOT NULL DEFAULT '', local_trust TEXT NOT NULL DEFAULT 'unknown', checked_ts TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)")
    con.commit(); con.close()
    db=Database(path)
    network_cols={r[1] for r in db.execute("PRAGMA table_info(network_events)")}
    rep_cols={r[1] for r in db.execute("PRAGMA table_info(file_reputation)")}
    assert {"endpoint_status","process_sha256","signer"} <= network_cols
    assert {"issuer","thumbprint","timestamp_signer"} <= rep_cols


def test_telemetry_service_network_collection_is_opt_in_by_source_contract():
    source=Path("sentinel/telemetry_service_core.py").read_text(encoding="utf-8")
    assert 'op == "set_network_collection"' in source
    start=source[source.index("def start_backends"):source.index("def stop_backends")]
    assert "self.network.start()" not in start

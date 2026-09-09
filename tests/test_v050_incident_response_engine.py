from __future__ import annotations
import json
from sentinel.core.events import SecurityEvent
from sentinel.database import Database
from sentinel.incident_engine import IncidentCorrelationEngine
from sentinel.process_tree import ProcessTree
from sentinel.response_engine import ResponseEngine

class Corr:
    def __init__(self,delta=0,confidence=0.0,reasons=None,incident_id=""):
        self.score_delta=delta; self.confidence=confidence; self.reasons=reasons or []; self.incident_id=incident_id

def test_incident_converges_and_persists(tmp_path):
    db=Database(tmp_path/"db.sqlite"); tree=ProcessTree()
    path=r"C:\Users\Test\AppData\Local\Temp\powershell.exe"
    tree.observe(444,10,"powershell.exe",path,create_time=1234.5)
    engine=IncidentCorrelationEngine(db,tree,incident_window_seconds=60)
    event=SecurityEvent(category="process",action="start",source="process_monitor",score=32,pid=444,ppid=10,process_name="powershell.exe",process_path=path,reasons=["Encoded script execution"],data={"signature_status":"NotSigned"},ts=10)
    inc=engine.ingest(event,correlation=Corr(22,.88,["PowerShell encoded"],"BCI-TEST000001"),ancestry=tree.ancestry(444))
    assert inc is not None and inc.incident_id=="BCI-TEST000001" and inc.score>=50
    net=SecurityEvent(category="network",action="connect",source="network_monitor",score=20,pid=444,ppid=10,process_name="powershell.exe",process_path=path,reasons=["Endpoint watchlist"],data={"endpoint_status":"suspicious","remote_addr":"203.0.113.10","signature_status":"NotSigned"},ts=12)
    inc2=engine.ingest(net,correlation=Corr(12,.75,["Script network"],"BCI-TEST000001"),ancestry=tree.ancestry(444))
    assert inc2 is not None and inc2.score>=inc.score and "network" in inc2.categories
    row=db.get_incident(inc2.incident_id); assert row is not None
    assert len(json.loads(row["timeline_json"]))==2

def test_allowlist_suppresses_non_deterministic(tmp_path):
    db=Database(tmp_path/"db.sqlite"); path=r"C:\Tools\trusted.exe"; db.add_allowlist("file",path)
    inc=IncidentCorrelationEngine(db).ingest(SecurityEvent(category="process",action="start",source="heuristic",score=72,pid=800,process_name="trusted.exe",process_path=path,reasons=["Heuristic convergence"],ts=20),correlation=Corr(10,.7,["Context"]))
    assert inc is not None and inc.suppressed and inc.score<=49

def test_known_bad_endpoint_overrides_allowlist_suppression(tmp_path):
    db=Database(tmp_path/"db.sqlite"); path=r"C:\Tools\trusted.exe"; db.add_allowlist("file",path)
    inc=IncidentCorrelationEngine(db).ingest(SecurityEvent(category="network",action="connect",source="network_monitor",score=60,pid=801,process_name="trusted.exe",process_path=path,reasons=["Endpoint malevolo"],data={"endpoint_status":"malicious","remote_addr":"198.51.100.2"},ts=21))
    assert inc is not None and not inc.suppressed and inc.score>=70

class FakeQ:
    def __init__(self):self.calls=[]
    def quarantine(self,path,score,reason):self.calls.append((str(path),score,reason)); return "a"*32

def incident(**kw):
    d={"incident_id":"BCI-RESP01","pid":4321,"process_name":"sample.exe","process_path":r"C:\Temp\sample.exe","process_sha256":"","signer":"","score":88,"confidence":.9,"reasons":["Multi-signal"],"data":{"process_create_time":1000.0},"recommended_actions":["terminate_process_if_identity_matches"]}; d.update(kw); return d

def persist(db):
    db.upsert_incident({**incident(),"created_ts":1.0,"updated_ts":1.0,"status":"open","subject_key":"pid:4321:1000","ppid":1,"signature_status":"","level":"CRITICAL","categories":["process","network"],"timeline":[],"suppressed":False})

def test_response_requires_explicit_approval_and_audits(tmp_path):
    db=Database(tmp_path/"db.sqlite"); persist(db); r=ResponseEngine(db,FakeQ()).terminate_process(incident(),approved=False)
    assert r.status=="blocked" and db.incident_actions("BCI-RESP01")[0]["status"]=="blocked"

def test_response_rejects_pid_reuse(monkeypatch,tmp_path):
    db=Database(tmp_path/"db.sqlite")
    class P:
        def __init__(self,pid):pass
        def create_time(self):return 2000.0
        def name(self):return "sample.exe"
        def exe(self):return r"C:\Temp\sample.exe"
        def terminate(self):raise AssertionError
    monkeypatch.setattr("sentinel.response_engine.psutil.Process",P)
    r=ResponseEngine(db,FakeQ()).terminate_process(incident(),approved=True)
    assert r.status=="blocked" and "PID generation changed" in r.detail

def test_response_terminates_after_identity_validation(monkeypatch,tmp_path):
    db=Database(tmp_path/"db.sqlite"); state={"x":False}
    class P:
        def __init__(self,pid):pass
        def create_time(self):return 1000.0
        def name(self):return "sample.exe"
        def exe(self):return r"C:\Temp\sample.exe"
        def terminate(self):state["x"]=True
        def wait(self,timeout):return 0
    monkeypatch.setattr("sentinel.response_engine.psutil.Process",P)
    r=ResponseEngine(db,FakeQ()).terminate_process(incident(),approved=True)
    assert r.status=="success" and state["x"]

def test_network_containment_fails_closed(tmp_path):
    r=ResponseEngine(Database(tmp_path/"db.sqlite"),FakeQ()).contain_network(incident(),approved=True)
    assert r.status=="unsupported" and "hardened privileged service" in r.detail


def test_incident_uses_event_create_time_without_process_tree(tmp_path):
    db=Database(tmp_path/"db.sqlite")
    engine=IncidentCorrelationEngine(db)
    event=SecurityEvent(
        category="process", action="start", source="process_monitor", score=60,
        pid=990, process_name="sample.exe", process_path=r"C:\Temp\sample.exe",
        reasons=["Synthetic convergence"], data={"create_time":123.456}, ts=30,
    )
    inc=engine.ingest(event,correlation=Corr(15,.8,["Correlated behavior"]))
    assert inc is not None
    assert inc.subject_key.startswith("pid:990:123.456")
    assert inc.data["process_create_time"]==123.456
    assert inc.incident_id.startswith("BCI-")

def test_generic_malicious_word_does_not_override_allowlist(tmp_path):
    db=Database(tmp_path/"db.sqlite")
    path=r"C:\Tools\trusted.exe"
    db.add_allowlist("file",path)
    event=SecurityEvent(
        category="process", action="start", source="heuristic", score=72, pid=991,
        process_name="trusted.exe", process_path=path,
        reasons=["Generic text says malicious behavior may be possible"], ts=31,
    )
    inc=IncidentCorrelationEngine(db).ingest(event,correlation=Corr(10,.7,["Context"]))
    assert inc is not None and inc.suppressed and inc.score<=49


def test_termination_requires_process_generation(tmp_path):
    db=Database(tmp_path/"db.sqlite")
    payload=incident(data={})
    r=ResponseEngine(db,FakeQ()).terminate_process(payload,approved=True)
    assert r.status=="blocked" and "generation is unavailable" in r.detail

def test_file_event_preserves_quarantine_candidate(tmp_path):
    db=Database(tmp_path/"db.sqlite")
    engine=IncidentCorrelationEngine(db)
    event=SecurityEvent(
        category="file", action="write", source="etw", score=72, pid=992,
        process_name="writer.exe", process_path=r"C:\Temp\writer.exe",
        path=r"C:\Users\Test\Downloads\payload.exe",
        reasons=["Synthetic file evidence"], data={"create_time":321.0}, ts=32,
    )
    inc=engine.ingest(event,correlation=Corr(10,.8,["Write correlation"]))
    assert inc is not None
    assert inc.data["file_candidate_path"].endswith("payload.exe")

def test_quarantine_prefers_file_candidate_path(monkeypatch,tmp_path):
    db=Database(tmp_path/"db.sqlite"); q=FakeQ()
    candidate=tmp_path/"payload.exe"; candidate.write_bytes(b"harmless")
    monkeypatch.setattr("sentinel.response_engine.is_reparse_point",lambda p:False)
    payload=incident(process_path=str(tmp_path/"writer.exe"),data={"process_create_time":1000.0,"file_candidate_path":str(candidate)})
    r=ResponseEngine(db,q).quarantine_file(payload,approved=True)
    assert r.status=="success" and q.calls and q.calls[0][0]==str(candidate)

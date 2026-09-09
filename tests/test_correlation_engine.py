from sentinel.correlation_engine import (
    BehavioralCorrelationEngine,
    EventDeduplicator,
)
from sentinel.core.events import SecurityEvent
from sentinel.process_tree import ProcessNode

def event(**kwargs):
    base=dict(
        category="process",
        action="start",
        source="test",
        process_name="powershell.exe",
        process_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        pid=20,
        ppid=10,
        data={"cmdline":"powershell.exe -EncodedCommand AAAA"},
    )
    base.update(kwargs)
    return SecurityEvent(**base)

def test_office_to_encoded_powershell_correlates():
    engine=BehavioralCorrelationEngine()
    ancestry=[
        ProcessNode(pid=20,ppid=10,name="powershell.exe"),
        ProcessNode(pid=10,ppid=1,name="winword.exe"),
    ]
    result=engine.assess(event(),ancestry)
    assert result.score_delta >= 30
    joined=" ".join(result.reasons).lower()
    assert "office" in joined
    assert "codificato" in joined

def test_temp_execution_adds_context():
    engine=BehavioralCorrelationEngine()
    e=event(
        process_name="update.exe",
        process_path=r"C:\Users\A\AppData\Local\Temp\update.exe",
        data={},
    )
    result=engine.assess(e,[])
    assert result.score_delta >= 8

def test_persistence_temp_path_is_stronger():
    engine=BehavioralCorrelationEngine()
    e=SecurityEvent(
        category="persistence",
        action="added",
        source="test",
        path=r"registry:Run",
        data={"cmdline":r"C:\Users\A\AppData\Local\Temp\a.exe"},
        pid=5,
    )
    result=engine.assess(e,[])
    assert result.score_delta >= 18

def test_deduplicator_suppresses_identical_burst():
    d=EventDeduplicator(ttl_seconds=5)
    e=event()
    assert d.allow(e,now=100)
    assert not d.allow(e,now=101)
    assert d.allow(e,now=106)


def test_suppressed_duplicates_do_not_extend_ttl():
    d=EventDeduplicator(ttl_seconds=5)
    e=event()
    assert d.allow(e,now=100)
    assert not d.allow(e,now=101)
    assert not d.allow(e,now=104)
    assert d.allow(e,now=106)

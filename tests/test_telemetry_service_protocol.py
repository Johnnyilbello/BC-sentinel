from sentinel.telemetry_service_core import EventBuffer
from sentinel.core.events import SecurityEvent

def test_event_buffer_sequence():
    buf=EventBuffer(max_events=10)
    buf.append(SecurityEvent(category="process",action="start",source="test",pid=10))
    buf.append(SecurityEvent(category="file",action="write",source="test",pid=10,path="x.txt"))
    rows=buf.since(0)
    assert [x["seq"] for x in rows]==[1,2]
    assert buf.sequence==2

def test_event_buffer_since():
    buf=EventBuffer(max_events=10)
    for i in range(4):
        buf.append(SecurityEvent(category="file",action="write",source="test",path=str(i)))
    rows=buf.since(2)
    assert len(rows)==2
    assert rows[0]["seq"]==3

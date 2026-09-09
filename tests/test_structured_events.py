from sentinel.database import Database
from sentinel.core.events import SecurityEvent

def test_event_journal(tmp_path):
    db=Database(tmp_path/"db.sqlite"); i=db.record_security_event(SecurityEvent(category="file",action="write",source="test",pid=9))
    assert i>0 and db.recent_security_events()[0]["pid"]==9

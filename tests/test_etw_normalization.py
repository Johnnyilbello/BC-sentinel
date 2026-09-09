from sentinel.etw_monitor import normalize_etw_event

def test_tuple():
    d=normalize_etw_event(("provider",{"Task Name":"Write","ProcessId":42}))
    assert d["ProcessId"]==42 and d["_provider"]=="provider"

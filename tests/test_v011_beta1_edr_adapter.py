from __future__ import annotations

from types import SimpleNamespace

from sentinel.edr import EdrPipeline, EdrTelemetryStore
from sentinel.edr_adapter import EdrEventAdapter, telemetry_from_security_event


def test_security_event_adapter_maps_core_fields(tmp_path):
    source = SimpleNamespace(
        category="network",
        pid=42,
        ppid=7,
        process_name="powershell.exe",
        process_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        path="",
        ts=1234.5,
        data={
            "cmdline": "powershell -enc AAAA",
            "remote_domain": "malware.test",
            "remote_addr": "192.0.2.55",
            "port": 443,
            "signed_ioc": True,
            "user_sid": "S-1-5-21-demo",
            "session_id": 2,
            "integrity_level": "medium",
        },
    )
    event = telemetry_from_security_event(source)
    assert event.category == "network"
    assert event.pid == 42
    assert event.ppid == 7
    assert event.command_line == "powershell -enc AAAA"
    assert event.remote_domain == "malware.test"
    assert event.remote_address == "192.0.2.55"
    assert event.remote_port == 443
    assert event.user_sid == "S-1-5-21-demo"
    assert event.session_id == 2
    assert event.integrity_level == "medium"
    assert event.source == "security_event"


def test_adapter_ingests_into_pipeline(tmp_path):
    pipeline = EdrPipeline(EdrTelemetryStore(tmp_path / "edr.sqlite3"))
    adapter = EdrEventAdapter(pipeline)
    source = SimpleNamespace(
        category="process",
        pid=100,
        ppid=1,
        process_name="notepad.exe",
        process_path=r"C:\Windows\System32\notepad.exe",
        path="",
        ts=2000.0,
        data={},
    )
    result = adapter.ingest_security_event(source)
    assert result["stored"] is True
    rows = pipeline.store.query_events(pid=100)
    assert len(rows) == 1
    assert rows[0]["process_name"] == "notepad.exe"

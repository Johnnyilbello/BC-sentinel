from __future__ import annotations

from pathlib import Path

from sentinel.edr import EDR_PROFILE, EdrPipeline, EdrTelemetryEvent, EdrTelemetryStore


def make_pipeline(tmp_path: Path, **kwargs) -> EdrPipeline:
    store = EdrTelemetryStore(tmp_path / "edr.sqlite3", **kwargs)
    return EdrPipeline(store, window_seconds=120)


def test_profile_and_non_destructive_status(tmp_path: Path):
    pipeline = make_pipeline(tmp_path)
    status = pipeline.status()
    assert status["profile"] == EDR_PROFILE == "v0.11.0-beta.1"
    assert status["enabled"] is True
    assert status["single_heuristic_high"] is False
    assert status["automatic_process_kill"] is False
    assert status["automatic_file_delete"] is False
    assert status["automatic_host_isolation"] is False
    assert status["cloud_required"] is False


def test_event_deduplication_is_stable(tmp_path: Path):
    pipeline = make_pipeline(tmp_path)
    event = EdrTelemetryEvent(category="process", pid=10, process_name="notepad.exe", ts=1000.0)
    first = pipeline.ingest(event)
    second = pipeline.ingest(event)
    assert first["stored"] is True
    assert second["stored"] is False
    assert second["disposition"] == "duplicate"
    assert first["event_id"] == second["event_id"]
    assert pipeline.store.stats()["duplicates"] == 1


def test_process_tree_parent_child(tmp_path: Path):
    pipeline = make_pipeline(tmp_path)
    pipeline.ingest(EdrTelemetryEvent(category="process", pid=100, ppid=1, process_name="msedge.exe", ts=2000.0))
    pipeline.ingest(EdrTelemetryEvent(category="process", pid=200, ppid=100, process_name="powershell.exe", ts=2001.0))
    tree = pipeline.store.process_tree(since=1999.0)
    assert tree[100]["name"] == "msedge.exe"
    assert tree[200]["ppid"] == 100
    assert 200 in tree[100]["children"]


def test_benign_browser_and_network_do_not_create_incident(tmp_path: Path):
    pipeline = make_pipeline(tmp_path)
    assert pipeline.ingest(EdrTelemetryEvent(
        category="process", pid=101, ppid=1, process_name="msedge.exe",
        process_path=r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", ts=3000.0,
    ))["incident"] is None
    result = pipeline.ingest(EdrTelemetryEvent(
        category="network", pid=101, process_name="msedge.exe",
        remote_domain="accounts.google.com", remote_address="142.250.0.1", ts=3001.0,
        data={"signed_ioc": False, "suspicious_domain": False},
    ))
    assert result["incident"] is None
    assert pipeline.store.incidents() == []


def test_single_heuristic_family_never_becomes_high(tmp_path: Path):
    pipeline = make_pipeline(tmp_path)
    result = pipeline.ingest(EdrTelemetryEvent(
        category="process", pid=202, ppid=1, process_name="powershell.exe",
        process_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        command_line="powershell.exe -EncodedCommand ZgBvAG8=", ts=4000.0,
    ))
    incident = result["incident"]
    if incident is not None:
        assert incident["score"] <= 49
        assert incident["severity"] != "HIGH"
    assert pipeline.status()["single_heuristic_high"] is False


def test_browser_download_to_script_and_signed_ioc_qualifies_high(tmp_path: Path):
    pipeline = make_pipeline(tmp_path)
    pipeline.ingest(EdrTelemetryEvent(
        category="process", pid=300, ppid=1, process_name="msedge.exe", ts=5000.0,
    ))
    pipeline.ingest(EdrTelemetryEvent(
        category="download", pid=300, process_name="msedge.exe", path=r"C:\Users\demo\Downloads\invoice.ps1",
        ts=5001.0, data={"url": "https://malware.test/invoice.ps1", "signed_ioc": True},
    ))
    result = pipeline.ingest(EdrTelemetryEvent(
        category="process", pid=301, ppid=300, process_name="powershell.exe",
        process_path=r"C:\Users\demo\Downloads\invoice.ps1",
        command_line="powershell.exe -EncodedCommand SQBFAFgA", ts=5002.0,
        data={"parent_name": "msedge.exe"},
    ))
    incident = result["incident"]
    assert incident is not None
    assert incident["severity"] == "HIGH"
    assert incident["score"] >= 70
    assert "deterministic" in incident["evidence_families"]
    assert "delivery" in incident["evidence_families"]
    assert "execution" in incident["evidence_families"]
    assert incident["automatic_destructive_action"] is False
    assert incident["host_isolation"] is False


def test_incident_survives_store_restart(tmp_path: Path):
    db = tmp_path / "persistent.sqlite3"
    pipeline = EdrPipeline(EdrTelemetryStore(db), window_seconds=120)
    pipeline.ingest(EdrTelemetryEvent(category="process", pid=410, process_name="msedge.exe", ts=6000.0))
    pipeline.ingest(EdrTelemetryEvent(
        category="download", pid=410, process_name="msedge.exe", path=r"C:\Users\demo\Downloads\x.ps1",
        ts=6001.0, data={"url": "https://malware.test/x.ps1", "signed_ioc": True},
    ))
    result = pipeline.ingest(EdrTelemetryEvent(
        category="process", pid=411, ppid=410, process_name="powershell.exe",
        process_path=r"C:\Users\demo\Downloads\x.ps1", command_line="powershell -enc AAAA", ts=6002.0,
        data={"parent_name": "msedge.exe"},
    ))
    assert result["incident"] is not None
    restarted = EdrTelemetryStore(db)
    incidents = restarted.incidents()
    assert incidents
    assert incidents[0]["incident_id"].startswith("BCEDR-")
    assert restarted.query_events(limit=50)


def test_retention_removes_expired_events(tmp_path: Path):
    store = EdrTelemetryStore(tmp_path / "retention.sqlite3", retention_seconds=60)
    pipeline = EdrPipeline(store)
    pipeline.ingest(EdrTelemetryEvent(category="process", pid=1, process_name="old.exe", ts=1000.0))
    store.prune(now=1100.0)
    assert store.query_events(limit=10) == []


def test_flood_guard_bounds_same_pid_category(tmp_path: Path):
    pipeline = make_pipeline(
        tmp_path,
        flood_window_seconds=5.0,
        max_events_per_pid_window=5,
    )
    stored = 0
    dropped = 0
    for i in range(10):
        result = pipeline.ingest(EdrTelemetryEvent(
            category="file", pid=900, process_name="worker.exe", path=fr"C:\Temp\f{i}.tmp",
            ts=7000.0 + (i * 0.01), data={"sequence": i},
        ))
        stored += int(result["stored"])
        dropped += int(result["disposition"] == "flood_guard")
    assert stored == 5
    assert dropped == 5
    assert pipeline.store.stats()["flood_dropped"] == 5


def test_query_filters_pid_and_category(tmp_path: Path):
    pipeline = make_pipeline(tmp_path)
    pipeline.ingest(EdrTelemetryEvent(category="process", pid=77, process_name="a.exe", ts=8000.0))
    pipeline.ingest(EdrTelemetryEvent(category="network", pid=77, process_name="a.exe", ts=8001.0, remote_domain="example.com"))
    pipeline.ingest(EdrTelemetryEvent(category="process", pid=88, process_name="b.exe", ts=8002.0))
    rows = pipeline.store.query_events(pid=77, category="network", limit=10)
    assert len(rows) == 1
    assert rows[0]["remote_domain"] == "example.com"

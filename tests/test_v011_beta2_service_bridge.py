from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from sentinel.edr_service_bridge import EDR_SERVICE_PROFILE, EdrServiceBridge


def _event(*, category: str, pid: int, ts: float, ppid: int = 0, process_name: str = "", process_path: str = "", path: str = "", data=None):
    return SimpleNamespace(
        category=category,
        pid=pid,
        ppid=ppid,
        process_name=process_name,
        process_path=process_path,
        path=path,
        data=dict(data or {}),
        ts=ts,
    )


def make_bridge(tmp_path: Path, **kwargs) -> EdrServiceBridge:
    return EdrServiceBridge(db_path=tmp_path / "service-edr.sqlite3", **kwargs)


def test_bridge_owns_one_persistent_store_and_preserves_non_destructive_policy(tmp_path: Path):
    bridge = make_bridge(tmp_path)
    status = bridge.status()
    assert status["service_profile"] == EDR_SERVICE_PROFILE == "v0.11.0-beta.2"
    assert status["service_owned_store"] is True
    assert status["authenticated_ipc_required"] is True
    assert status["automatic_process_kill"] is False
    assert status["automatic_file_delete"] is False
    assert status["automatic_host_isolation"] is False
    assert status["cloud_required"] is False
    assert "edr_hunt" in status["read_operations"]
    assert status["privileged_operations"] == ["edr_update_retention"]


def test_existing_security_event_shape_ingests_and_is_queryable(tmp_path: Path):
    bridge = make_bridge(tmp_path)
    event = _event(
        category="file",
        pid=10,
        ts=1000.0,
        process_name="worker.exe",
        path=r"C:\Users\demo\Downloads\payload.exe",
        data={"sha256": "a" * 64, "source": "etw"},
    )
    result = bridge.ingest_security_event(event)
    assert result["stored"] is True
    timeline = bridge.dispatch_read("edr_timeline", {"pid": 10})
    assert len(timeline["items"]) == 1
    assert timeline["items"][0]["path"].endswith("payload.exe")
    hunt = bridge.dispatch_read("edr_hunt", {"indicator": "a" * 64})
    assert [row["pid"] for row in hunt["items"]] == [10]


def test_read_dispatch_rejects_privileged_or_unknown_operations(tmp_path: Path):
    bridge = make_bridge(tmp_path)
    with pytest.raises(ValueError, match="read operation"):
        bridge.dispatch_read("edr_update_retention", {})
    with pytest.raises(ValueError, match="read operation"):
        bridge.dispatch_read("run_arbitrary_command", {})


def test_retention_mutation_is_separate_privileged_surface(tmp_path: Path):
    bridge = make_bridge(tmp_path)
    result = bridge.dispatch_privileged(
        "edr_update_retention",
        {"retention_seconds": 7200, "max_events": 5000, "prune": False},
    )
    assert result["retention_seconds"] == 7200.0
    assert result["max_events"] == 5000
    assert result["automatic_destructive_action"] is False
    with pytest.raises(ValueError, match="privileged operation"):
        bridge.dispatch_privileged("edr_hunt", {})


def test_ingest_failure_is_contained_and_does_not_raise_into_protection_path(tmp_path: Path):
    bridge = make_bridge(tmp_path)
    bad = _event(category="process", pid=1, ts=1000.0, data={"session_id": "not-an-int"})
    result = bridge.ingest_security_event(bad)
    assert result["stored"] is False
    assert result["disposition"] == "edr_bridge_error"
    assert bridge.status()["service_ingest_errors"] == 1


def test_qualified_high_incident_surfaces_to_inbox_without_response_action(tmp_path: Path):
    notices = []
    bridge = make_bridge(tmp_path, inbox_callback=notices.append, correlation_window_seconds=120)

    bridge.ingest_security_event(_event(
        category="process", pid=100, ts=2000.0, process_name="msedge.exe",
    ))
    bridge.ingest_security_event(_event(
        category="download", pid=100, ts=2001.0, process_name="msedge.exe",
        path=r"C:\Users\demo\Downloads\invoice.ps1",
        data={"url": "https://malware.test/invoice.ps1", "signed_ioc": True},
    ))
    result = bridge.ingest_security_event(_event(
        category="process", pid=101, ppid=100, ts=2002.0,
        process_name="powershell.exe",
        process_path=r"C:\Users\demo\Downloads\invoice.ps1",
        data={"parent_name": "msedge.exe", "cmdline": "powershell.exe -EncodedCommand AAAA"},
    ))

    assert result["incident"] is not None
    assert result["incident"]["severity"] == "HIGH"
    assert len(notices) == 1
    notice = notices[0]
    assert notice["source"] == "edr"
    assert notice["incident_id"].startswith("BCEDR-")
    assert notice["automatic_destructive_action"] is False
    assert bridge.status()["inbox_notifications"] == 1


def test_process_tree_and_incident_evidence_are_bounded_read_surfaces(tmp_path: Path):
    bridge = make_bridge(tmp_path)
    bridge.ingest_security_event(_event(category="process", pid=200, ppid=1, ts=3000.0, process_name="parent.exe"))
    bridge.ingest_security_event(_event(category="process", pid=201, ppid=200, ts=3001.0, process_name="child.exe"))
    tree = bridge.dispatch_read("edr_process_tree", {})
    assert tree["count"] == 2
    by_pid = {node["pid"]: node for node in tree["nodes"]}
    assert by_pid[201]["ppid"] == 200
    assert 201 in by_pid[200]["children"]

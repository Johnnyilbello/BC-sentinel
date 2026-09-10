from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.edr import EdrIncident, EdrPipeline, EdrTelemetryEvent, EdrTelemetryStore
from sentinel.edr_hunting import (
    EDR_HUNT_PROFILE,
    MAX_PAGE_SIZE,
    EdrHuntQueryError,
    EdrHuntingService,
)


def make_store(tmp_path: Path) -> EdrTelemetryStore:
    return EdrTelemetryStore(tmp_path / "edr-beta2.sqlite3", retention_seconds=3600, max_events=10000)


def test_hunting_profile_and_expression_indexes_are_installed(tmp_path: Path):
    store = make_store(tmp_path)
    hunting = EdrHuntingService(store)

    with store._connect() as con:
        names = {
            str(row["name"])
            for row in con.execute("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='edr_events'")
        }

    assert hunting.status()["profile"] == EDR_HUNT_PROFILE == "v0.11.0-beta.2"
    assert hunting.status()["indexed_hunting"] is True
    assert hunting.status()["automatic_process_kill"] is False
    assert hunting.status()["automatic_file_delete"] is False
    assert hunting.status()["automatic_host_isolation"] is False
    assert {
        "idx_edr_events_hunt_sha256",
        "idx_edr_events_hunt_domain",
        "idx_edr_events_hunt_address",
        "idx_edr_events_hunt_path",
    }.issubset(names)


def test_exact_ioc_hunting_is_case_insensitive_but_does_not_suffix_match(tmp_path: Path):
    store = make_store(tmp_path)
    pipeline = EdrPipeline(store)
    hunting = EdrHuntingService(store)
    digest = "A" * 64

    pipeline.ingest(EdrTelemetryEvent(
        category="network",
        pid=10,
        remote_domain="Malware.Test",
        remote_address="192.0.2.10",
        ts=1000.0,
    ))
    pipeline.ingest(EdrTelemetryEvent(
        category="network",
        pid=11,
        remote_domain="notmalware.test",
        remote_address="192.0.2.11",
        ts=1001.0,
    ))
    pipeline.ingest(EdrTelemetryEvent(
        category="file",
        pid=12,
        path=r"C:\Users\demo\Downloads\payload.exe",
        sha256=digest,
        ts=1002.0,
    ))

    domain = hunting.hunt("malware.test")
    assert [row["pid"] for row in domain["items"]] == [10]
    assert domain["indicator"] == {"kind": "domain", "value": "malware.test"}

    by_hash = hunting.hunt(digest.lower())
    assert [row["pid"] for row in by_hash["items"]] == [12]
    assert by_hash["indicator"]["kind"] == "sha256"

    by_ip = hunting.hunt("192.0.2.10")
    assert [row["pid"] for row in by_ip["items"]] == [10]

    by_path = hunting.hunt(r"c:\users\demo\downloads\payload.exe")
    assert [row["pid"] for row in by_path["items"]] == [12]


def test_timeline_cursor_is_stable_for_sub_microsecond_timestamps(tmp_path: Path):
    store = make_store(tmp_path)
    pipeline = EdrPipeline(store)
    hunting = EdrHuntingService(store)

    times = [2000.0000001, 2000.0000002, 2000.0000003]
    for idx, ts in enumerate(times, start=1):
        pipeline.ingest(EdrTelemetryEvent(
            category="file",
            pid=20,
            path=fr"C:\Temp\event-{idx}.tmp",
            ts=ts,
            data={"sequence": idx},
        ))

    first = hunting.timeline(pid=20, limit=2)
    second = hunting.timeline(pid=20, limit=2, cursor=first["next_cursor"])

    assert first["has_more"] is True
    assert first["next_cursor"]
    assert [row["data"]["sequence"] for row in first["items"]] == [1, 2]
    assert [row["data"]["sequence"] for row in second["items"]] == [3]
    assert second["has_more"] is False


def test_page_size_is_bounded_and_invalid_cursor_fails_closed(tmp_path: Path):
    store = make_store(tmp_path)
    hunting = EdrHuntingService(store)

    page = hunting.timeline(limit=MAX_PAGE_SIZE + 1000)
    assert page["limit"] == MAX_PAGE_SIZE

    with pytest.raises(EdrHuntQueryError, match="pagination cursor"):
        hunting.timeline(cursor="not-a-valid-cursor")


def test_incident_evidence_navigates_only_linked_events(tmp_path: Path):
    store = make_store(tmp_path)
    pipeline = EdrPipeline(store)
    hunting = EdrHuntingService(store)

    a = EdrTelemetryEvent(category="process", pid=100, process_name="parent.exe", ts=3000.0)
    b = EdrTelemetryEvent(category="process", pid=101, ppid=100, process_name="child.exe", ts=3001.0)
    c = EdrTelemetryEvent(category="file", pid=999, path=r"C:\Temp\unrelated.tmp", ts=3002.0)
    pipeline.ingest(a)
    pipeline.ingest(b)
    pipeline.ingest(c)

    incident = EdrIncident(
        incident_id="BCEDR-BETA2EVIDENCE00001",
        score=80,
        severity="HIGH",
        confidence=0.9,
        event_ids=[a.ensure_id(), b.ensure_id()],
        pids=[100, 101],
        signal_codes=["fixture"],
        evidence_families=["fixture"],
        reasons=["fixture"],
        first_seen=3000.0,
        last_seen=3001.0,
    )
    store.save_incident(incident)

    page = hunting.incident_evidence(incident.incident_id)
    assert [row["pid"] for row in page["items"]] == [100, 101]
    assert all(row["event_id"] != c.ensure_id() for row in page["items"])


def test_root_cause_returns_incident_process_edges_and_roots(tmp_path: Path):
    store = make_store(tmp_path)
    pipeline = EdrPipeline(store)
    hunting = EdrHuntingService(store)

    root = EdrTelemetryEvent(category="process", pid=200, ppid=1, process_name="browser.exe", ts=4000.0)
    child = EdrTelemetryEvent(category="process", pid=201, ppid=200, process_name="powershell.exe", ts=4001.0)
    grandchild = EdrTelemetryEvent(category="process", pid=202, ppid=201, process_name="rundll32.exe", ts=4002.0)
    for event in (root, child, grandchild):
        pipeline.ingest(event)

    incident = EdrIncident(
        incident_id="BCEDR-BETA2ROOTCAUSE001",
        score=90,
        severity="HIGH",
        confidence=0.95,
        event_ids=[root.ensure_id(), child.ensure_id(), grandchild.ensure_id()],
        pids=[200, 201, 202],
        signal_codes=["fixture"],
        evidence_families=["process_chain"],
        reasons=["fixture"],
        first_seen=4000.0,
        last_seen=4002.0,
    )
    store.save_incident(incident)

    view = hunting.root_cause(incident.incident_id)
    assert view["root_pids"] == [200]
    assert {tuple(edge.values()) for edge in view["edges"]} == {(200, 201), (201, 202)}
    assert [node["pid"] for node in view["nodes"]] == [200, 201, 202]
    assert view["truncated"] is False


def test_retention_administration_is_bounded_and_non_destructive(tmp_path: Path):
    store = make_store(tmp_path)
    hunting = EdrHuntingService(store)

    policy = hunting.update_retention(retention_seconds=7200, max_events=5000, prune=False)
    assert policy["retention_seconds"] == 7200.0
    assert policy["max_events"] == 5000
    assert policy["pruned"] is False
    assert policy["automatic_destructive_action"] is False

    with pytest.raises(EdrHuntQueryError, match="retention_seconds"):
        hunting.update_retention(retention_seconds=1, prune=False)
    with pytest.raises(EdrHuntQueryError, match="max_events"):
        hunting.update_retention(max_events=10_000_000, prune=False)


def test_checkpoint_a_uses_isolated_per_run_pytest_basetemp():
    script = Path(__file__).resolve().parents[1] / "TEST-V011-BETA2-CHECKPOINT-A.ps1"
    text = script.read_text(encoding="utf-8")

    assert "bc-sentinel-v011-beta2-checkpoint-a-" in text
    assert "[guid]::NewGuid().ToString('N')" in text
    assert "-m pytest -q --basetemp $PytestTemp" in text
    assert "pytest-current" in text
    assert "-ErrorAction SilentlyContinue" in text

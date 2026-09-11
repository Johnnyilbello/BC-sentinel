from __future__ import annotations

from sentinel import b2_diagnostic_trace as trace


def test_non_marker_paths_do_not_enter_trace_buffer(monkeypatch, tmp_path):
    monkeypatch.setenv("PROGRAMDATA", str(tmp_path))
    trace.clear_trace()
    assert trace.trace_marker("IGNORED", path=str(tmp_path / "ordinary.txt")) is None
    assert trace.trace_snapshot() == []


def test_marker_trace_records_normalized_path_stage_and_fields(monkeypatch, tmp_path):
    monkeypatch.setenv("PROGRAMDATA", str(tmp_path))
    trace.clear_trace()
    marker = tmp_path / "bcs-v011-test-marker.tmp"
    marker.write_text("safe", encoding="utf-8")

    record = trace.trace_marker("WATCHDOG_EVENT_RECEIVED", path=str(marker), event_type="created")
    assert record is not None
    assert record["stage"] == "WATCHDOG_EVENT_RECEIVED"
    assert record["path"] == str(marker)
    assert record["normalized_path"]
    assert record["fields"]["event_type"] == "created"

    items = trace.trace_snapshot()
    assert len(items) == 1
    assert items[0]["seq"] == 1
    meta = trace.trace_metadata()
    assert meta["marker_only"] is True
    assert meta["buffered"] == 1
    assert meta["capacity"] == 256


def test_trace_is_bounded(monkeypatch, tmp_path):
    monkeypatch.setenv("PROGRAMDATA", str(tmp_path))
    trace.clear_trace()
    marker = tmp_path / "bcs-v011-bounded.tmp"
    for index in range(400):
        trace.trace_marker("STEP", path=str(marker), index=index)
    items = trace.trace_snapshot(256)
    assert len(items) == 256
    assert items[-1]["fields"]["index"] == 399
    assert items[0]["fields"]["index"] == 144


def test_jsonl_is_written_only_for_markers(monkeypatch, tmp_path):
    monkeypatch.setenv("PROGRAMDATA", str(tmp_path))
    trace.clear_trace()
    trace.trace_marker("IGNORED", path=str(tmp_path / "ordinary.tmp"))
    target = tmp_path / "BC Sentinel" / "Logs" / "b2-marker-trace.jsonl"
    assert not target.exists()

    trace.trace_marker("EDR_BRIDGE_INGEST_RESULT", path=str(tmp_path / "bcs-v011-jsonl.tmp"), stored=True)
    assert target.is_file()
    content = target.read_text(encoding="utf-8")
    assert "EDR_BRIDGE_INGEST_RESULT" in content
    assert '"stored":true' in content

from pathlib import Path

from sentinel.core.events import SecurityEvent
from sentinel.correlation_engine import BehavioralCorrelationEngine, EventDeduplicator
from sentinel.process_tree import ProcessNode


def _process(pid, ppid, name, path, ts, cmdline=""):
    return SecurityEvent(
        category="process",
        action="start",
        source="test",
        pid=pid,
        ppid=ppid,
        process_name=name,
        process_path=path,
        data={"cmdline": cmdline},
        ts=ts,
    )


def _ancestry(*nodes):
    return [ProcessNode(**node) for node in nodes]


def test_cross_pid_written_payload_is_correlated_to_child_execution():
    engine = BehavioralCorrelationEngine(window_seconds=60)
    parent_chain = _ancestry(
        {"pid": 200, "ppid": 100, "name": "powershell.exe", "create_time": 1001},
        {"pid": 100, "ppid": 1, "name": "winword.exe", "create_time": 1000},
    )
    child_chain = _ancestry(
        {"pid": 300, "ppid": 200, "name": "payload.exe", "create_time": 1002},
        {"pid": 200, "ppid": 100, "name": "powershell.exe", "create_time": 1001},
        {"pid": 100, "ppid": 1, "name": "winword.exe", "create_time": 1000},
    )

    engine.assess(
        SecurityEvent(
            category="file",
            action="create",
            source="test",
            pid=200,
            ppid=100,
            process_name="powershell.exe",
            path=r"C:\Users\A\AppData\Local\Temp\payload.exe",
            ts=10,
        ),
        parent_chain,
    )
    result = engine.assess(
        _process(
            300,
            200,
            "payload.exe",
            r"C:\Users\A\AppData\Local\Temp\payload.exe",
            12,
        ),
        child_chain,
    )

    assert "written_payload_execution" in result.evidence_families
    assert any("scritto" in reason.lower() and "eseguito" in reason.lower() for reason in result.reasons)
    assert result.score_delta >= 24
    assert result.incident_id.startswith("BCI-")


def test_ordered_encoded_script_to_network_sequence_scores_but_reverse_does_not():
    ancestry = _ancestry(
        {"pid": 20, "ppid": 10, "name": "powershell.exe", "create_time": 2},
        {"pid": 10, "ppid": 1, "name": "explorer.exe", "create_time": 1},
    )

    ordered = BehavioralCorrelationEngine(window_seconds=60)
    ordered.assess(
        _process(
            20,
            10,
            "powershell.exe",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            10,
            "powershell.exe -EncodedCommand AAAA",
        ),
        ancestry,
    )
    result = ordered.assess(
        SecurityEvent(
            category="network",
            action="connect",
            source="test",
            pid=20,
            ppid=10,
            process_name="powershell.exe",
            data={"remote_addr": "8.8.8.8", "remote_port": 443},
            ts=12,
        ),
        ancestry,
    )
    assert "encoded_to_network" in result.evidence_families

    reverse = BehavioralCorrelationEngine(window_seconds=60)
    reverse.assess(
        SecurityEvent(
            category="network",
            action="connect",
            source="test",
            pid=20,
            ppid=10,
            process_name="powershell.exe",
            data={"remote_addr": "8.8.8.8", "remote_port": 443},
            ts=10,
        ),
        ancestry,
    )
    reversed_result = reverse.assess(
        _process(
            20,
            10,
            "powershell.exe",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            12,
            "powershell.exe -EncodedCommand AAAA",
        ),
        ancestry,
    )
    assert "encoded_to_network" not in reversed_result.evidence_families


def test_noisy_browser_cache_write_plus_https_does_not_become_behavioral_alert():
    engine = BehavioralCorrelationEngine(window_seconds=60)
    ancestry = _ancestry(
        {"pid": 50, "ppid": 1, "name": "chrome.exe", "create_time": 50},
    )
    engine.assess(
        SecurityEvent(
            category="file",
            action="write",
            source="test",
            pid=50,
            process_name="chrome.exe",
            process_path=r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            path=r"C:\Users\A\AppData\Local\Google\Chrome\Cache\cache.bin",
            ts=10,
        ),
        ancestry,
    )
    result = engine.assess(
        SecurityEvent(
            category="network",
            action="connect",
            source="test",
            pid=50,
            process_name="chrome.exe",
            process_path=r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            data={"remote_addr": "142.250.184.14", "remote_port": 443},
            ts=11,
        ),
        ancestry,
    )
    assert result.score_delta == 0
    assert result.severity == "none"


def test_pidless_persistence_links_recent_executable_path():
    engine = BehavioralCorrelationEngine(window_seconds=60)
    ancestry = _ancestry(
        {"pid": 77, "ppid": 1, "name": "payload.exe", "path": r"C:\Users\A\AppData\Local\Temp\payload.exe", "create_time": 77},
    )
    engine.assess(
        _process(
            77,
            1,
            "payload.exe",
            r"C:\Users\A\AppData\Local\Temp\payload.exe",
            10,
        ),
        ancestry,
    )
    result = engine.assess(
        SecurityEvent(
            category="persistence",
            action="added",
            source="test",
            path="registry:HKCU:Run:Updater",
            data={"value": r"C:\Users\A\AppData\Local\Temp\payload.exe"},
            ts=12,
        ),
        [],
    )
    assert "persistence_process_link" in result.evidence_families
    assert result.incident_id.startswith("BCI-")
    assert "persistence" in result.stages


def test_stale_events_outside_window_do_not_converge():
    engine = BehavioralCorrelationEngine(window_seconds=5)
    ancestry = _ancestry({"pid": 20, "ppid": 1, "name": "powershell.exe", "create_time": 2})
    engine.assess(
        _process(20, 1, "powershell.exe", r"C:\Windows\powershell.exe", 1, "powershell -EncodedCommand AAAA"),
        ancestry,
    )
    result = engine.assess(
        SecurityEvent(
            category="network",
            action="connect",
            source="test",
            pid=20,
            process_name="powershell.exe",
            data={"remote_addr": "8.8.8.8", "remote_port": 443},
            ts=20,
        ),
        ancestry,
    )
    assert "encoded_to_network" not in result.evidence_families


def test_incident_id_is_stable_for_same_process_generation_inside_bucket():
    engine = BehavioralCorrelationEngine(window_seconds=60)
    ancestry = _ancestry(
        {"pid": 20, "ppid": 10, "name": "powershell.exe", "create_time": 123.5},
        {"pid": 10, "ppid": 1, "name": "winword.exe", "create_time": 120.0},
    )
    a = engine.assess(
        _process(20, 10, "powershell.exe", r"C:\Windows\powershell.exe", 100, "powershell -EncodedCommand AAAA"),
        ancestry,
    )
    b = engine.assess(
        SecurityEvent(
            category="network",
            action="connect",
            source="test",
            pid=20,
            ppid=10,
            process_name="powershell.exe",
            data={"remote_addr": "8.8.8.8", "remote_port": 443},
            ts=110,
        ),
        ancestry,
    )
    assert a.incident_id == b.incident_id


def test_deduplicator_keeps_distinct_network_endpoints():
    d = EventDeduplicator(ttl_seconds=5)
    a = SecurityEvent(
        category="network", action="connect", source="test", pid=10,
        process_name="sample.exe", path="network", data={"remote_addr": "1.1.1.1", "remote_port": 443},
    )
    b = SecurityEvent(
        category="network", action="connect", source="test", pid=10,
        process_name="sample.exe", path="network", data={"remote_addr": "8.8.8.8", "remote_port": 443},
    )
    assert d.allow(a, now=100)
    assert d.allow(b, now=101)


def test_sequence_is_bounded_and_stage_order_is_explainable():
    engine = BehavioralCorrelationEngine(window_seconds=120)
    ancestry = _ancestry({"pid": 90, "ppid": 1, "name": "sample.exe", "create_time": 90})
    for index in range(20):
        engine.assess(
            SecurityEvent(
                category="file",
                action="write",
                source="test",
                pid=90,
                process_name="sample.exe",
                path=rf"C:\tmp\f{index}.bin",
                ts=10 + index,
            ),
            ancestry,
        )
    result = engine.assess(
        SecurityEvent(
            category="network",
            action="connect",
            source="test",
            pid=90,
            process_name="sample.exe",
            data={"remote_addr": "8.8.8.8", "remote_port": 443},
            ts=40,
        ),
        ancestry,
    )
    assert len(result.sequence) <= 8
    if "file_modification" in result.stages and "network_activity" in result.stages:
        assert result.stages.index("file_modification") < result.stages.index("network_activity")


def test_local_persistence_callback_routes_through_v2_pipeline():
    source = Path("app/ui/main_window.py").read_text(encoding="utf-8")
    start = source.index("    def on_persistence_event")
    end = source.index("    def _handle_persistence_event", start)
    block = source[start:end]
    assert "self.on_security_event(event)" in block
    assert "record_security_event(event)" not in block


def test_windows_acceptance_dependencies_are_in_top_level_requirements():
    requirements = Path("requirements.txt").read_text(encoding="utf-8").casefold()
    assert "pywintrace" in requirements
    assert "pywin32" in requirements


def test_correlation_engine_is_safe_under_parallel_event_submission():
    from concurrent.futures import ThreadPoolExecutor

    engine = BehavioralCorrelationEngine(window_seconds=30)
    ancestry = _ancestry({"pid": 501, "ppid": 1, "name": "worker.exe", "create_time": 501})

    def submit(index):
        event = SecurityEvent(
            category="file" if index % 2 == 0 else "network",
            action="write" if index % 2 == 0 else "connect",
            source="parallel-test",
            pid=501,
            process_name="worker.exe",
            path=rf"C:\bench\f{index}.dat" if index % 2 == 0 else "",
            data={} if index % 2 == 0 else {"remote_addr": "203.0.113.20", "remote_port": 443},
            ts=100 + index * 0.001,
        )
        return engine.assess(event, ancestry)

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(submit, range(200)))

    assert len(results) == 200
    assert all(0 <= result.score_delta <= 75 for result in results)


def test_windows_acceptance_contains_behavioral_v2_probe():
    source = Path("tools/windows_acceptance.py").read_text(encoding="utf-8")
    assert "behavioral-correlation-v2" in source
    assert "_behavioral_correlation_probe()" in source

from __future__ import annotations

import argparse
import gc
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from time import perf_counter

from sentinel import __version__
from sentinel.edr import EDR_PROFILE, EdrPipeline, EdrTelemetryEvent, EdrTelemetryStore


def run_acceptance() -> dict:
    temp = TemporaryDirectory(prefix="bc-sentinel-v011-edr-")
    try:
        td = temp.name
        db = Path(td) / "edr.sqlite3"
        store = EdrTelemetryStore(
            db,
            retention_seconds=36_000,
            max_events=5000,
            flood_window_seconds=5.0,
            max_events_per_pid_window=8,
        )
        pipeline = EdrPipeline(store, window_seconds=120)

        benign_process = pipeline.ingest(EdrTelemetryEvent(
            category="process", pid=1000, ppid=1, process_name="msedge.exe",
            process_path=r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", ts=10_000.0,
        ))
        benign_network = pipeline.ingest(EdrTelemetryEvent(
            category="network", pid=1000, process_name="msedge.exe", remote_domain="accounts.google.com",
            remote_address="142.250.0.1", ts=10_001.0,
            data={"signed_ioc": False, "suspicious_domain": False},
        ))

        pipeline.ingest(EdrTelemetryEvent(
            category="process", pid=2000, ppid=1, process_name="msedge.exe", ts=20_000.0,
        ))
        download = pipeline.ingest(EdrTelemetryEvent(
            category="download", pid=2000, process_name="msedge.exe",
            path=r"C:\Users\demo\Downloads\invoice.ps1", ts=20_001.0,
            data={"url": "https://malware.test/invoice.ps1", "signed_ioc": True},
        ))
        execution = pipeline.ingest(EdrTelemetryEvent(
            category="process", pid=2001, ppid=2000, process_name="powershell.exe",
            process_path=r"C:\Users\demo\Downloads\invoice.ps1",
            command_line="powershell.exe -EncodedCommand SQBFAFgA", ts=20_002.0,
            data={"parent_name": "msedge.exe"},
        ))
        network = pipeline.ingest(EdrTelemetryEvent(
            category="network", pid=2001, ppid=2000, process_name="powershell.exe",
            remote_domain="malware.test", remote_address="192.0.2.55", remote_port=443, ts=20_003.0,
            data={"signed_ioc": True},
        ))
        persistence = pipeline.ingest(EdrTelemetryEvent(
            category="persistence", pid=2001, ppid=2000, process_name="powershell.exe",
            path=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Demo", ts=20_004.0,
        ))

        duplicate_event = EdrTelemetryEvent(category="file", pid=3000, path=r"C:\Temp\same.bin", ts=30_000.0)
        duplicate_first = pipeline.ingest(duplicate_event)
        duplicate_second = pipeline.ingest(duplicate_event)

        tree = store.process_tree(since=19_999.0)
        incidents_before_restart = store.incidents()
        restarted = EdrTelemetryStore(db)
        incidents_after_restart = restarted.incidents()
        events_after_restart = restarted.query_events(limit=5000)

        flood_store = EdrTelemetryStore(
            Path(td) / "flood.sqlite3",
            max_events_per_pid_window=5,
            flood_window_seconds=5.0,
        )
        flood_pipeline = EdrPipeline(flood_store)
        flood_results = [
            flood_pipeline.ingest(EdrTelemetryEvent(
                category="file", pid=4444, process_name="worker.exe", path=fr"C:\Temp\storm-{i}.tmp",
                ts=40_000.0 + i * 0.01, data={"i": i},
            ))
            for i in range(10)
        ]

        perf_store = EdrTelemetryStore(Path(td) / "perf.sqlite3", max_events=10_000, max_events_per_pid_window=10_000)
        perf_pipeline = EdrPipeline(perf_store)
        start = perf_counter()
        iterations = 1000
        for i in range(iterations):
            perf_pipeline.ingest(EdrTelemetryEvent(
                category="network", pid=5000 + (i % 20), process_name="browser.exe",
                remote_domain="example.com", remote_address="192.0.2.1", ts=50_000.0 + i * 0.001,
                data={"sequence": i},
            ))
        elapsed = perf_counter() - start
        throughput = iterations / elapsed if elapsed > 0 else 0.0

        high_incidents = [x for x in incidents_before_restart if str(x.get("severity")) == "HIGH"]
        high = high_incidents[0] if high_incidents else {}
        status = pipeline.status()
        acceptance = {
            "profile": status.get("profile") == EDR_PROFILE,
            "benign_no_incident": benign_process["incident"] is None and benign_network["incident"] is None,
            "telemetry_persisted": len(events_after_restart) >= 8,
            "process_tree": 2000 in tree and 2001 in tree and 2001 in tree[2000]["children"],
            "download_correlation": bool(download["stored"]),
            "high_multi_signal_incident": bool(high) and int(high.get("score", 0)) >= 70,
            "deterministic_evidence": "deterministic" in set(high.get("evidence_families") or []),
            "execution_evidence": "execution" in set(high.get("evidence_families") or []),
            "incident_persistence_restart": bool(incidents_after_restart),
            "stable_event_dedup": duplicate_first["stored"] and (not duplicate_second["stored"]) and duplicate_second["disposition"] == "duplicate",
            "flood_guard": sum(1 for x in flood_results if x["disposition"] == "flood_guard") == 5,
            "queryable": bool(restarted.query_events(pid=2001, limit=100)),
            "single_heuristic_high": status["single_heuristic_high"] is False,
            "automatic_process_kill": status["automatic_process_kill"] is False,
            "automatic_file_delete": status["automatic_file_delete"] is False,
            "automatic_host_isolation": status["automatic_host_isolation"] is False,
            "cloud_required": status["cloud_required"] is False,
            "throughput_floor": throughput >= 50.0,
        }
        passed = all(acceptance.values())
        report = {
            "product": "BC Sentinel",
            "version": __version__,
            "milestone": EDR_PROFILE,
            "profile": EDR_PROFILE,
            "passed": passed,
            "acceptance": acceptance,
            "detail": {
                "high_incident": high,
                "download_result": download,
                "execution_result": execution,
                "network_result": network,
                "persistence_result": persistence,
                "status": status,
                "performance": {
                    "iterations": iterations,
                    "elapsed_seconds": round(elapsed, 6),
                    "throughput_per_second": round(throughput, 2),
                    "minimum_required": 50.0,
                },
            },
            "safety": {
                "single_heuristic_high": False,
                "automatic_process_kill": False,
                "automatic_file_delete": False,
                "automatic_host_isolation": False,
                "cloud_required": False,
                "reboot_gate_deferred": True,
            },
        }
        return report
    finally:
        # SQLite connections are explicitly closed by EdrTelemetryStore. GC here
        # makes the acceptance cleanup deterministic even if future fixtures add
        # cursors/connection cycles that otherwise linger until a later collection.
        gc.collect()
        temp.cleanup()


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel v0.11.0-beta.1 EDR acceptance")
    parser.add_argument("--output", default="")
    args = parser.parse_args()
    report = run_acceptance()
    text = json.dumps(report, ensure_ascii=False, indent=2)
    print(text)
    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

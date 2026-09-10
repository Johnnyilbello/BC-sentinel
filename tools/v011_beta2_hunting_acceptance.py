from __future__ import annotations

import argparse
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from sentinel.edr import EdrPipeline, EdrTelemetryEvent, EdrTelemetryStore
from sentinel.edr_hunting import EDR_HUNT_PROFILE, EdrHuntingService


def run_acceptance() -> dict:
    with TemporaryDirectory(prefix="bcs-v011-beta2-hunt-") as temp_dir:
        db = Path(temp_dir) / "edr.sqlite3"
        store = EdrTelemetryStore(db, retention_seconds=3600, max_events=10000)
        pipeline = EdrPipeline(store, window_seconds=120)
        hunting = EdrHuntingService(store)

        digest = "ab" * 32
        root = EdrTelemetryEvent(
            category="process",
            pid=1000,
            ppid=1,
            process_name="msedge.exe",
            process_path=r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
            ts=10000.0,
        )
        download = EdrTelemetryEvent(
            category="download",
            pid=1000,
            process_name="msedge.exe",
            path=r"C:\Users\demo\Downloads\invoice.ps1",
            sha256=digest,
            ts=10001.0,
            data={"url": "https://malware.test/invoice.ps1", "signed_ioc": True},
        )
        child = EdrTelemetryEvent(
            category="process",
            pid=1001,
            ppid=1000,
            process_name="powershell.exe",
            process_path=r"C:\Users\demo\Downloads\invoice.ps1",
            command_line="powershell.exe -EncodedCommand SQBFAFgA",
            sha256=digest,
            ts=10002.0,
            data={"parent_name": "msedge.exe"},
        )
        network = EdrTelemetryEvent(
            category="network",
            pid=1001,
            ppid=1000,
            process_name="powershell.exe",
            remote_domain="malware.test",
            remote_address="192.0.2.44",
            ts=10003.0,
            data={"signed_ioc": True},
        )
        persistence = EdrTelemetryEvent(
            category="persistence",
            pid=1001,
            ppid=1000,
            process_name="powershell.exe",
            path=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Invoice",
            ts=10004.0,
        )

        latest = None
        for event in (root, download, child, network, persistence):
            result = pipeline.ingest(event)
            if result.get("incident"):
                latest = result["incident"]

        for sequence, ts in enumerate((10005.0000001, 10005.0000002, 10005.0000003), start=1):
            pipeline.ingest(EdrTelemetryEvent(
                category="file",
                pid=1001,
                path=fr"C:\Temp\page-{sequence}.tmp",
                ts=ts,
                data={"sequence": sequence},
            ))

        first_page = hunting.timeline(pid=1001, category="file", limit=2)
        second_page = hunting.timeline(
            pid=1001,
            category="file",
            limit=2,
            cursor=first_page.get("next_cursor"),
        )
        domain_hunt = hunting.hunt("MALWARE.TEST")
        hash_hunt = hunting.hunt(digest.upper())
        ip_hunt = hunting.hunt("192.0.2.44")

        incident_id = str((latest or {}).get("incident_id") or "")
        evidence = hunting.incident_evidence(incident_id) if incident_id else {"items": []}
        root_cause = hunting.root_cause(incident_id) if incident_id else {"root_pids": [], "edges": []}
        retention = hunting.update_retention(retention_seconds=7200, max_events=5000, prune=False)
        status = hunting.status()

        checks = {
            "profile": status.get("profile") == EDR_HUNT_PROFILE,
            "indexed_hunting": status.get("indexed_hunting") is True,
            "domain_hunt_exact": [row.get("pid") for row in domain_hunt.get("items", [])] == [1001],
            "sha256_hunt": {row.get("pid") for row in hash_hunt.get("items", [])} == {1000, 1001},
            "ip_hunt": [row.get("pid") for row in ip_hunt.get("items", [])] == [1001],
            "pagination_first": [row.get("data", {}).get("sequence") for row in first_page.get("items", [])] == [1, 2],
            "pagination_second": [row.get("data", {}).get("sequence") for row in second_page.get("items", [])] == [3],
            "incident_evidence": bool(evidence.get("items")),
            "root_cause_root": root_cause.get("root_pids") == [1000],
            "root_cause_edge": {tuple(edge.values()) for edge in root_cause.get("edges", [])} >= {(1000, 1001)},
            "retention_bounded": retention.get("retention_seconds") == 7200.0 and retention.get("max_events") == 5000,
            "no_auto_kill": status.get("automatic_process_kill") is False,
            "no_auto_delete": status.get("automatic_file_delete") is False,
            "no_auto_isolation": status.get("automatic_host_isolation") is False,
            "no_cloud_required": status.get("cloud_required") is False,
        }

        return {
            "product": "BC Sentinel",
            "milestone": EDR_HUNT_PROFILE,
            "checkpoint": "A-indexed-retrospective-hunting",
            "passed": all(checks.values()),
            "checks": checks,
            "detail": {
                "domain_hits": len(domain_hunt.get("items", [])),
                "sha256_hits": len(hash_hunt.get("items", [])),
                "ip_hits": len(ip_hunt.get("items", [])),
                "incident_id": incident_id,
                "evidence_events": len(evidence.get("items", [])),
                "root_pids": root_cause.get("root_pids", []),
                "page_1_count": len(first_page.get("items", [])),
                "page_2_count": len(second_page.get("items", [])),
            },
            "safety": {
                "automatic_process_kill": False,
                "automatic_file_delete": False,
                "automatic_host_isolation": False,
                "cloud_required": False,
            },
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="")
    args = parser.parse_args()

    result = run_acceptance()
    rendered = json.dumps(result, indent=2, ensure_ascii=False)
    print(rendered)
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import argparse
import json
from pathlib import Path
import tempfile
import time

from sentinel.config import APP_VERSION
from sentinel.core.events import SecurityEvent
from sentinel.database import Database
from sentinel.protection_client import ProtectionServiceClient
from sentinel.protection_service_core import ProtectionRuntime
from sentinel.web_download_protection import BrowserDownloadCorrelation
from sentinel.web_protection import WebProtectionEngine


def _ioc(db: Database, domain: str) -> None:
    db.execute(
        """INSERT OR REPLACE INTO ioc_indicators(kind,value,severity,label,expires_at,bundle_id)
           VALUES('domain',?,?,?,?,?)""",
        (domain, "critical", "BC Sentinel harmless Beta4 download acceptance IOC", time.time() + 3600, "web-download-acceptance"),
    )


def _runtime(root: Path) -> ProtectionRuntime:
    runtime = ProtectionRuntime.__new__(ProtectionRuntime)
    runtime.db = Database(root / "web-download.sqlite")
    runtime.web_protection = WebProtectionEngine(runtime.db)
    runtime.download_correlation = BrowserDownloadCorrelation(runtime.web_protection, window_seconds=45)
    return runtime


def run(*, service_live: bool = False) -> dict:
    result = {
        "product": "BC Sentinel", "version": APP_VERSION,
        "harmless_fixture": True, "service_live_requested": bool(service_live), "passed": False,
    }
    with tempfile.TemporaryDirectory(prefix="bcs-web-download-") as raw:
        root = Path(raw)
        runtime = _runtime(root)
        _ioc(runtime.db, "malware.test")
        network = SecurityEvent(
            category="network", action="connect", source="acceptance", pid=4242,
            process_name="chrome.exe", process_path="C:/Chrome/chrome.exe",
            data={"remote_domain": "malware.test", "remote_addr": "192.0.2.55", "signer": "Google LLC"},
        )
        runtime._enrich_web_download_event(network)
        file_event = SecurityEvent(
            category="file", action="write", source="etw", pid=4242,
            process_name="chrome.exe", process_path="C:/Chrome/chrome.exe",
            path="C:/Users/Acceptance/Downloads/bcs-safe-download.bin", data={"signer": "Google LLC"},
        )
        download_id = runtime._enrich_web_download_event(file_event)
        row = dict(runtime.db.web_download(download_id)) if download_id else {}
        origin_separate = bool(
            download_id.startswith("BCD-")
            and row.get("domain") == "malware.test"
            and bool(row.get("origin_signed_ioc"))
            and int(row.get("origin_score") or 0) >= 85
            and int(row.get("file_score") or 0) == 0
            and str(row.get("file_level") or "") == "UNSCANNED"
            and int(file_event.score or 0) == 0
        )

        runtime.db.update_web_download_file_verdict(
            file_event.path, sha256="a" * 64, score=82, level="HIGH"
        )
        after_scan = dict(runtime.db.web_download(download_id))
        process = SecurityEvent(
            category="process", action="start", source="acceptance", pid=5000,
            process_name="bcs-safe-download.bin", process_path=file_event.path, path=file_event.path, data={},
        )
        execution_id = runtime._enrich_web_download_event(process)
        runtime.db.mark_web_download_executed(file_event.path, executed_pid=5000, incident_id="BCI-BETA4-ACCEPT")
        executed = dict(runtime.db.web_download(download_id))

        wrong_pid = SecurityEvent(
            category="file", action="write", source="etw", pid=9000,
            process_name="chrome.exe", process_path="C:/Chrome/chrome.exe",
            path="C:/Users/Acceptance/Downloads/wrong-pid.bin", data={"signer": "Google LLC"},
        )
        wrong = runtime.download_correlation.correlate_file(wrong_pid)
        fake_browser_net = SecurityEvent(
            category="network", action="connect", source="acceptance", pid=7000,
            process_name="chrome-helper-malware.exe", process_path="C:/Temp/chrome-helper-malware.exe",
            data={"remote_domain": "malware.test", "remote_addr": "192.0.2.55", "signer": "Google LLC"},
        )
        fake_observed = runtime.download_correlation.observe_network(fake_browser_net)

        local_ok = bool(
            origin_separate
            and int(after_scan.get("file_score") or 0) == 82
            and str(after_scan.get("file_level") or "") == "HIGH"
            and execution_id == download_id
            and process.data.get("download_execution") is True
            and int(process.score or 0) == 35
            and executed.get("status") == "executed"
            and executed.get("incident_id") == "BCI-BETA4-ACCEPT"
            and wrong.matched is False
            and fake_observed is False
        )
        result.update({
            "local_foundation_passed": local_ok,
            "download": {
                "download_id": download_id,
                "domain": row.get("domain"),
                "origin_signed_ioc": bool(row.get("origin_signed_ioc")),
                "origin_score": int(row.get("origin_score") or 0),
                "file_score_before_scan": int(row.get("file_score") or 0),
                "file_score_after_scan": int(after_scan.get("file_score") or 0),
                "file_verdict_separate": True,
                "stage": row.get("stage"),
            },
            "execution": {
                "tracked_download_execution": execution_id == download_id,
                "behavior_score_delta": int(process.score or 0),
                "incident_link": executed.get("incident_id"),
            },
            "attribution_safety": {
                "same_pid_required": not wrong.matched,
                "exact_browser_required": not fake_observed,
                "origin_only_never_file_malicious": True,
            },
            "safety": {
                "auto_quarantine_from_origin": False,
                "auto_delete_from_origin": False,
                "mitm_https": False,
            },
        })

    live_ok = True
    if service_live:
        client = ProtectionServiceClient(timeout=2.0)
        status = client.web_status()
        downloads = client.web_downloads(20)
        live_ok = bool(
            isinstance(status, dict)
            and status.get("mode") == "active_reversible"
            and status.get("download_tracking") is True
            and status.get("download_origin_never_overrides_file_verdict") is True
            and isinstance(status.get("download_correlation"), dict)
            and status.get("download_correlation", {}).get("browser_exact_classification") is True
            and status.get("download_correlation", {}).get("origin_only_never_file_malicious") is True
            and status.get("mitm_https") is False
            and status.get("auto_block") is False
            and isinstance(downloads, list)
        )
        result["service"] = status if isinstance(status, dict) else {"error": client.last_error or "unavailable"}
        result["service_downloads_readable"] = isinstance(downloads, list)
        result["service_live_passed"] = live_ok

    result["passed"] = bool(result.get("local_foundation_passed") and live_ok)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel v0.7.2 Beta 4 Browser Download Protection safe acceptance")
    parser.add_argument("--service-live", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = run(service_live=bool(args.service_live))
    text = json.dumps(result, indent=2, ensure_ascii=False)
    print(text)
    if args.output:
        args.output.write_text(text + "\n", encoding="utf-8")
    return 0 if result.get("passed") else 2


if __name__ == "__main__":
    raise SystemExit(main())

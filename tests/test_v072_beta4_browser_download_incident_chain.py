from __future__ import annotations

from pathlib import Path
import time

from sentinel.service_update import version_key
from sentinel.core.events import SecurityEvent
from sentinel.database import Database
from sentinel.protection_protocol import build_request, validate_request
from sentinel.protection_service_core import ProtectionRuntime
from sentinel.web_download_protection import BrowserDownloadCorrelation, download_stage, is_download_candidate
from sentinel.web_protection import WebProtectionEngine

ROOT = Path(__file__).resolve().parents[1]
SECRET = "e" * 64


def _ioc(db: Database, domain: str):
    db.execute(
        """INSERT OR REPLACE INTO ioc_indicators(kind,value,severity,label,expires_at,bundle_id)
           VALUES('domain',?,?,?,?,?)""",
        (domain, "critical", "Beta4 harmless signed download-origin IOC", time.time() + 3600, "unit-beta4"),
    )


def _network(pid=4242, *, domain="malware.test", process="chrome.exe", now=None):
    return SecurityEvent(
        category="network", action="connect", source="unit", pid=pid,
        process_name=process, process_path=f"C:/Browser/{process}", score=0,
        data={"remote_domain": domain, "remote_addr": "192.0.2.55", "signer": "Google LLC"},
        ts=float(now or time.time()),
    )


def _file(pid=4242, *, path="C:/Users/Test/Downloads/setup.exe", process="chrome.exe", now=None):
    return SecurityEvent(
        category="file", action="write", source="etw", pid=pid, path=path,
        process_name=process, process_path=f"C:/Browser/{process}", score=0,
        data={"signer": "Google LLC"}, ts=float(now or time.time()),
    )


def _runtime(tmp_path):
    runtime = ProtectionRuntime.__new__(ProtectionRuntime)
    runtime.db = Database(tmp_path / "runtime.sqlite")
    runtime.web_protection = WebProtectionEngine(runtime.db)
    runtime.download_correlation = BrowserDownloadCorrelation(runtime.web_protection, window_seconds=45)
    return runtime


def test_beta4_download_candidate_is_bounded_to_download_paths_or_partial_extensions():
    assert is_download_candidate("C:/Users/Test/Downloads/setup.exe") is True
    assert is_download_candidate("C:/Temp/setup.crdownload") is True
    assert is_download_candidate("C:/Users/Test/Documents/setup.exe") is False
    assert download_stage("C:/Temp/setup.crdownload") == "partial"
    assert download_stage("C:/Users/Test/Downloads/setup.exe") == "materialized"


def test_beta4_same_pid_exact_browser_correlation_only(tmp_path):
    db = Database(tmp_path / "corr.sqlite")
    engine = WebProtectionEngine(db)
    corr = BrowserDownloadCorrelation(engine, window_seconds=45)
    assert corr.observe_network(_network(pid=4242)) is True
    matched = corr.correlate_file(_file(pid=4242))
    assert matched.matched is True and matched.domain == "malware.test" and matched.browser_family == "Chrome"
    assert corr.correlate_file(_file(pid=9999)).matched is False

    fake = BrowserDownloadCorrelation(engine)
    assert fake.observe_network(_network(pid=55, process="chrome-helper-malware.exe")) is False
    assert fake.correlate_file(_file(pid=55, process="chrome-helper-malware.exe")).matched is False


def test_beta4_expired_browser_network_observation_does_not_attribute_download(tmp_path):
    db = Database(tmp_path / "expired.sqlite")
    corr = BrowserDownloadCorrelation(WebProtectionEngine(db), window_seconds=5)
    net = _network(pid=4242)
    assert corr.observe_network(net, now=100.0)
    result = corr.correlate_file(_file(pid=4242), now=106.0)
    assert result.matched is False


def test_beta4_runtime_persists_download_origin_but_keeps_file_verdict_independent(tmp_path):
    runtime = _runtime(tmp_path)
    _ioc(runtime.db, "malware.test")
    network = _network(pid=4242)
    runtime._enrich_web_download_event(network)
    event = _file(pid=4242)
    download_id = runtime._enrich_web_download_event(event)
    assert download_id.startswith("BCD-")
    row = dict(runtime.db.web_download(download_id))
    assert row["domain"] == "malware.test"
    assert row["origin_signed_ioc"] == 1
    assert row["origin_score"] >= 85
    assert row["file_score"] == 0
    assert row["file_level"] == "UNSCANNED"
    assert event.score == 0
    assert event.data["download_file_verdict_separate"] is True


def test_beta4_scanner_verdict_updates_download_without_origin_overriding_it(tmp_path):
    runtime = _runtime(tmp_path)
    runtime.download_correlation.observe_network(_network(pid=4242))
    path = "C:/Users/Test/Downloads/clean.bin"
    download_id = runtime._enrich_web_download_event(_file(pid=4242, path=path))
    assert download_id
    runtime.db.update_web_download_file_verdict(path, sha256="a" * 64, score=0, level="SAFE")
    safe = dict(runtime.db.web_download(download_id))
    assert safe["file_score"] == 0 and safe["file_level"] == "SAFE"
    runtime.db.update_web_download_file_verdict(path, sha256="b" * 64, score=82, level="HIGH")
    risky = dict(runtime.db.web_download(download_id))
    assert risky["origin_score"] == 0
    assert risky["file_score"] == 82 and risky["file_level"] == "HIGH" and risky["status"] == "file_risk"


def test_beta4_execution_of_tracked_download_becomes_behavioral_evidence(tmp_path):
    runtime = _runtime(tmp_path)
    _ioc(runtime.db, "malware.test")
    runtime.download_correlation.observe_network(_network(pid=4242))
    path = "C:/Users/Test/Downloads/setup.exe"
    download_id = runtime._enrich_web_download_event(_file(pid=4242, path=path))
    process = SecurityEvent(category="process", action="start", source="unit", pid=5000, process_name="setup.exe", process_path=path, path=path, data={})
    matched = runtime._enrich_web_download_event(process)
    assert matched == download_id
    assert process.data["download_execution"] is True
    assert process.data["download_origin_signed_ioc"] is True
    assert process.score == 35
    assert any("download" in x.casefold() for x in process.reasons)
    runtime.db.mark_web_download_executed(path, executed_pid=5000, incident_id="BCI-BETA4")
    row = dict(runtime.db.web_download(download_id))
    assert row["status"] == "executed" and row["executed_pid"] == 5000 and row["incident_id"] == "BCI-BETA4"


def test_beta4_protocol_exposes_bounded_read_only_download_queries():
    assert validate_request(build_request("web_downloads", SECRET, limit=25)).payload == {"limit": 25}
    assert validate_request(build_request("web_download_detail", SECRET, download_id="BCD-" + "A" * 20)).payload["download_id"].startswith("BCD-")


def test_beta4_ui_exposes_download_chain_without_destructive_origin_action():
    source = (ROOT / "app" / "ui" / "main_window.py").read_text(encoding="utf-8")
    for text in ["Download Protection", "Download tracciati", "web_downloads", "Dettagli download"]:
        assert text in source


def test_beta4_release_version_and_artifacts():
    from sentinel.config import APP_VERSION
    assert version_key(APP_VERSION) >= version_key("0.9.0-rc.1")
    assert (ROOT / "sentinel" / "__init__.py").read_text(encoding="utf-8").strip() == f'__version__ = "{APP_VERSION}"'
    assert f'version = "{APP_VERSION.replace("-alpha.", "a").replace("-beta.", "b").replace("-rc.", "rc")}"' in (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert (ROOT / "RELEASE-NOTES-v0.9.0-beta.3.md").exists()
    assert (ROOT / "BC_SENTINEL_V072_BETA4_BROWSER_DOWNLOAD_REPORT.md").exists()


def test_beta4_acceptance_passes_side_effect_free():
    from tools.web_download_acceptance import run
    result = run(service_live=False)
    assert result["passed"] is True
    assert result["download"]["origin_signed_ioc"] is True
    assert result["download"]["file_verdict_separate"] is True
    assert result["execution"]["tracked_download_execution"] is True


def test_beta4_windows_acceptance_registers_download_foundation_and_live_gates():
    from tools.windows_acceptance import _v072_beta4_download_probe
    probe = _v072_beta4_download_probe()
    assert probe["status"] == "pass" and probe["critical"] is True
    source = (ROOT / "tools" / "windows_acceptance.py").read_text(encoding="utf-8")
    assert "web-download-v072-beta4-foundation" in source
    assert "web-download-v072-beta4-live" in source

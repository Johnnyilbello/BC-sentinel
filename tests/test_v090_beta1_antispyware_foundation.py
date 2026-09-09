from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.service_update import version_key
from sentinel.antispyware import (
    AntispywareEngine,
    PersistenceEntry,
    WindowsPersistenceCollector,
    assess_persistence_entry,
    extract_command_target,
)
from sentinel.correlation_engine import BehavioralCorrelationEngine
from sentinel.core.events import SecurityEvent
from sentinel.database import Database
from sentinel.protection_protocol import ProtocolError, validate_request
from sentinel.scoring import level_for


def _req(op: str, **payload):
    return {"version": 1, "request_id": "v090b1-test", "op": op, "token": "a" * 64, "payload": payload}


def test_v090b1_command_target_extraction_is_bounded_and_nonexecuting():
    assert extract_command_target('"C:\\Program Files\\Example\\app.exe" --background').endswith("app.exe")
    assert extract_command_target(r"C:\Users\demo\AppData\Local\Temp\sample.exe -x").endswith("sample.exe")
    assert extract_command_target("") == ""


def test_v090b1_single_normal_persistence_signal_is_not_malware():
    entry = PersistenceEntry(
        kind="registry_run",
        location=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        name="LegitUpdater",
        command=r'"C:\Program Files\Legit\updater.exe" --background',
        target_path=r"C:\Program Files\Legit\updater.exe",
        target_exists=True,
        signature_status="Valid",
        signer="CN=Legit Software",
    )
    result = assess_persistence_entry(entry)
    assert result.score < 25
    assert result.level in {"SAFE", "LOW"}
    assert result.automatic_destructive_action is False


def test_v090b1_user_writable_unsigned_encoded_persistence_is_suspicious_but_not_auto_destructive():
    entry = PersistenceEntry(
        kind="registry_runonce",
        location=r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        name="HarmlessFixture",
        command=r'powershell.exe -EncodedCommand VEhJU19JU19OT1RfTUFMV0FSRQ==',
        target_path=r"C:\Users\demo\AppData\Local\Temp\fixture.ps1",
        target_exists=True,
        user_writable=True,
        signature_status="NotSigned",
    )
    result = assess_persistence_entry(entry)
    assert result.score >= 50
    assert result.score < 70
    assert result.level == "SUSPICIOUS"
    assert result.remediation == "reversible_plan_recommended"
    assert result.automatic_destructive_action is False


def test_v090b1_multi_signal_file_verdict_can_cross_high_without_persistence_doing_delete_itself():
    entry = PersistenceEntry(
        kind="scheduled_task", location="Task Scheduler", name="HarmlessFixture",
        command=r"C:\Users\demo\AppData\Local\Temp\fixture.exe",
        target_path=r"C:\Users\demo\AppData\Local\Temp\fixture.exe",
        target_exists=True, user_writable=True, signature_status="NotSigned",
    )
    result = assess_persistence_entry(entry, network_recent=True, file_malicious=True)
    assert result.score >= 70
    assert result.level in {"HIGH", "CRITICAL"}
    assert result.automatic_destructive_action is False


def test_v090b1_browser_proxy_dns_and_wmi_are_advisory_by_default():
    entries = [
        PersistenceEntry("browser_policy", r"HKLM\Software\Policies\Google\Chrome", "ExtensionInstallForcelist", command="fixture"),
        PersistenceEntry("proxy_config", "Internet Settings", "ProxyServer", command="127.0.0.1:8080", metadata={"changed": False}),
        PersistenceEntry("dns_config", "DnsClient", "Ethernet", command="1.1.1.1", metadata={"changed": False}),
        PersistenceEntry("wmi_subscription", "root/subscription", "HarmlessConsumer", command=r"C:\Program Files\Legit\agent.exe", target_exists=True, signature_status="Valid"),
    ]
    results = [assess_persistence_entry(e) for e in entries]
    assert all(x.automatic_destructive_action is False for x in results)
    assert all(x.score < 70 for x in results)


def test_v090b1_proxy_change_from_baseline_is_detected_without_auto_remediation(tmp_path):
    db = Database(tmp_path / "sentinel.sqlite")
    engine = AntispywareEngine(db)
    first = PersistenceEntry("proxy_config", "Internet Settings", "ProxyServer", command="proxy-a:8080")
    second = PersistenceEntry("proxy_config", "Internet Settings", "ProxyServer", command="proxy-b:8080")
    engine.scan([first])
    result = engine.scan([second])[0]
    assert result.entry.metadata["changed"] is True
    assert result.entry.metadata["previous_value"] == "proxy-a:8080"
    assert any(s.key == "network:proxy-changed" for s in result.signals)
    assert result.automatic_destructive_action is False


def test_v090b1_database_persists_provenance_and_summary(tmp_path):
    db = Database(tmp_path / "sentinel.sqlite")
    entry = PersistenceEntry(
        kind="registry_run", location="HKCU\\Run", name="Fixture",
        command=r"C:\Users\demo\AppData\Local\Temp\fixture.exe",
        target_path=r"C:\Users\demo\AppData\Local\Temp\fixture.exe",
        target_exists=False, user_writable=True, signature_status="NotSigned",
        metadata={"harmless_fixture": True},
    )
    assessment = assess_persistence_entry(entry)
    stored = db.record_antispyware_finding(assessment)
    assert stored["finding_id"].startswith("BCP-")
    assert stored["kind"] == "registry_run"
    assert stored["target_path"].endswith("fixture.exe")
    rows = db.recent_antispyware_findings(10)
    assert len(rows) == 1
    summary = db.antispyware_summary()
    assert summary["total"] == 1


def test_v090b1_engine_emits_only_suspicious_changes_once(tmp_path):
    db = Database(tmp_path / "sentinel.sqlite")
    seen = []
    engine = AntispywareEngine(db, callback=seen.append)
    suspicious = PersistenceEntry(
        "registry_runonce", "HKCU\\RunOnce", "Fixture",
        command="powershell.exe -EncodedCommand AAAA",
        target_path=r"C:\Users\demo\AppData\Local\Temp\fixture.ps1",
        target_exists=True, user_writable=True, signature_status="NotSigned",
    )
    engine.scan([suspicious])
    engine.scan([suspicious])
    assert len(seen) == 1
    assert seen[0].category == "antispyware"
    assert seen[0].data["automatic_destructive_action"] is False


def test_v090b1_correlation_treats_antispyware_as_persistence_evidence():
    engine = BehavioralCorrelationEngine(window_seconds=45)
    event = SecurityEvent(
        category="antispyware", action="persistence_finding", source="antispyware_engine",
        score=58, path=r"C:\Users\demo\AppData\Local\Temp\fixture.exe",
        reasons=["harmless fixture"],
        data={"user_writable": True, "signature_status": "NotSigned"},
    )
    result = engine.assess(event)
    assert "persistence" in result.stages
    assert "antispyware_persistence" in result.evidence_families
    assert result.total_score >= event.score


def test_v090b1_protocol_read_only_surface_and_bounds():
    validate_request(_req("antispyware_status"))
    req = validate_request(_req("antispyware_findings", limit=50, min_score=25))
    assert req.payload == {"limit": 50, "min_score": 25}
    with pytest.raises(ProtocolError):
        validate_request(_req("antispyware_findings", limit=501, min_score=0))


def test_v090b1_collector_contract_covers_required_windows_surfaces():
    collector = WindowsPersistenceCollector(authenticode=False)
    required = {
        "registry_run_entries", "startup_entries", "scheduled_tasks", "auto_services",
        "wmi_subscriptions", "browser_policies", "proxy_config", "dns_config",
    }
    assert required.issubset(set(dir(collector)))
    if not collector.supported():
        assert collector.collect() == []


def test_v090b1_version_and_acceptance_artifacts_present():
    from sentinel.config import APP_VERSION
    root = Path(__file__).resolve().parents[1]
    assert version_key(APP_VERSION) >= version_key("0.9.0-rc.1")
    assert (root / "sentinel" / "__init__.py").read_text(encoding="utf-8").strip() == f'__version__ = "{APP_VERSION}"'
    assert f'version = "{APP_VERSION.replace("-alpha.", "a").replace("-beta.", "b").replace("-rc.", "rc")}"' in (root / "pyproject.toml").read_text(encoding="utf-8")
    assert (root / "RELEASE-NOTES-v0.9.0-beta.3.md").exists()
    assert (root / "tools" / "antispyware_acceptance.py").exists()
    assert "antispyware-v090-beta1-foundation" in (root / "tools" / "windows_acceptance.py").read_text(encoding="utf-8")
    assert "antispyware-v090-beta1-live" in (root / "tools" / "windows_acceptance.py").read_text(encoding="utf-8")

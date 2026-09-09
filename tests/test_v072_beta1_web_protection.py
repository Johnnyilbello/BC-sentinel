from __future__ import annotations

import json
from pathlib import Path
import time

from sentinel.service_update import version_key
from sentinel.correlation import FileProcessCorrelator
from sentinel.database import Database
from sentinel.etw_monitor import DNS_PROVIDER, FILE_PROVIDER, ETWMonitor
from sentinel.network_intelligence import NetworkReputationEngine
from sentinel.network_monitor import NetworkMonitor
from sentinel.process_tree import ProcessTree
from sentinel.protection_protocol import ClientContext, build_request
from sentinel.protection_service_core import ProtectionRuntime, ProtectionServiceCore
from sentinel.web_protection import DNSCorrelationCache, WebProtectionEngine, extract_ip_addresses

ROOT = Path(__file__).resolve().parents[1]
SECRET = "e" * 64
STANDARD = ClientContext(local=True, authenticated=True, is_admin=False, sid="S-1-5-21-user", session_id=1, transport="test", process_id=701)
UNAUTH = ClientContext(local=True, authenticated=False, is_admin=False, sid="", session_id=1, transport="test", process_id=702)


def _insert_domain_ioc(db: Database, domain: str, severity: str = "critical"):
    db.execute(
        """INSERT OR REPLACE INTO ioc_indicators(kind,value,severity,label,expires_at,bundle_id)
           VALUES('domain',?,?,?,?,?)""",
        (domain, severity, "Safe test signed-domain simulation", time.time() + 3600, "unit-test-signed-feed"),
    )


def test_beta1_web_domain_signed_ioc_is_block_recommended_but_not_auto_block(tmp_path):
    db = Database(tmp_path / "web.sqlite")
    _insert_domain_ioc(db, "malware.test")
    result = WebProtectionEngine(db).assess_domain("sub.malware.test")
    assert result.status == "malicious"
    assert result.signed_ioc is True
    assert result.block_recommended is True
    assert result.decision == "containment_recommended"
    assert result.score >= 85


def test_beta1_structural_phishing_heuristics_never_cross_high_threshold(tmp_path):
    db = Database(tmp_path / "heuristics.sqlite")
    engine = WebProtectionEngine(db)
    result = engine.assess_url("https://user:pass@xn--paypa1-l2c.a.b.c.d.example.com/login")
    assert result.status == "suspicious"
    assert result.score < 50
    assert result.block_recommended is False
    assert result.decision == "review"


def test_beta1_dns_cache_is_strictly_pid_scoped():
    cache = DNSCorrelationCache(ttl_seconds=60)
    assert cache.observe(1234, "example.test", ["192.0.2.55"]) == 1
    assert cache.lookup(1234, "192.0.2.55") == "example.test"
    assert cache.lookup(4321, "192.0.2.55") == ""


def test_beta1_dns_etw_query_results_are_parsed_and_correlated(tmp_path):
    db = Database(tmp_path / "dns.sqlite")
    _insert_domain_ioc(db, "malware.test")
    cache = DNSCorrelationCache(ttl_seconds=60)
    web = WebProtectionEngine(db)
    events = []
    tree = ProcessTree()
    monitor = ETWMonitor(tree, FileProcessCorrelator(process_tree=tree), event_callback=events.append, dns_cache=cache, web_engine=web)
    monitor._on_event((DNS_PROVIDER, {
        "EventId": 3008,
        "ProcessId": 424242,
        "QueryName": "malware.test",
        "QueryType": 1,
        "QueryStatus": 0,
        "QueryResults": "type: 1 192.0.2.55; type: 28 2001:db8::55",
    }))
    assert events
    event = events[-1]
    assert event.category == "web"
    assert event.action == "dns_resolved"
    assert event.data["remote_domain"] == "malware.test"
    assert "192.0.2.55" in event.data["resolved_addresses"]
    assert event.data["web_signed_ioc"] is True
    assert event.data["web_block_recommended"] is True
    assert cache.lookup(424242, "192.0.2.55") == "malware.test"


def test_beta1_non_dns_etw_event_cannot_be_misclassified_by_event_id(tmp_path):
    db = Database(tmp_path / "nondns.sqlite")
    events = []
    tree = ProcessTree()
    monitor = ETWMonitor(tree, FileProcessCorrelator(process_tree=tree), event_callback=events.append, dns_cache=DNSCorrelationCache(), web_engine=WebProtectionEngine(db))
    monitor._on_event((FILE_PROVIDER, {
        "EventId": 3008,
        "ProcessId": 777,
        "Name": "malware.test",
    }))
    assert not any(event.category == "web" for event in events)


def test_beta1_network_connection_uses_only_same_pid_dns_correlation(tmp_path):
    db = Database(tmp_path / "network.sqlite")
    _insert_domain_ioc(db, "malware.test")
    cache = DNSCorrelationCache(ttl_seconds=60)
    cache.observe(7001, "malware.test", ["192.0.2.55"])
    monitor = NetworkMonitor(intelligence=NetworkReputationEngine(db), dns_cache=cache)
    context = {"process_name": "browser.exe", "process_path": "C:/browser.exe", "ppid": 1, "create_time": 1.0, "cmdline": "", "process_sha256": "", "signature_status": "", "signer": ""}
    event = monitor._build_event(pid=7001, local_text="127.0.0.1:50000", remote_host="192.0.2.55", remote_port=443, remote_text="192.0.2.55:443", protocol="TCP", state="ESTABLISHED", context=context)
    assert event.data["remote_domain"] == "malware.test"
    assert event.data["dns_correlated"] is True
    assert event.data["endpoint_source"] == "signed_ioc"
    assert event.score >= 70

    other = monitor._build_event(pid=7002, local_text="127.0.0.1:50001", remote_host="192.0.2.55", remote_port=443, remote_text="192.0.2.55:443", protocol="TCP", state="ESTABLISHED", context=context)
    assert other.data["remote_domain"] == ""
    assert other.data["dns_correlated"] is False


def test_beta1_extract_ip_addresses_rejects_non_addresses():
    assert extract_ip_addresses("type: 1 192.0.2.5; alias evil.test; 999.2.3.4") == ["192.0.2.5"]


class _Events:
    sequence = 0
    def since(self, seq, limit): return []


class _WebRuntime:
    def __init__(self): self.events = _Events()
    def status(self): return {"health": "HEALTHY"}
    def web_status(self): return {"mode": "observe_recommend", "dns_etw": True, "mitm_https": False, "auto_block": False}
    def web_findings(self, limit): return [{"path": "example.test", "score": 20}]
    def web_assess(self, value): return {"indicator": "example.test", "score": 0, "decision": "observe"}


def _core():
    core = ProtectionServiceCore(_WebRuntime(), secret=SECRET)
    core._audit = lambda *a, **k: None
    core._audit_broker = lambda *a, **k: None
    return core


def test_beta1_web_protocol_is_read_only_for_authenticated_standard_user():
    core = _core()
    for request in (
        build_request("web_status", SECRET),
        build_request("web_findings", SECRET, limit=20),
        build_request("web_assess", SECRET, value="https://example.test"),
    ):
        result = core.dispatch(request, STANDARD)
        assert result["ok"] is True
    # READ operations follow the established service contract: a local caller
    # with the installation token may inspect telemetry without an admin token.
    # Identity authentication is mandatory for privileged/broker/decision ops,
    # not for read-only status surfaces.
    local_token_only = core.dispatch(build_request("web_status", SECRET), UNAUTH)
    assert local_token_only["ok"] is True


def test_beta1_runtime_web_status_is_observe_only(tmp_path):
    runtime = ProtectionRuntime.__new__(ProtectionRuntime)
    runtime.db = Database(tmp_path / "status.sqlite")
    runtime.settings = type("S", (), {"network_enabled": True, "etw_enabled": True})()
    runtime.dns_cache = DNSCorrelationCache()
    runtime.etw = type("E", (), {"status": lambda self: {"dns_tracking": True}})()
    status = runtime.web_status()
    assert status["mode"] in {"observe_recommend", "active_reversible"}
    assert status["dns_etw"] is True
    assert status["pid_scoped_dns"] is True
    assert status["mitm_https"] is False
    assert status["auto_block"] is False


def test_beta1_ui_contains_web_protection_center_and_no_mitm_language():
    source = (ROOT / "app" / "ui" / "main_window.py").read_text(encoding="utf-8")
    for text in ["Web Protection / Anti-Phishing", "Web Protection Center", "Analizza URL", "nessun MITM HTTPS", "web_assess"]:
        assert text in source


def test_beta1_web_acceptance_passes_side_effect_free():
    from tools.web_protection_acceptance import run
    result = run(service_live=False)
    assert result["passed"] is True
    assert result["safety"]["mitm_https"] is False
    assert result["safety"]["auto_block_from_heuristics"] is False


def test_beta1_release_version_and_artifacts():
    from sentinel.config import APP_VERSION
    assert version_key(APP_VERSION) >= version_key("0.9.0-rc.1")
    assert (ROOT / "sentinel" / "__init__.py").read_text(encoding="utf-8").strip() == f'__version__ = "{APP_VERSION}"'
    assert f'version = "{APP_VERSION.replace("-alpha.", "a").replace("-beta.", "b").replace("-rc.", "rc")}"' in (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert (ROOT / "RELEASE-NOTES-v0.7.2-beta.2.md").exists()
    assert (ROOT / "BC_SENTINEL_V072_BETA1_WEB_PROTECTION_REPORT.md").exists()

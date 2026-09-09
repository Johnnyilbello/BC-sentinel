from __future__ import annotations

import json
from pathlib import Path
import time

import pytest

from sentinel.service_update import version_key
from sentinel.database import Database
from sentinel.core.events import SecurityEvent
from sentinel.firewall_policy import FirewallManager, InMemoryFirewallBackend
from sentinel.network_intelligence import NetworkReputationEngine
from sentinel.network_monitor import NetworkMonitor
from sentinel.protection_protocol import ClientContext, build_request
from sentinel.protection_service_core import ProtectionRuntime, ProtectionServiceCore
from sentinel.web_protection import DNSCorrelationCache, WebProtectionEngine

ROOT = Path(__file__).resolve().parents[1]
SECRET = "b" * 64
AUTH_USER = ClientContext(local=True, authenticated=True, is_admin=False, sid="S-1-5-21-user", session_id=1, transport="test", process_id=9001)
UNAUTH = ClientContext(local=True, authenticated=False, is_admin=False, sid="", session_id=1, transport="test", process_id=9002)
ADMIN = ClientContext(local=True, authenticated=True, is_admin=True, sid="S-1-5-32-544", session_id=1, transport="test", process_id=9003)


def _ioc(db: Database, kind: str, value: str, severity: str = "critical"):
    db.execute(
        """INSERT OR REPLACE INTO ioc_indicators(kind,value,severity,label,expires_at,bundle_id)
           VALUES(?,?,?,?,?,?)""",
        (kind, value, severity, "Beta2 harmless signed IOC simulation", time.time() + 3600, "unit-beta2"),
    )


def _runtime(tmp_path):
    runtime = ProtectionRuntime.__new__(ProtectionRuntime)
    runtime.db = Database(tmp_path / "runtime.sqlite")
    runtime.web_protection = WebProtectionEngine(runtime.db)
    runtime.dns_cache = DNSCorrelationCache(ttl_seconds=120)
    runtime.firewall = FirewallManager(InMemoryFirewallBackend(), desired_state_store=runtime.db)
    runtime.events = type("E", (), {"sequence": 0, "since": lambda self, seq, limit: []})()
    return runtime


def _finding(runtime, *, domain="malware.test", address="192.0.2.55", pid=4242, source="signed_ioc_domain"):
    finding_id = "BCW-" + "A" * 20
    runtime.db.record_web_finding(
        finding_id=finding_id,
        created_at=time.time(),
        domain=domain,
        remote_address=address,
        pid=pid,
        process_name="browser.exe",
        process_path="C:/browser.exe",
        score=90,
        level="CRITICAL",
        source=source,
        reasons_json=json.dumps(["signed IOC"]),
        evidence_json=json.dumps({"signed_ioc": True, "event_category": "network", "dns_correlated": True}),
        shared_ip=False,
        block_recommended=True,
        decision="containment_recommended",
    )
    return finding_id


def test_beta2_dns_cache_detects_shared_ip_without_cross_pid_attribution():
    cache = DNSCorrelationCache(ttl_seconds=60)
    cache.observe(1001, "malware.test", ["192.0.2.55"], now=10.0)
    cache.observe(1002, "cdn.example.test", ["192.0.2.55"], now=11.0)
    first = cache.lookup_context(1001, "192.0.2.55", now=12.0)
    second = cache.lookup_context(1002, "192.0.2.55", now=12.0)
    assert first.domain == "malware.test"
    assert second.domain == "cdn.example.test"
    assert first.shared_ip is True
    assert first.domain_count == 2
    assert first.pid_count == 2
    assert cache.lookup(9999, "192.0.2.55", now=12.0) == ""


def test_beta2_signed_domain_on_shared_ip_never_recommends_address_block(tmp_path):
    db = Database(tmp_path / "web.sqlite")
    _ioc(db, "domain", "malware.test")
    result = WebProtectionEngine(db).assess_connection(
        domain="malware.test", address="192.0.2.55", shared_ip=True, domain_count=3, pid_count=2
    )
    assert result.signed_ioc is True
    assert result.score >= 85
    assert result.block_recommended is False
    assert result.decision == "review_shared_infrastructure"
    assert any("condiviso" in reason.casefold() or "cdn" in reason.casefold() for reason in result.reasons)


def test_beta2_signed_network_ioc_can_recommend_block_even_if_ip_is_shared(tmp_path):
    db = Database(tmp_path / "network-ioc.sqlite")
    _ioc(db, "network", "192.0.2.55")
    result = WebProtectionEngine(db).assess_connection(
        domain="cdn.example.test", address="192.0.2.55", shared_ip=True, domain_count=7, pid_count=5
    )
    assert result.source == "signed_ioc_network"
    assert result.block_recommended is True
    assert result.decision == "containment_recommended"


def test_beta2_network_event_exports_shared_guard_and_web_decision(tmp_path):
    db = Database(tmp_path / "network.sqlite")
    _ioc(db, "domain", "malware.test")
    cache = DNSCorrelationCache(ttl_seconds=60)
    cache.observe(7001, "malware.test", ["192.0.2.55"])
    cache.observe(7002, "other.example.test", ["192.0.2.55"])
    monitor = NetworkMonitor(
        intelligence=NetworkReputationEngine(db), dns_cache=cache, web_engine=WebProtectionEngine(db)
    )
    context = {"process_name": "browser.exe", "process_path": "C:/browser.exe", "ppid": 1, "create_time": 1.0,
               "cmdline": "", "process_sha256": "", "signature_status": "", "signer": ""}
    event = monitor._build_event(
        pid=7001, local_text="127.0.0.1:50000", remote_host="192.0.2.55", remote_port=443,
        remote_text="192.0.2.55:443", protocol="TCP", state="ESTABLISHED", context=context,
    )
    assert event.data["remote_domain"] == "malware.test"
    assert event.data["dns_shared_ip"] is True
    assert event.data["web_decision"] == "review_shared_infrastructure"
    assert event.data["web_block_recommended"] is False


def test_beta2_web_containment_rechecks_nonshared_pid_dns_before_block(tmp_path):
    runtime = _runtime(tmp_path)
    _ioc(runtime.db, "domain", "malware.test")
    runtime.dns_cache.observe(4242, "malware.test", ["192.0.2.55"])
    finding_id = _finding(runtime)
    lease = runtime.create_web_containment({
        "finding_id": finding_id, "ttl_seconds": 60, "reason": "unit", "approved": True,
    })
    assert lease["qualification"] == "signed_domain_nonshared_ip"
    assert len(runtime.firewall.list_rules()) == 1
    row = runtime.db.web_finding(finding_id)
    assert row["status"] == "contained"
    released = runtime._release_containment_lease(lease["lease_id"], reason="unit_release")
    assert released["removed"] is True
    assert runtime.db.web_finding(finding_id)["status"] == "released"
    assert runtime.firewall.list_rules() == []


def test_beta2_web_containment_fails_closed_when_ip_becomes_shared(tmp_path):
    runtime = _runtime(tmp_path)
    _ioc(runtime.db, "domain", "malware.test")
    runtime.dns_cache.observe(4242, "malware.test", ["192.0.2.55"])
    finding_id = _finding(runtime)
    runtime.dns_cache.observe(9009, "shared.example.test", ["192.0.2.55"])
    with pytest.raises(PermissionError, match="shared/CDN"):
        runtime.create_web_containment({
            "finding_id": finding_id, "ttl_seconds": 60, "reason": "unit", "approved": True,
        })
    assert runtime.firewall.list_rules() == []
    assert runtime.db.web_finding(finding_id)["status"] == "pending"


def test_beta2_dns_only_finding_requires_observed_network_connection_before_containment(tmp_path):
    runtime = _runtime(tmp_path)
    _ioc(runtime.db, "domain", "malware.test")
    runtime.dns_cache.observe(4242, "malware.test", ["192.0.2.55"])
    event = SecurityEvent(
        category="web", action="dns_resolved", path="malware.test",
        score=90, reasons=["signed IOC"], source="web_protection", pid=4242,
        process_name="browser.exe", process_path="C:/browser.exe",
        data={
            "resolved_addresses": ["192.0.2.55"], "web_source": "signed_ioc_domain",
            "web_level": "CRITICAL", "web_decision": "containment_recommended",
            "web_signed_ioc": True, "web_block_recommended": True,
        },
    )
    finding_id = runtime._record_actionable_web_finding(event)
    row = runtime.db.web_finding(finding_id)
    assert row is not None
    assert bool(row["block_recommended"]) is False
    assert row["decision"] == "await_connection"
    with pytest.raises(PermissionError, match="not qualified|observed same-PID network connection"):
        runtime.create_web_containment({
            "finding_id": finding_id, "ttl_seconds": 60, "reason": "dns-only", "approved": True,
        })
    assert runtime.firewall.list_rules() == []


def test_beta2_web_containment_fails_closed_when_dns_mapping_expired(tmp_path):
    runtime = _runtime(tmp_path)
    _ioc(runtime.db, "domain", "malware.test")
    finding_id = _finding(runtime)
    with pytest.raises(PermissionError, match="expired or changed"):
        runtime.create_web_containment({
            "finding_id": finding_id, "ttl_seconds": 60, "reason": "unit", "approved": True,
        })
    assert runtime.firewall.list_rules() == []


def test_beta2_web_ignore_once_is_authenticated_non_privileged_decision(tmp_path):
    runtime = _runtime(tmp_path)
    finding_id = _finding(runtime)
    core = ProtectionServiceCore(runtime, secret=SECRET)
    core._audit = lambda *a, **k: None
    denied = core.dispatch(build_request("web_finding_decide", SECRET, finding_id=finding_id, action="ignore_once", detail="unit"), UNAUTH)
    assert denied["ok"] is False
    assert denied["error"]["code"] == "unauthorized"
    allowed = core.dispatch(build_request("web_finding_decide", SECRET, finding_id=finding_id, action="ignore_once", detail="unit"), AUTH_USER)
    assert allowed["ok"] is True
    assert runtime.db.web_finding(finding_id)["status"] == "ignored_once"


def test_beta2_web_containment_protocol_requires_admin(tmp_path):
    runtime = _runtime(tmp_path)
    _ioc(runtime.db, "domain", "malware.test")
    runtime.dns_cache.observe(4242, "malware.test", ["192.0.2.55"])
    finding_id = _finding(runtime)
    core = ProtectionServiceCore(runtime, secret=SECRET)
    core._audit = lambda *a, **k: None
    request = build_request("web_containment_create", SECRET, finding_id=finding_id, ttl_seconds=60, reason="unit", approved=True)
    blocked = core.dispatch(request, AUTH_USER)
    assert blocked["ok"] is False and blocked["error"]["code"] == "admin_required"
    ok = core.dispatch(request, ADMIN)
    assert ok["ok"] is True
    assert ok["lease"]["qualification"] == "signed_domain_nonshared_ip"


def test_beta2_release_version_and_artifacts():
    # Bumped by the release finalization step; this test prevents partial packaging.
    from sentinel.config import APP_VERSION
    assert version_key(APP_VERSION) >= version_key("0.9.0-rc.1")
    assert (ROOT / "sentinel" / "__init__.py").read_text(encoding="utf-8").strip() == f'__version__ = "{APP_VERSION}"'
    assert f'version = "{APP_VERSION.replace("-alpha.", "a").replace("-beta.", "b").replace("-rc.", "rc")}"' in (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert (ROOT / "RELEASE-NOTES-v0.7.2-beta.2.md").exists()


def test_beta2_web_findings_persist_state_and_dedupe(tmp_path):
    db = Database(tmp_path / "findings.sqlite")
    now = time.time()
    first = db.record_web_finding(
        finding_id="BCW-" + "D" * 20, created_at=now, domain="malware.test", remote_address="192.0.2.55",
        pid=44, process_name="browser.exe", score=90, level="CRITICAL", source="signed_ioc_domain",
        reasons_json='["first"]', evidence_json='{"signed_ioc":true}', shared_ip=False,
        block_recommended=True, decision="containment_recommended",
    )
    second = db.record_web_finding(
        finding_id="BCW-" + "E" * 20, created_at=now + 1, domain="malware.test", remote_address="192.0.2.55",
        pid=44, process_name="browser.exe", score=91, level="CRITICAL", source="signed_ioc_domain",
        reasons_json='["updated"]', evidence_json='{"signed_ioc":true}', shared_ip=False,
        block_recommended=True, decision="containment_recommended",
    )
    assert first["created"] is True
    assert second["created"] is False
    assert second["finding_id"] == first["finding_id"]
    rows = db.recent_web_findings(10, status="pending")
    assert len(rows) == 1 and int(rows[0]["score"]) == 91
    db.resolve_web_finding(first["finding_id"], status="ignored_once", resolution="unit")
    assert db.recent_web_findings(10, status="pending") == []


def test_beta2_ui_exposes_reversible_web_actions_and_shared_ip_guard():
    source = (ROOT / "app" / "ui" / "main_window.py").read_text(encoding="utf-8")
    for text in [
        "Active reversible", "Ignora una volta", "Blocca 15 min", "shared-IP guard",
        "web_containment_create", "web_finding_decide",
    ]:
        assert text in source
    assert "nessun MITM HTTPS / auto-blocco" in source


def test_beta2_web_response_acceptance_passes_side_effect_free():
    from tools.web_threat_response_acceptance import run
    result = run(service_live=False)
    assert result["passed"] is True
    assert result["nonshared"]["lease"]["qualification"] == "signed_domain_nonshared_ip"
    assert result["shared_guard"]["containment_denied"] is True
    assert result["safety"]["auto_block"] is False


def test_beta2_median_benchmark_reports_three_runs(tmp_path):
    from tools.security_benchmark import make_corpus, scan_benchmark, scan_benchmark_median
    corpus = tmp_path / "corpus"
    db = Database(tmp_path / "bench.sqlite")
    make_corpus(corpus, 40, 128)
    first = scan_benchmark(corpus, db)
    robust = scan_benchmark_median(corpus, db, runs=3, first_pair=first)
    assert robust["run_count"] == 3
    assert len(robust["runs"]) == 3
    assert robust["cold_elapsed_median_seconds"] > 0
    assert robust["warm_elapsed_median_seconds"] > 0
    assert robust["warm_hash_cache_hit_ratio_median"] >= 0.9

from __future__ import annotations

import json
from pathlib import Path
import time

import pytest

from sentinel.service_update import version_key
from sentinel.database import Database
from sentinel.firewall_policy import FirewallManager, InMemoryFirewallBackend
from sentinel.network_monitor import NetworkMonitor
from sentinel.protection_protocol import ClientContext, build_request, validate_request
from sentinel.protection_service_core import ProtectionRuntime, ProtectionServiceCore
from sentinel.web_protection import DNSCorrelationCache, WebProtectionEngine, classify_browser_process

ROOT = Path(__file__).resolve().parents[1]
SECRET = "c" * 64
AUTH_USER = ClientContext(local=True, authenticated=True, is_admin=False, sid="S-1-5-21-user", session_id=1, transport="test", process_id=9101)
ADMIN = ClientContext(local=True, authenticated=True, is_admin=True, sid="S-1-5-32-544", session_id=1, transport="test", process_id=9102)


def _ioc(db: Database, kind: str, value: str, severity: str = "critical"):
    db.execute(
        """INSERT OR REPLACE INTO ioc_indicators(kind,value,severity,label,expires_at,bundle_id)
           VALUES(?,?,?,?,?,?)""",
        (kind, value, severity, "Beta3 harmless signed IOC simulation", time.time() + 3600, "unit-beta3"),
    )


def _runtime(tmp_path):
    runtime = ProtectionRuntime.__new__(ProtectionRuntime)
    runtime.db = Database(tmp_path / "runtime.sqlite")
    runtime.web_protection = WebProtectionEngine(runtime.db)
    runtime.dns_cache = DNSCorrelationCache(ttl_seconds=120)
    runtime.firewall = FirewallManager(InMemoryFirewallBackend(), desired_state_store=runtime.db)
    runtime.events = type("E", (), {"sequence": 0, "since": lambda self, seq, limit: []})()
    return runtime


def _heuristic_domain() -> str:
    return "xn--paypa1-l2c.a.b.c.d.example.com"


def test_beta3_exact_domain_trust_precedes_heuristics_but_not_subdomains(tmp_path):
    db = Database(tmp_path / "trust.sqlite")
    engine = WebProtectionEngine(db)
    domain = _heuristic_domain()
    before = engine.assess_domain(domain)
    assert before.score > 0 and before.decision == "review"
    db.add_web_domain_trust(domain, reason="operator trusted exact domain")
    trusted = engine.assess_domain(domain)
    assert trusted.status == "trusted"
    assert trusted.decision == "allow_trusted"
    assert trusted.trusted_domain is True
    assert trusted.trust_scope == "exact"
    assert trusted.score == 0
    sub = engine.assess_domain("child." + domain)
    assert sub.trusted_domain is False
    assert sub.status != "trusted"


def test_beta3_signed_ioc_overrides_existing_local_domain_trust(tmp_path):
    db = Database(tmp_path / "precedence.sqlite")
    domain = "portal.example.test"
    db.add_web_domain_trust(domain, reason="older local trust")
    _ioc(db, "domain", domain)
    result = WebProtectionEngine(db).assess_domain(domain)
    assert result.signed_ioc is True
    assert result.status == "malicious"
    assert result.decision == "containment_recommended"
    assert result.trusted_domain is True
    assert any(item.get("state") == "overridden_by_signed_ioc" for item in result.provenance)
    assert any("precedenza" in reason.casefold() for reason in result.reasons)


def test_beta3_signed_network_ioc_also_overrides_domain_trust(tmp_path):
    db = Database(tmp_path / "network-precedence.sqlite")
    db.add_web_domain_trust("portal.example.test", reason="trusted")
    _ioc(db, "network", "192.0.2.0/24")
    result = WebProtectionEngine(db).assess_connection(
        domain="portal.example.test", address="192.0.2.55", shared_ip=False
    )
    assert result.source == "signed_ioc_network"
    assert result.signed_ioc is True
    assert result.block_recommended is True
    assert result.provenance[0]["kind"] == "network"


def test_beta3_persistent_domain_trust_requires_admin_and_rejects_active_signed_ioc(tmp_path):
    runtime = _runtime(tmp_path)
    core = ProtectionServiceCore(runtime, secret=SECRET)
    core._audit = lambda *a, **k: None
    req = build_request(
        "web_domain_trust_add", SECRET,
        domain="portal.example.test", reason="unit", finding_id="", approved=True,
    )
    denied = core.dispatch(req, AUTH_USER)
    assert denied["ok"] is False and denied["error"]["code"] == "admin_required"
    allowed = core.dispatch(req, ADMIN)
    assert allowed["ok"] is True
    assert runtime.db.match_web_domain_trust("portal.example.test") is not None

    _ioc(runtime.db, "domain", "malware.test")
    blocked = core.dispatch(
        build_request("web_domain_trust_add", SECRET, domain="malware.test", reason="should fail", finding_id="", approved=True),
        ADMIN,
    )
    assert blocked["ok"] is False
    assert runtime.db.match_web_domain_trust("malware.test") is None


def test_beta3_domain_trust_remove_is_privileged_and_auditable_policy_change(tmp_path):
    runtime = _runtime(tmp_path)
    runtime.db.add_web_domain_trust("portal.example.test", reason="unit")
    core = ProtectionServiceCore(runtime, secret=SECRET)
    core._audit = lambda *a, **k: None
    req = build_request("web_domain_trust_remove", SECRET, domain="portal.example.test", approved=True)
    denied = core.dispatch(req, AUTH_USER)
    assert denied["ok"] is False and denied["error"]["code"] == "admin_required"
    allowed = core.dispatch(req, ADMIN)
    assert allowed["ok"] is True
    assert runtime.db.match_web_domain_trust("portal.example.test") is None


def test_beta3_trusting_exact_domain_resolves_only_matching_pending_findings(tmp_path):
    runtime = _runtime(tmp_path)
    now = time.time()
    for suffix, domain in (("A", "portal.example.test"), ("B", "other.example.test")):
        runtime.db.record_web_finding(
            finding_id="BCW-" + suffix * 20, created_at=now, domain=domain, remote_address="192.0.2.55",
            pid=44, process_name="chrome.exe", process_path="C:/chrome.exe", score=30, level="LOW",
            source="local_heuristics", reasons_json='["heuristic"]', evidence_json='{}', shared_ip=False,
            block_recommended=False, decision="review",
        )
    result = runtime.add_web_domain_trust({
        "domain": "portal.example.test", "reason": "operator trust", "finding_id": "BCW-" + "A" * 20, "approved": True,
    })
    assert result["resolved_findings"] == 1
    assert runtime.db.web_finding("BCW-" + "A" * 20)["status"] == "trusted_domain"
    assert runtime.db.web_finding("BCW-" + "B" * 20)["status"] == "pending"


def test_beta3_local_domain_reputation_records_bounded_provenance_samples(tmp_path):
    db = Database(tmp_path / "rep.sqlite")
    for idx in range(25):
        db.record_web_domain_observation(
            domain="portal.example.test", score=20 + idx, status="suspicious", source="network",
            process_name=f"proc{idx}.exe", process_path=f"C:/proc{idx}.exe", remote_address=f"192.0.2.{idx+1}",
        )
    rep = db.web_domain_reputation("portal.example.test")
    assert rep["observed"] is True
    assert rep["observations"] == 25
    assert rep["max_score"] == 44
    assert rep["suspicious_observations"] == 25
    assert len(rep["processes"]) == 16
    assert len(rep["addresses"]) == 16


def test_beta3_browser_context_uses_exact_known_executable_names_only():
    chrome = classify_browser_process("chrome.exe", "C:/Program Files/Google/Chrome/Application/chrome.exe", "Google LLC")
    fake = classify_browser_process("chrome-helper-malware.exe", "C:/Temp/chrome-helper-malware.exe", "Google LLC")
    firefox = classify_browser_process("", "C:/Program Files/Mozilla Firefox/firefox.exe", "Mozilla Corporation")
    assert chrome["is_browser"] is True and chrome["browser_family"] == "Chrome"
    assert firefox["is_browser"] is True and firefox["browser_family"] == "Firefox"
    assert fake["is_browser"] is False and fake["browser_family"] == ""


def test_beta3_network_event_exports_browser_and_process_provenance(tmp_path):
    db = Database(tmp_path / "browser-event.sqlite")
    cache = DNSCorrelationCache(ttl_seconds=60)
    cache.observe(7001, "portal.example.test", ["192.0.2.55"])
    monitor = NetworkMonitor(dns_cache=cache, web_engine=WebProtectionEngine(db))
    context = {
        "process_name": "msedge.exe", "process_path": "C:/Program Files/Edge/msedge.exe", "ppid": 1,
        "create_time": 1.0, "cmdline": "", "process_sha256": "a" * 64, "signature_status": "Valid", "signer": "Microsoft Corporation",
    }
    event = monitor._build_event(
        pid=7001, local_text="127.0.0.1:50000", remote_host="192.0.2.55", remote_port=443,
        remote_text="192.0.2.55:443", protocol="TCP", state="ESTABLISHED", context=context,
    )
    assert event.data["is_browser"] is True
    assert event.data["browser_family"] == "Edge"
    assert event.data["process_sha256"] == "a" * 64
    assert event.data["signature_status"] == "Valid"


def test_beta3_protocol_rejects_wildcard_or_url_domain_trust():
    with pytest.raises(Exception):
        validate_request(build_request("web_domain_trust_add", SECRET, domain="*.example.com", reason="x", finding_id="", approved=True))
    with pytest.raises(Exception):
        validate_request(build_request("web_domain_trust_add", SECRET, domain="https://example.com", reason="x", finding_id="", approved=True))


def test_beta3_ui_exposes_domain_trust_revoke_and_provenance():
    source = (ROOT / "app" / "ui" / "main_window.py").read_text(encoding="utf-8")
    for text in [
        "Consenti dominio", "Revoca fiducia", "Dettagli dominio", "exact-domain", "IOC firmati hanno sempre precedenza",
        "web_domain_trust_add", "web_domain_trust_remove", "web_domain_reputation",
    ]:
        assert text in source


def test_beta3_release_version_and_artifacts():
    from sentinel.config import APP_VERSION
    assert version_key(APP_VERSION) >= version_key("0.9.0-rc.1")
    assert (ROOT / "sentinel" / "__init__.py").read_text(encoding="utf-8").strip() == f'__version__ = "{APP_VERSION}"'
    assert f'version = "{APP_VERSION.replace("-alpha.", "a").replace("-beta.", "b").replace("-rc.", "rc")}"' in (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert (ROOT / "RELEASE-NOTES-v0.7.2-beta.3.md").exists()
    assert (ROOT / "BC_SENTINEL_V072_BETA3_DOMAIN_TRUST_REPORT.md").exists()


def test_beta3_domain_trust_acceptance_passes_side_effect_free():
    from tools.web_domain_trust_acceptance import run
    result = run(service_live=False)
    assert result["passed"] is True
    assert result["precedence"]["signed_ioc_overrides_trust"] is True
    assert result["scope"]["subdomain_inherits_trust"] is False


def test_beta3_windows_acceptance_registers_domain_trust_foundation_and_live_gates():
    from tools.windows_acceptance import _v072_beta3_domain_trust_probe
    probe = _v072_beta3_domain_trust_probe()
    assert probe["status"] == "pass" and probe["critical"] is True
    source = (ROOT / "tools" / "windows_acceptance.py").read_text(encoding="utf-8")
    assert "web-trust-v072-beta3-foundation" in source
    assert "web-trust-v072-beta3-live" in source

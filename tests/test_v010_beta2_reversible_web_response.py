from __future__ import annotations

import json
from pathlib import Path
import time

import pytest

from sentinel.config import APP_VERSION
from sentinel.database import Database
from sentinel.firewall_policy import FirewallManager, InMemoryFirewallBackend
from sentinel.protection_service_core import ProtectionRuntime
from sentinel.service_update import version_key
from sentinel.web_protection import DNSCorrelationCache, WebProtectionEngine
from sentinel.web_response import WEB_RESPONSE_PROFILE, qualify_web_containment

ROOT = Path(__file__).resolve().parents[1]


def _ioc(db: Database, kind: str, value: str):
    db.execute(
        """INSERT OR REPLACE INTO ioc_indicators(kind,value,severity,label,expires_at,bundle_id)
           VALUES(?,?,?,?,?,?)""",
        (kind, value, "critical", "Beta2 harmless signed fixture", time.time() + 3600, "v010-beta2"),
    )


def _runtime(root: Path, backend=None) -> ProtectionRuntime:
    root.mkdir(parents=True, exist_ok=True)
    runtime = ProtectionRuntime.__new__(ProtectionRuntime)
    runtime.db = Database(root / "beta2.sqlite")
    runtime.web_protection = WebProtectionEngine(runtime.db)
    runtime.dns_cache = DNSCorrelationCache(ttl_seconds=120)
    runtime.firewall = FirewallManager(backend or InMemoryFirewallBackend(), desired_state_store=runtime.db)
    return runtime


def _finding(runtime: ProtectionRuntime, fid: str, *, source="signed_ioc_domain", domain="malware.test", address="192.0.2.55", pid=4242, score=90, block=True, shared=False):
    runtime.db.record_web_finding(
        finding_id=fid, created_at=time.time(), domain=domain, remote_address=address, pid=pid,
        process_name="chrome.exe", process_path="C:/Program Files/Chrome/chrome.exe",
        score=score, level="CRITICAL" if score >= 90 else "LOW", source=source,
        reasons_json=json.dumps(["harmless test"]),
        evidence_json=json.dumps({"event_category":"network", "dns_correlated":True}),
        shared_ip=shared, block_recommended=block, decision="containment_recommended" if block else "review",
        dedupe_seconds=1,
    )


def test_version_and_response_profile():
    assert version_key(APP_VERSION) >= version_key("0.10.0-beta.2")
    assert WEB_RESPONSE_PROFILE == "v0.10.0-beta.2"


def test_pure_policy_never_promotes_heuristic_only():
    q = qualify_web_containment(
        source="local_heuristics", score=100, block_recommended=True, event_category="network",
        domain="lookalike.example", remote_address="192.0.2.9", dns_domain="lookalike.example",
        signed_domain_active=False,
    )
    assert q.eligible is False and q.reason == "heuristic_only_never_blocks"


def test_pure_policy_shared_ip_guard_even_with_signed_domain():
    q = qualify_web_containment(
        source="signed_ioc_domain", score=90, block_recommended=True, event_category="network",
        domain="malware.test", remote_address="192.0.2.55", dns_domain="malware.test",
        shared_ip=True, signed_domain_active=True,
    )
    assert q.eligible is False and q.reason == "shared_ip_guard"


def test_signed_domain_same_pid_creates_and_manual_rollback(tmp_path):
    r = _runtime(tmp_path)
    _ioc(r.db, "domain", "malware.test")
    r.dns_cache.observe(4242, "malware.test", ["192.0.2.55"])
    fid="BCW-"+"A"*20; _finding(r,fid)
    lease=r.create_web_containment({"finding_id":fid,"ttl_seconds":60,"approved":True,"reason":"unit"})
    assert lease["qualification"] == "signed_domain_nonshared_ip"
    assert len(r.firewall.list_rules()) == 1
    released=r.release_containment_lease(lease["lease_id"], approved=True)
    assert released["removed"] is True and r.firewall.list_rules() == []


def test_signed_ioc_overrides_exact_trust_for_containment(tmp_path):
    r=_runtime(tmp_path); _ioc(r.db,"domain","malware.test")
    r.db.add_web_domain_trust("malware.test", reason="older local trust")
    assessment=r.web_protection.assess_domain("malware.test")
    assert assessment.signed_ioc is True and assessment.trusted_domain is True
    r.dns_cache.observe(4242,"malware.test",["192.0.2.55"])
    fid="BCW-"+"B"*20; _finding(r,fid)
    assert r.create_web_containment({"finding_id":fid,"ttl_seconds":60,"approved":True})["qualification"] == "signed_domain_nonshared_ip"


def test_wrong_pid_dns_revalidation_denies(tmp_path):
    r=_runtime(tmp_path); _ioc(r.db,"domain","malware.test")
    r.dns_cache.observe(9999,"malware.test",["192.0.2.55"])
    fid="BCW-"+"C"*20; _finding(r,fid,pid=4242)
    with pytest.raises(PermissionError, match="expired or changed"):
        r.create_web_containment({"finding_id":fid,"ttl_seconds":60,"approved":True})
    assert r.firewall.list_rules() == []


def test_duplicate_request_is_idempotent_and_no_second_rule(tmp_path):
    r=_runtime(tmp_path); _ioc(r.db,"domain","malware.test")
    r.dns_cache.observe(4242,"malware.test",["192.0.2.55"])
    fid="BCW-"+"D"*20; _finding(r,fid)
    one=r.create_web_containment({"finding_id":fid,"ttl_seconds":60,"approved":True})
    two=r.create_web_containment({"finding_id":fid,"ttl_seconds":60,"approved":True})
    assert one["lease_id"] == two["lease_id"] and two["idempotent"] is True
    assert len(r.firewall.list_rules()) == 1


def test_separate_finding_same_address_reuses_active_lease(tmp_path):
    r=_runtime(tmp_path); _ioc(r.db,"domain","malware.test")
    r.dns_cache.observe(4242,"malware.test",["192.0.2.55"])
    first="BCW-"+"E"*20; _finding(r,first)
    one=r.create_web_containment({"finding_id":first,"ttl_seconds":60,"approved":True})
    second="BCW-"+"F"*20; _finding(r,second,pid=4243)
    r.dns_cache.observe(4243,"malware.test",["192.0.2.55"])
    two=r.create_web_containment({"finding_id":second,"ttl_seconds":60,"approved":True})
    assert one["lease_id"] == two["lease_id"] and two["reused_existing"] is True
    assert len(r.firewall.list_rules()) == 1


def test_ttl_expiry_removes_rule(tmp_path):
    r=_runtime(tmp_path); _ioc(r.db,"domain","malware.test")
    r.dns_cache.observe(4242,"malware.test",["192.0.2.55"])
    fid="BCW-"+"1"*20; _finding(r,fid)
    lease=r.create_web_containment({"finding_id":fid,"ttl_seconds":60,"approved":True})
    r.db.execute("UPDATE containment_leases SET expires_at=? WHERE lease_id=?",(time.time()-1,lease["lease_id"]))
    expired=r.expire_containment_leases()
    assert expired and expired[0]["release_reason"] == "ttl_expired" and r.firewall.list_rules()==[]


def test_restart_recovery_preserves_valid_active_rule(tmp_path):
    backend=InMemoryFirewallBackend(); r=_runtime(tmp_path,backend)
    _ioc(r.db,"domain","malware.test"); r.dns_cache.observe(4242,"malware.test",["192.0.2.55"])
    fid="BCW-"+"2"*20; _finding(r,fid)
    lease=r.create_web_containment({"finding_id":fid,"ttl_seconds":300,"approved":True})
    r2=_runtime(tmp_path,backend)
    result=r2.recover_web_containment_state()
    assert lease["lease_id"] in result["active"] and result["stale"] == [] and len(r2.firewall.list_rules())==1


def test_restart_recovery_cleans_stale_missing_rule(tmp_path):
    backend=InMemoryFirewallBackend(); r=_runtime(tmp_path,backend)
    _ioc(r.db,"domain","malware.test"); r.dns_cache.observe(4242,"malware.test",["192.0.2.55"])
    fid="BCW-"+"3"*20; _finding(r,fid)
    lease=r.create_web_containment({"finding_id":fid,"ttl_seconds":300,"approved":True})
    backend.remove_rule(lease["rule_id"])
    r2=_runtime(tmp_path,backend)
    result=r2.recover_web_containment_state()
    assert lease["lease_id"] in result["stale"]
    assert r2.db.containment_lease(lease["lease_id"])["status"] == "released"
    assert r2.db.list_firewall_expected_rules() == []


def test_signed_network_ioc_requires_observed_network_and_nonshared(tmp_path):
    r=_runtime(tmp_path); _ioc(r.db,"network","192.0.2.55/32")
    r.dns_cache.observe(4242,"neutral.example",["192.0.2.55"])
    fid="BCW-"+"4"*20; _finding(r,fid,source="signed_ioc_network",domain="neutral.example")
    lease=r.create_web_containment({"finding_id":fid,"ttl_seconds":60,"approved":True})
    assert lease["qualification"] == "signed_network_ioc"


def test_beta2_acceptance_tool_passes():
    from tools.v010_web_response_acceptance import run
    result=run(service_live=False)
    assert result["passed"] is True
    assert all(result["acceptance"].values())

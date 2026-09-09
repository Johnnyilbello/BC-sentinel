from __future__ import annotations

from contextlib import contextmanager
import hashlib
from pathlib import Path

import pytest

from sentinel.service_update import version_key
from sentinel.database import Database
from sentinel.firewall_policy import (
    FirewallManager,
    FirewallPolicyError,
    InMemoryFirewallBackend,
    MANAGED_FIREWALL_GROUP,
    ManagedFirewallRule,
    remote_addresses_equivalent,
)
from sentinel.firewall_windows import NET_FW_ACTION_BLOCK, WindowsFirewallBackend
from sentinel.protection_protocol import ClientContext, build_request
from sentinel.protection_service_core import ProtectionServiceCore
from sentinel.quarantine import QuarantineManager


SECRET = "1" * 64
STANDARD = ClientContext(
    local=True, authenticated=True, is_admin=False, sid="S-1-5-21-710",
    session_id=1, transport="test", process_id=710,
)
ADMIN = ClientContext(
    local=True, authenticated=True, is_admin=True, sid="S-1-5-21-710",
    session_id=1, transport="test", process_id=711,
)


def _fixed_rule(**overrides):
    base = dict(
        rule_id="BCSF-0710710710710710",
        remote_address="192.0.2.77",
        direction="outbound",
        protocol="any",
        remote_port=None,
        application_path="",
        reason="v0.7.1 drift test",
        incident_id="BCI-V071",
        enabled=True,
        created_at=1.0,
    )
    base.update(overrides)
    return ManagedFirewallRule(**base)


def test_v071_remote_address_equivalence_covers_windows_host_roundtrip():
    assert remote_addresses_equivalent("192.0.2.77", "192.0.2.77/32")
    assert remote_addresses_equivalent("192.0.2.77", "192.0.2.77/255.255.255.255")
    assert not remote_addresses_equivalent("192.0.2.77", "192.0.2.78")


def test_v071_desired_state_persists_in_database(tmp_path):
    db = Database(tmp_path / "sentinel.sqlite")
    backend = InMemoryFirewallBackend()
    manager = FirewallManager(backend, desired_state_store=db)
    manager.block_remote(
        remote_address="192.0.2.77",
        rule_id="BCSF-0710710710710710",
        reason="persist desired state",
    )
    rows = db.list_firewall_expected_rules()
    assert len(rows) == 1
    assert rows[0]["rule_id"] == "BCSF-0710710710710710"
    assert rows[0]["remote_address"] == "192.0.2.77"
    assert rows[0]["enabled"] == 1


def test_v071_drift_does_not_false_positive_equivalent_windows_address():
    backend = InMemoryFirewallBackend()
    manager = FirewallManager(backend)
    manager.block_remote(
        remote_address="192.0.2.77",
        rule_id="BCSF-0710710710710710",
    )
    backend._rules["BCSF-0710710710710710"] = _fixed_rule(
        remote_address="192.0.2.77/255.255.255.255"
    )
    assert manager.drift_report()["ok"] is True


def test_v071_detects_and_reconciles_modified_owned_rule():
    events = []
    backend = InMemoryFirewallBackend()
    manager = FirewallManager(backend, event_callback=events.append)
    manager.block_remote(
        remote_address="192.0.2.77",
        rule_id="BCSF-0710710710710710",
        reason="drift regression",
        incident_id="BCI-V071",
    )
    expected = backend._rules["BCSF-0710710710710710"]
    backend._rules[expected.rule_id] = ManagedFirewallRule(
        **{**expected.to_dict(), "remote_address": "192.0.2.78"}
    )

    report = manager.drift_report()
    assert report["ok"] is False
    assert report["reconcilable"] == 1
    assert report["issues"][0]["type"] == "modified"
    assert "remote_address" in report["issues"][0]["differences"]
    assert any(e.action == "rule_drift_detected" for e in events)

    result = manager.reconcile_drift(approved=True)
    assert result["ok"] is True
    assert result["actions"][0]["status"] == "restored"
    assert manager.drift_report()["ok"] is True
    assert remote_addresses_equivalent(
        "192.0.2.77",
        backend._rules[expected.rule_id].remote_address,
    )


def test_v071_detects_missing_and_external_disable():
    backend = InMemoryFirewallBackend()
    manager = FirewallManager(backend)
    rule = manager.block_remote(
        remote_address="198.51.100.7",
        rule_id="BCSF-0710710710710710",
    )
    rid = rule["rule_id"]
    original = backend._rules[rid]

    backend._rules.pop(rid)
    missing = manager.drift_report()
    assert missing["issues"][0]["type"] == "missing"
    assert manager.reconcile_drift(approved=True)["ok"] is True

    backend._rules[rid] = ManagedFirewallRule(**{**original.to_dict(), "enabled": False})
    disabled = manager.drift_report()
    assert disabled["issues"][0]["type"] == "disabled"
    assert manager.reconcile_drift(approved=True)["ok"] is True


def test_v071_reconciliation_requires_explicit_approval():
    manager = FirewallManager(InMemoryFirewallBackend())
    with pytest.raises(FirewallPolicyError, match="explicit operator approval"):
        manager.reconcile_drift(approved=False)


def test_v071_untracked_owned_rule_is_observed_but_not_deleted():
    backend = InMemoryFirewallBackend()
    backend.add_block_rule(_fixed_rule())
    manager = FirewallManager(backend)
    report = manager.drift_report()
    assert report["issues"][0]["type"] == "untracked_owned"
    result = manager.reconcile_drift(approved=True)
    assert result["actions"][0]["status"] == "not_acted"
    assert "BCSF-0710710710710710" in backend._rules


def test_v071_windows_exact_group_collision_is_fail_closed_observation_only():
    class CollisionRule:
        Name = "BC Sentinel - BCSF-0710710710710710"
        DisplayName = ""
        Grouping = MANAGED_FIREWALL_GROUP
        Action = 1  # ALLOW: never owned by BC Sentinel v0.7.x
        Enabled = True
        Description = "spoofed rule"

    class OwnedRule:
        Name = "BC Sentinel - BCSF-AAAAAAAAAAAAAAAA"
        DisplayName = ""
        Grouping = MANAGED_FIREWALL_GROUP
        Action = NET_FW_ACTION_BLOCK
        Enabled = True
        Description = "Managed by BC Sentinel; bcsentinel-rule-id=BCSF-AAAAAAAAAAAAAAAA"

    class Policy:
        Rules = [CollisionRule(), OwnedRule()]

    backend = WindowsFirewallBackend()

    @contextmanager
    def fake_policy():
        yield Policy()

    backend._policy = fake_policy
    anomalies = backend.list_group_anomalies(limit=20)
    assert len(anomalies) == 1
    assert anomalies[0]["action"] == 1
    assert "failed closed ownership" in anomalies[0]["reason"]


class _Audit:
    def append(self, record):
        pass


class _Events:
    sequence = 0
    def since(self, seq, limit):
        return []


class _Runtime:
    def __init__(self):
        self.secret = SECRET
        self.events = _Events()
        self.audit_writer = _Audit()
        self.firewall = FirewallManager(InMemoryFirewallBackend())
        self._hardening_status = {"ok": True, "mode": "development"}

    def status(self):
        return {"service": "BCSentinelProtection", "health": "HEALTHY", "firewall": self.firewall.status()}

    def firewall_status(self): return self.firewall.status()
    def firewall_rules(self, limit=200): return self.firewall.list_rules(limit)
    def firewall_drift(self): return self.firewall.drift_report()
    def firewall_reconcile(self, *, approved): return self.firewall.reconcile_drift(approved=approved)
    def firewall_block_remote(self, p):
        return self.firewall.block_remote(
            remote_address=p["remote_address"], direction=p["direction"], protocol=p["protocol"],
            remote_port=p.get("remote_port"), application_path=p.get("application_path", ""),
            reason=p.get("reason", ""), incident_id=p.get("incident_id", ""),
        )
    def firewall_remove_rule(self, rule_id): return self.firewall.remove_rule(rule_id)
    def firewall_set_managed_enabled(self, enabled): return self.firewall.set_managed_enabled(enabled)


def _core():
    core = ProtectionServiceCore(_Runtime(), secret=SECRET)
    core._audit = lambda *args, **kwargs: None
    core._audit_broker = lambda *args, **kwargs: None
    return core


def test_v071_drift_read_is_standard_user_safe_and_reconcile_is_privileged():
    core = _core()
    read = core.dispatch(build_request("firewall_drift", SECRET), STANDARD)
    assert read["ok"] is True and read["drift"]["ok"] is True

    direct = core.dispatch(build_request("firewall_reconcile", SECRET, approved=True), STANDARD)
    assert direct["ok"] is False
    assert direct["error"]["code"] == "admin_required"

    no_approval = core.dispatch(build_request("firewall_reconcile", SECRET, approved=False), ADMIN)
    assert no_approval["ok"] is False
    assert no_approval["error"]["code"] == "approval_required"


def test_v071_permanent_delete_revalidates_sha256_and_snapshot(tmp_path):
    qdir = tmp_path / "quarantine"
    key = tmp_path / "quarantine.key"
    managed = tmp_path / "managed"
    managed.mkdir()
    db = Database(tmp_path / "db.sqlite")
    q = QuarantineManager(db, quarantine_dir=qdir, key_path=key, managed_roots=(managed,))

    victim = tmp_path / "detected.bin"
    victim.write_bytes(b"detected payload")
    digest = hashlib.sha256(victim.read_bytes()).hexdigest()
    removed = q.delete_detected_file(victim, digest)
    assert removed == victim.resolve()
    assert not victim.exists()


def test_v071_permanent_delete_refuses_stale_hash_and_managed_paths(tmp_path):
    qdir = tmp_path / "quarantine"
    key = tmp_path / "quarantine.key"
    managed = tmp_path / "managed"
    managed.mkdir()
    db = Database(tmp_path / "db.sqlite")
    q = QuarantineManager(db, quarantine_dir=qdir, key_path=key, managed_roots=(managed,))

    victim = tmp_path / "changed.bin"
    victim.write_bytes(b"new content")
    with pytest.raises(ValueError, match="identity changed"):
        q.delete_detected_file(victim, "0" * 64)
    assert victim.exists()

    protected = managed / "sentinel-owned.bin"
    protected.write_bytes(b"owned")
    digest = hashlib.sha256(protected.read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="BC Sentinel managed"):
        q.delete_detected_file(protected, digest)
    assert protected.exists()


def test_v071_threat_decision_ui_exposes_safe_explicit_actions():
    source = Path("app/ui/main_window.py").read_text(encoding="utf-8")
    assert 'QPushButton("Quarantena · consigliato")' in source
    assert 'QPushButton("Elimina definitivamente")' in source
    assert 'QPushButton("Mantieni questa volta")' in source
    assert 'QPushButton("Consenti hash")' in source
    assert 'self.quarantine.delete_detected_file(report.path, report.sha256)' in source
    assert 'self.db.add_allowlist("hash", report.sha256)' in source
    assert 'if a.score>=70:' in source
    assert 'if report.assessment.score>=70: self.present_threat(report)' in source
    assert 'explicit_user_decision' in source


def test_v071_version_and_release_artifacts_are_consistent():
    from sentinel.config import APP_VERSION
    assert version_key(APP_VERSION) >= version_key("0.9.0-rc.1")
    assert Path("sentinel/__init__.py").read_text(encoding="utf-8").strip() == f'__version__ = "{APP_VERSION}"'
    assert f'version = "{APP_VERSION.replace("-alpha.", "a").replace("-beta.", "b").replace("-rc.", "rc")}"' in Path("pyproject.toml").read_text(encoding="utf-8")
    assert Path("RELEASE-NOTES-v0.7.2-beta.2.md").exists()
    roadmap = Path("ROADMAP.md").read_text(encoding="utf-8")
    assert "Threat Decision Center" in roadmap
    assert "Mantieni questa volta" in roadmap
    assert "Elimina definitivamente" in roadmap


def test_v071_service_hardening_cycle_monitors_firewall_drift():
    source = Path("sentinel/protection_service_core.py").read_text(encoding="utf-8")
    assert "self._firewall_drift_status = self.firewall.drift_report()" in source
    assert '"inspection_error"' in source


def test_v071_native_drift_acceptance_is_transactional_and_narrow():
    source = Path("tools/firewall_drift_acceptance.py").read_text(encoding="utf-8")
    assert "WindowsFirewallBackend" in source
    assert "rule.Enabled = False" in source
    assert '"firewall_reconcile"' in source
    assert "finally:" in source
    assert 'result["baseline_restored"]' in source
    assert "DefaultInboundAction" not in source
    assert "DefaultOutboundAction" not in source
    assert "netsh" not in source.casefold()


def test_v071_service_allow_hash_uses_privileged_broker_wrapper():
    client = Path("sentinel/protection_client.py").read_text(encoding="utf-8")
    ui = Path("app/ui/main_window.py").read_text(encoding="utf-8")
    assert 'return self._privileged_request("add_exclusion"' in client
    assert 'self.telemetry_client.add_exclusion("hash", report.sha256)' in ui

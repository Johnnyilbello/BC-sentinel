from __future__ import annotations

from pathlib import Path
import hashlib

import pytest

from sentinel.database import Database
from sentinel.firewall_policy import FirewallManager, InMemoryFirewallBackend, build_block_rule
from sentinel.protection_protocol import ClientContext, build_request
from sentinel.protection_service_core import ProtectionRuntime, ProtectionServiceCore
from sentinel.quarantine import QuarantineManager
from sentinel.rate_limit import SlidingWindowRateLimiter
from tools.threat_decision_acceptance import run as run_threat_decision_acceptance
from tools.windows_acceptance import _v071_beta2_security_probe

SECRET = "c" * 64
ADMIN = ClientContext(local=True, authenticated=True, is_admin=True, sid="S-1-5-21-admin", session_id=1, transport="windows_named_pipe", process_id=100)
STANDARD = ClientContext(local=True, authenticated=True, is_admin=False, sid="S-1-5-21-user", session_id=1, transport="windows_named_pipe", process_id=200)


class _Runtime:
    def status(self):
        return {"health": "HEALTHY"}

    def firewall_reconcile(self, *, approved: bool):
        return {"ok": bool(approved), "actions": [], "after": {"ok": bool(approved)}}

    def firewall_status(self):
        return {"available": True, "mode": "memory_test"}

    def firewall_drift(self):
        return {"ok": True, "issues": []}

    def firewall_conflicts(self):
        return {"ok": True, "blocking_conflicts": [], "advisories": []}

    def threat_file_action(self, payload):
        return {"action": payload["action"], "status": "success", "path": payload["path"]}


class _CollisionBackend(InMemoryFirewallBackend):
    def list_group_anomalies(self, *, limit: int = 200):
        return [{"name": "BC Sentinel - forged", "reason": "failed ownership gate"}]


def _core():
    core = ProtectionServiceCore(_Runtime(), secret=SECRET)
    core._audit = lambda *args, **kwargs: None
    core._audit_broker = lambda *args, **kwargs: None
    core._request_limiter = SlidingWindowRateLimiter(clock=lambda: 100.0)
    core._abuse_limiter = SlidingWindowRateLimiter(clock=lambda: 100.0)
    return core


def test_beta2_firewall_mutation_burst_is_rate_limited_without_weakening_approval_gate():
    core = _core()
    responses = [
        core.dispatch(build_request("firewall_reconcile", SECRET, approved=False), ADMIN)
        for _ in range(7)
    ]
    assert all(r["error"]["code"] == "approval_required" for r in responses[:6])
    assert responses[6]["error"]["code"] == "rate_limited"
    assert responses[6]["error"]["retry_after_seconds"] > 0


def test_beta2_invalid_ipc_flood_is_bounded_per_authenticated_context():
    core = _core()
    responses = [core.dispatch_bytes(b"{not-json", STANDARD) for _ in range(25)]
    assert all(r["error"]["code"] == "malformed_json" for r in responses[:24])
    assert responses[24]["error"]["code"] == "rate_limited"


def test_beta2_threat_file_action_is_privileged_and_payload_is_strict(tmp_path):
    core = _core()
    path = str(tmp_path / "sample.bin")
    payload = dict(
        action="quarantine",
        path=path,
        sha256="a" * 64,
        score=100,
        level="CRITICAL",
        reasons=["test signature"],
        approved=True,
    )
    denied = core.dispatch(build_request("threat_file_action", SECRET, **payload), STANDARD)
    assert denied["ok"] is False
    assert denied["error"]["code"] == "admin_required"
    allowed = core.dispatch(build_request("threat_file_action", SECRET, **payload), ADMIN)
    assert allowed["ok"] is True
    assert allowed["result"]["status"] == "success"

    invalid = dict(payload, sha256="not-a-hash")
    rejected = core.dispatch({
        "version": 1,
        "request_id": "bad-threat-action",
        "op": "threat_file_action",
        "token": SECRET,
        "payload": invalid,
    }, ADMIN)
    assert rejected["ok"] is False
    assert rejected["error"]["code"] == "invalid_payload"


def test_beta2_policy_conflicts_separate_advisory_overlap_from_blocking_collision():
    backend = InMemoryFirewallBackend()
    manager = FirewallManager(backend)
    rule = manager.block_remote(remote_address="192.0.2.10", direction="outbound", protocol="any")
    backend.policy_conflicts.append({
        "type": "external_allow_overlap",
        "rule_id": rule["rule_id"],
        "effect": "advisory_only_windows_block_precedence_retained",
    })
    report = manager.policy_conflict_report()
    assert report["ok"] is True
    assert report["advisory_count"] == 1
    assert report["blocking_count"] == 0

    collision_manager = FirewallManager(_CollisionBackend())
    collision = collision_manager.policy_conflict_report()
    assert collision["ok"] is False
    assert collision["blocking_count"] == 1
    assert collision["blocking_conflicts"][0]["type"] == "managed_group_collision"


def test_beta2_exact_duplicate_managed_scopes_are_reported_as_redundant_advisory():
    backend = InMemoryFirewallBackend()
    manager = FirewallManager(backend)
    manager.block_remote(remote_address="192.0.2.20", direction="outbound", protocol="tcp", remote_port=443)
    manager.block_remote(remote_address="192.0.2.20/32", direction="outbound", protocol="tcp", remote_port=443)
    report = manager.policy_conflict_report()
    assert report["ok"] is True
    assert any(item["type"] == "redundant_managed_rule" for item in report["advisories"])


def test_beta2_ui_routes_file_destruction_and_quarantine_through_service_when_owned():
    source = Path("app/ui/main_window.py").read_text(encoding="utf-8")
    assert 'self.telemetry_client.threat_file_action(' in source
    assert '"quarantine",' in source
    assert '"delete",' in source
    assert 'class FirewallAlertDialog' in source
    assert '"rule_drift_detected", "policy_conflict_detected"' in source
    assert "Nessuna regola di terze parti viene modificata automaticamente" in source


def test_beta2_protocol_and_client_expose_conflict_read_and_threat_action():
    protocol = Path("sentinel/protection_protocol.py").read_text(encoding="utf-8")
    client = Path("sentinel/protection_client.py").read_text(encoding="utf-8")
    assert '"firewall_conflicts"' in protocol
    assert '"threat_file_action"' in protocol
    assert 'def firewall_conflicts(self):' in client
    assert 'def threat_file_action(' in client


def test_beta2_windows_com_cleanup_and_conflict_engine_remain_read_only():
    source = Path("sentinel/firewall_windows.py").read_text(encoding="utf-8")
    assert "gc.collect()" in source
    assert "policy = None" in source
    assert "external_allow_overlap" in source
    assert "advisory_only_windows_block_precedence_retained" in source
    assert "DefaultInboundAction" not in source
    assert "DefaultOutboundAction" not in source
    assert "netsh" not in source.casefold()


def test_beta2_harmless_eicar_decision_acceptance_passes():
    result = run_threat_decision_acceptance()
    assert result["passed"] is True
    assert result["detection"]["score"] == 100
    assert result["quarantine"]["source_removed"] is True
    assert result["restore"]["content_verified"] is True
    assert result["delete"]["removed"] is True
    assert result["keep_once"]["allowlist_unchanged"] is True
    assert result["allow_hash"]["original_trusted"] is True
    assert result["allow_hash"]["changed_content_trusted"] is False


def test_beta2_windows_acceptance_contains_side_effect_free_security_gates():
    checks = _v071_beta2_security_probe()
    assert checks
    assert all(item["status"] == "pass" for item in checks)
    names = {item["name"] for item in checks}
    assert "protection-v071-beta2-rate-limit" in names
    assert "firewall-v071-beta2-conflict-engine" in names
    assert "threat-decision-v071-beta2" in names


def test_beta2_runtime_refuses_destructive_threat_endpoint_for_unqualified_detection(tmp_path):
    runtime = ProtectionRuntime.__new__(ProtectionRuntime)
    with pytest.raises(PermissionError, match="HIGH/CRITICAL"):
        runtime.threat_file_action({
            "action": "delete",
            "path": str(tmp_path / "ordinary.bin"),
            "sha256": "a" * 64,
            "score": 69,
            "level": "MEDIUM",
            "reasons": ["weak heuristic"],
            "approved": True,
        })


def test_beta2_permanent_response_refuses_windows_system_tree(monkeypatch, tmp_path):
    windows_root = tmp_path / "Windows"
    windows_root.mkdir()
    victim = windows_root / "System32" / "protected.bin"
    victim.parent.mkdir()
    victim.write_bytes(b"protected system fixture")
    digest = hashlib.sha256(victim.read_bytes()).hexdigest()

    monkeypatch.setenv("WINDIR", str(windows_root))
    monkeypatch.setenv("SystemRoot", str(windows_root))
    db = Database(tmp_path / "db-system-path.sqlite")
    q = QuarantineManager(
        db,
        quarantine_dir=tmp_path / "q-system-path",
        key_path=tmp_path / "q-system-path.key",
        managed_roots=(tmp_path / "managed",),
    )

    with pytest.raises(ValueError, match="protected Windows system tree"):
        q.delete_detected_file(victim, digest)
    assert victim.exists()
    with pytest.raises(ValueError, match="protected Windows system tree"):
        q.quarantine(victim, 100, "test", expected_sha256=digest)
    assert victim.exists()


def test_beta2_threat_dialog_explicitly_recommends_reversible_quarantine():
    source = Path("app/ui/main_window.py").read_text(encoding="utf-8")
    assert "Azione consigliata: Quarantena · reversibile e verificata" in source

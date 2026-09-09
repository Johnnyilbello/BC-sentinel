from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import time

import pytest

from sentinel.config import Settings
from sentinel.database import Database
from sentinel.firewall_policy import FirewallManager, InMemoryFirewallBackend
from sentinel.ioc_denylist import IOCBundleError, SignedIOCVerifier
from sentinel.network_intelligence import NetworkReputationEngine
from sentinel.protection_protocol import ClientContext, build_request
from sentinel.protection_service_core import ProtectionRuntime, ProtectionServiceCore
from sentinel.scanner import StaticScanner
from tools.ioc_acceptance import run as run_ioc_acceptance
from tools.windows_acceptance import _v071_beta3_security_probe

ROOT = Path(__file__).resolve().parents[1]
BUNDLE_PATH = ROOT / "rules" / "ioc-denylist-v1.safe-fixture.json"
SIG_PATH = ROOT / "rules" / "ioc-denylist-v1.safe-fixture.sig"
SECRET = "d" * 64
ADMIN = ClientContext(local=True, authenticated=True, is_admin=True, sid="S-1-5-21-admin", session_id=1, transport="test", process_id=301)
STANDARD = ClientContext(local=True, authenticated=True, is_admin=False, sid="S-1-5-21-user", session_id=1, transport="test", process_id=302)
UNAUTH = ClientContext(local=True, authenticated=False, is_admin=False, sid="", session_id=1, transport="test", process_id=303)


def _fixture():
    return json.loads(BUNDLE_PATH.read_text(encoding="utf-8")), SIG_PATH.read_text(encoding="utf-8").strip()


def _verified():
    bundle, signature = _fixture()
    return SignedIOCVerifier().verify(bundle, signature)



# Unit-level scanner IOC fixture. Do not write the canonical EICAR payload to
# disk here: host AV/minifilter products may quarantine or deny the file between
# write and scan, making this logic test depend on the machine running pytest.
# Signature verification of the shipped EICAR IOC remains covered separately by
# the pinned Ed25519 fixture and tools.ioc_acceptance.
SAFE_SCANNER_IOC_BYTES = b"BC Sentinel harmless signed-IOC scanner fixture v0.7.2-beta.1"


def _scanner_verified_fixture():
    digest = hashlib.sha256(SAFE_SCANNER_IOC_BYTES).hexdigest()
    verified = _verified()
    entries = tuple(
        replace(
            entry,
            value=digest,
            label="Harmless synthetic SHA-256 scanner acceptance indicator",
        ) if entry.kind == "sha256" else entry
        for entry in verified.entries
    )
    synthetic_payload_sha256 = hashlib.sha256(
        b"bcsentinel-unit-safe-scanner-ioc-fixture-v1"
    ).hexdigest()
    return replace(
        verified,
        bundle_id="bcsentinel-unit-safe-scanner-fixture",
        payload_sha256=synthetic_payload_sha256,
        entries=entries,
    ), digest


def _runtime(tmp_path):
    runtime = ProtectionRuntime.__new__(ProtectionRuntime)
    runtime.db = Database(tmp_path / "state.sqlite")
    runtime.firewall = FirewallManager(InMemoryFirewallBackend(), desired_state_store=runtime.db)
    runtime.ioc_verifier = SignedIOCVerifier()
    return runtime


def test_beta3_shipped_safe_ioc_fixture_verifies_with_pinned_key():
    verified = _verified()
    assert verified.sequence == 1
    assert len(verified.entries) == 2
    assert verified.payload_sha256 == "b42fd32ba2f61b03e3b390dc084afdc0b52f0740835e3d27035c6fb8b3900d65"


def test_beta3_signed_ioc_tamper_is_rejected():
    bundle, signature = _fixture()
    bundle["bundle_id"] += ".tampered"
    with pytest.raises(IOCBundleError, match="signature verification failed"):
        SignedIOCVerifier().verify(bundle, signature)


def test_beta3_signed_ioc_expiry_is_fail_closed():
    bundle, signature = _fixture()
    expires = 1830297600.0  # 2028-01-01 UTC, after fixture expiry; signed payload stays unchanged
    with pytest.raises(IOCBundleError, match="expired"):
        SignedIOCVerifier().verify(bundle, signature, now=expires)


def test_beta3_ioc_database_antirollback_and_idempotence(tmp_path):
    db = Database(tmp_path / "db.sqlite")
    verified = _verified()
    first = db.install_ioc_bundle(verified)
    again = db.install_ioc_bundle(verified)
    assert first["installed"] is True
    assert again["idempotent"] is True
    with pytest.raises(ValueError, match="older"):
        db.install_ioc_bundle(replace(verified, sequence=0))
    with pytest.raises(ValueError, match="sequence reuse"):
        db.install_ioc_bundle(replace(verified, payload_sha256="f" * 64))


def test_beta3_signed_ioc_hash_overrides_old_local_hash_allowlist(tmp_path):
    db = Database(tmp_path / "scanner.sqlite")
    verified, digest = _scanner_verified_fixture()
    db.install_ioc_bundle(verified)
    sample = tmp_path / "ioc-scanner-fixture.bin"
    sample.write_bytes(SAFE_SCANNER_IOC_BYTES)
    db.add_allowlist("hash", digest)
    settings = Settings.defaults(); settings.exclude_self = False; settings.reputation_enabled = False
    report = StaticScanner(settings, db=db).scan_file(sample)
    assert report.sha256 == digest
    assert report.assessment.level == "CRITICAL"
    assert any(signal.key == "signed_ioc_sha256" for signal in report.assessment.signals)


def test_beta3_scanner_refreshes_ioc_map_immediately_on_database_revision(tmp_path):
    db = Database(tmp_path / "revision.sqlite")
    settings = Settings.defaults(); settings.exclude_self = False; settings.reputation_enabled = False
    scanner = StaticScanner(settings, db=db)
    assert scanner._ioc_hashes == {}
    verified, digest = _scanner_verified_fixture()
    db.install_ioc_bundle(verified)
    sample = tmp_path / "ioc-after-feed.bin"
    sample.write_bytes(SAFE_SCANNER_IOC_BYTES)
    report = scanner.scan_file(sample)
    assert report.sha256 == digest
    assert any(signal.key == "signed_ioc_sha256" for signal in report.assessment.signals)
    assert scanner._ioc_revision_seen == db.ioc_revision


def test_beta3_signed_network_ioc_has_precedence_in_network_reputation(tmp_path):
    db = Database(tmp_path / "network.sqlite")
    db.install_ioc_bundle(_verified())
    result = NetworkReputationEngine(db).assess_endpoint("192.0.2.240")
    assert result.status == "malicious"
    assert result.source == "signed_ioc"
    assert result.score_delta == 70


def test_beta3_containment_requires_signed_ioc_or_verified_incident(tmp_path):
    runtime = _runtime(tmp_path)
    with pytest.raises(PermissionError, match="signed IOC or a verified incident"):
        runtime.create_containment_lease({
            "remote_address": "198.51.100.44", "ttl_seconds": 60,
            "reason": "unqualified", "incident_id": "", "approved": True,
        })
    assert runtime.firewall.list_rules(100) == []


def test_beta3_signed_ioc_qualifies_reversible_containment_lease(tmp_path):
    runtime = _runtime(tmp_path)
    runtime.db.install_ioc_bundle(_verified())
    lease = runtime.create_containment_lease({
        "remote_address": "192.0.2.240", "ttl_seconds": 60,
        "reason": "signed IOC containment", "incident_id": "", "approved": True,
    })
    assert lease["status"] == "active"
    assert len(runtime.firewall.list_rules(100)) == 1
    assert any(row["lease_id"] == lease["lease_id"] for row in runtime.containment_leases())
    released = runtime.release_containment_lease(lease["lease_id"], approved=True)
    assert released["status"] == "released"
    assert runtime.firewall.list_rules(100) == []


def test_beta3_expired_lease_is_removed_by_runtime_expiry(tmp_path):
    runtime = _runtime(tmp_path)
    runtime.db.install_ioc_bundle(_verified())
    lease = runtime.create_containment_lease({
        "remote_address": "192.0.2.240", "ttl_seconds": 60,
        "reason": "expiry simulation", "incident_id": "", "approved": True,
    })
    runtime.db.execute("UPDATE containment_leases SET expires_at=? WHERE lease_id=?", (time.time() - 1, lease["lease_id"]))
    expired = runtime.expire_containment_leases()
    assert expired and expired[0]["release_reason"] == "ttl_expired"
    assert runtime.firewall.list_rules(100) == []


class _Events:
    sequence = 0
    def since(self, seq, limit): return []


class _ProtocolRuntime:
    def __init__(self): self.events = _Events()
    def status(self): return {"health": "HEALTHY"}
    def import_ioc_bundle(self, payload): return {"sequence": payload["bundle"]["sequence"], "status": {"active_entries": 2}}
    def acknowledge_threat_decision(self, sha256, action, detail=""): return {"sha256": sha256, "action": action}


def _core():
    core = ProtectionServiceCore(_ProtocolRuntime(), secret=SECRET)
    core._audit = lambda *a, **k: None
    core._audit_broker = lambda *a, **k: None
    return core


def test_beta3_ioc_import_is_privileged_protocol_operation():
    bundle, signature = _fixture()
    denied = _core().dispatch(build_request("ioc_import", SECRET, bundle=bundle, signature=signature, approved=True), STANDARD)
    assert denied["ok"] is False
    assert denied["error"]["code"] == "admin_required"


def test_beta3_threat_decision_ack_requires_authenticated_local_identity_but_not_admin():
    payload = dict(sha256="a" * 64, action="allowed_once", detail="known file")
    unauth = _core().dispatch(build_request("threat_decision_ack", SECRET, **payload), UNAUTH)
    assert unauth["ok"] is False and unauth["error"]["code"] == "unauthorized"
    standard = _core().dispatch(build_request("threat_decision_ack", SECRET, **payload), STANDARD)
    assert standard["ok"] is True


def test_beta3_security_center_pending_detection_is_resolved_only_by_explicit_action(tmp_path):
    db = Database(tmp_path / "inbox.sqlite")
    digest = "b" * 64
    db.add_detection("C:/Temp/pending.exe", digest, 91, "HIGH", '["test"]', "logged", dedupe_minutes=0)
    assert any(row["sha256"] == digest for row in db.pending_threat_decisions())
    db.update_detection_action(digest, "allowed_once")
    assert not any(row["sha256"] == digest for row in db.pending_threat_decisions())


def test_beta3_gui_contains_persistent_security_center_and_signed_ioc_import():
    source = (ROOT / "app" / "ui" / "main_window.py").read_text(encoding="utf-8")
    for text in ["Security Center Inbox", "Gestisci minaccia", "pending_threats", "Threat Intelligence firmata", "Importa IOC firmati…", "import_ioc_bundle"]:
        assert text in source


def test_beta3_windows_firewall_com_enumeration_is_materialized_before_release():
    source = (ROOT / "sentinel" / "firewall_windows.py").read_text(encoding="utf-8")
    acceptance = (ROOT / "tools" / "firewall_drift_acceptance.py").read_text(encoding="utf-8")
    assert "def _materialized_rules" in source
    assert "for rule in policy.Rules" not in source
    assert "with backend._materialized_rules(policy) as rules" in acceptance


def test_beta3_small_file_yara_reuses_in_memory_content_and_benchmark_profiles_phases():
    scanner = (ROOT / "sentinel" / "scanner.py").read_text(encoding="utf-8")
    benchmark = (ROOT / "tools" / "security_benchmark.py").read_text(encoding="utf-8")
    assert "self.yara.scan_data(head)" in scanner
    assert '"phase_profile"' in benchmark
    assert "deterministic content reinspection" in benchmark


def test_beta3_safe_ioc_acceptance_passes_locally():
    result = run_ioc_acceptance(native_service=False)
    assert result["passed"] is True
    assert result["signature_verified"] is True
    assert result["tamper_rejected"] is True


def test_beta3_windows_acceptance_contains_new_side_effect_free_gates():
    checks = _v071_beta3_security_probe()
    assert checks and all(item["status"] == "pass" for item in checks)
    names = {item["name"] for item in checks}
    assert names == {
        "ioc-v071-beta3-signed-feed",
        "containment-v071-beta3-lease-safety",
        "security-center-v071-beta3-inbox",
    }

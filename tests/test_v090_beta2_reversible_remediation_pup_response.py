from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel.service_update import version_key
from sentinel.antispyware import PersistenceEntry, assess_persistence_entry
from sentinel.antispyware_remediation import (
    AntispywareRemediationManager,
    RemediationConflict,
    UnsupportedRemediation,
    SUPPORTED_REMEDIATION_KINDS,
)
from sentinel.database import Database
from sentinel.protection_protocol import PRIVILEGED_OPERATIONS, READ_OPERATIONS, ProtocolError, validate_request


class FakeRemediationBackend:
    def __init__(self):
        self.state: dict[str, bool] = {}
        self.conflict = False

    @staticmethod
    def supported() -> bool:
        return True

    def capture(self, finding: dict):
        key = str(finding["finding_id"])
        self.state.setdefault(key, True)
        return {
            "backend": "fake",
            "key": key,
            "value": str(finding.get("command") or ""),
        }

    def apply(self, snapshot: dict, *, vault_dir: Path, plan_id: str):
        if self.conflict:
            raise RemediationConflict("simulated race")
        key = str(snapshot["key"])
        if not self.state.get(key):
            raise RemediationConflict("already disabled")
        self.state[key] = False
        return {"disabled": True, "mutation": "fake_disable"}

    def restore(self, snapshot: dict, *, vault_dir: Path, plan_id: str):
        if self.conflict:
            raise RemediationConflict("simulated restore race")
        key = str(snapshot["key"])
        if self.state.get(key):
            return {"restored": True, "already_restored": True}
        self.state[key] = True
        return {"restored": True, "mutation": "fake_restore"}


def _req(op: str, **payload):
    return {"version": 1, "request_id": "v090b2-test", "op": op, "token": "a" * 64, "payload": payload}


def _suspicious(db: Database, *, kind: str = "registry_run") -> str:
    entry = PersistenceEntry(
        kind=kind,
        location=r"HKU\S-1-5-21-1-2-3-1001\Software\Microsoft\Windows\CurrentVersion\Run",
        name="BCS090B2Fixture",
        command="powershell.exe -EncodedCommand QkNTMDkwQjJfRklYVFVSRQ==",
        target_path=r"C:\Users\demo\AppData\Local\Temp\bcs090b2.ps1",
        target_exists=True,
        user_writable=True,
        signature_status="NotSigned",
        metadata={"harmless_fixture": True},
    )
    assessment = assess_persistence_entry(entry)
    assert assessment.score >= 50
    return str(db.record_antispyware_finding(assessment)["finding_id"])


def test_v090b2_plan_is_hmac_authenticated_and_requires_explicit_approval(tmp_path):
    db = Database(tmp_path / "sentinel.sqlite")
    backend = FakeRemediationBackend()
    finding_id = _suspicious(db)
    manager = AntispywareRemediationManager(
        db, integrity_key=b"r" * 32, vault_dir=tmp_path / "vault", backend=backend
    )
    plan = manager.create_plan(finding_id)
    assert plan["integrity_verified"] is True
    assert plan["status"] == "planned"
    assert plan["explicit_approval_required"] is True
    with pytest.raises(PermissionError):
        manager.apply(plan["plan_id"], approved=False)
    applied = manager.apply(plan["plan_id"], approved=True)
    assert applied["status"] == "applied"
    assert backend.state[finding_id] is False
    restored = manager.restore(plan["plan_id"], approved=True)
    assert restored["status"] == "restored"
    assert backend.state[finding_id] is True
    assert db.get_antispyware_finding(finding_id)["status"] == "restored"


def test_v090b2_plan_tamper_is_rejected_before_mutation(tmp_path):
    db = Database(tmp_path / "sentinel.sqlite")
    backend = FakeRemediationBackend()
    finding_id = _suspicious(db)
    manager = AntispywareRemediationManager(
        db, integrity_key=b"t" * 32, vault_dir=tmp_path / "vault", backend=backend
    )
    plan = manager.create_plan(finding_id)
    with db.connect() as con:
        row = con.execute("SELECT snapshot_json FROM antispyware_remediation_plans WHERE plan_id=?", (plan["plan_id"],)).fetchone()
        payload = json.loads(row[0])
        payload["value"] = "tampered"
        con.execute(
            "UPDATE antispyware_remediation_plans SET snapshot_json=? WHERE plan_id=?",
            (json.dumps(payload, sort_keys=True), plan["plan_id"]),
        )
    with pytest.raises(RemediationConflict, match="integrity"):
        manager.apply(plan["plan_id"], approved=True)
    assert backend.state[finding_id] is True


def test_v090b2_race_conflict_fails_closed_and_keeps_plan_unapplied(tmp_path):
    db = Database(tmp_path / "sentinel.sqlite")
    backend = FakeRemediationBackend()
    finding_id = _suspicious(db)
    manager = AntispywareRemediationManager(
        db, integrity_key=b"u" * 32, vault_dir=tmp_path / "vault", backend=backend
    )
    plan = manager.create_plan(finding_id)
    backend.conflict = True
    with pytest.raises(RemediationConflict):
        manager.apply(plan["plan_id"], approved=True)
    assert manager.plan(plan["plan_id"])["status"] == "planned"
    assert backend.state[finding_id] is True


def test_v090b2_review_only_wmi_is_not_mutated(tmp_path):
    db = Database(tmp_path / "sentinel.sqlite")
    entry = PersistenceEntry(
        "wmi_subscription", "root/subscription", "FixtureConsumer",
        command="powershell.exe -EncodedCommand AAAA",
        target_path=r"C:\Users\demo\AppData\Local\Temp\fixture.ps1",
        target_exists=True, user_writable=True, signature_status="NotSigned",
    )
    finding_id = str(db.record_antispyware_finding(assess_persistence_entry(entry))["finding_id"])
    manager = AntispywareRemediationManager(
        db, integrity_key=b"v" * 32, vault_dir=tmp_path / "vault", backend=FakeRemediationBackend()
    )
    with pytest.raises(UnsupportedRemediation):
        manager.create_plan(finding_id)


def test_v090b2_pup_browser_policy_is_candidate_but_never_auto_malware():
    entry = PersistenceEntry(
        "browser_policy",
        r"HKLM\Software\Policies\Google\Chrome\ExtensionInstallForcelist",
        "1",
        command="abcdefghijklmnopabcdefghijklmnop;https://updates.example.test/extension.xml",
        metadata={"browser": "chrome", "harmless_fixture": True},
    )
    result = assess_persistence_entry(entry)
    assert result.pup_adware_candidate is True
    assert result.classification == "pup_adware_candidate"
    assert result.score >= 25
    assert result.score < 70
    assert result.remediation == "reversible_plan_recommended"
    assert result.automatic_destructive_action is False


def test_v090b2_supported_remediation_excludes_nonreversible_surfaces():
    assert {"registry_run", "registry_runonce", "startup", "scheduled_task", "service_auto", "browser_policy"}.issubset(SUPPORTED_REMEDIATION_KINDS)
    assert "wmi_subscription" not in SUPPORTED_REMEDIATION_KINDS
    assert "proxy_config" not in SUPPORTED_REMEDIATION_KINDS
    assert "dns_config" not in SUPPORTED_REMEDIATION_KINDS


def test_v090b2_protocol_separates_plan_read_from_privileged_apply_restore():
    assert "antispyware_remediation_plan" in READ_OPERATIONS
    assert "antispyware_remediation_plans" in READ_OPERATIONS
    assert "antispyware_remediation_apply" in PRIVILEGED_OPERATIONS
    assert "antispyware_remediation_restore" in PRIVILEGED_OPERATIONS
    plan_req = validate_request(_req("antispyware_remediation_plan", finding_id="BCP-" + "A" * 20))
    assert plan_req.payload["finding_id"].startswith("BCP-")
    apply_req = validate_request(_req("antispyware_remediation_apply", plan_id="BCR-" + "B" * 20, approved=True))
    assert apply_req.payload["approved"] is True
    broker_req = validate_request(_req(
        "prepare_privileged_action",
        action="antispyware_remediation_apply",
        payload={"plan_id": "BCR-" + "C" * 20, "approved": True},
    ))
    assert broker_req.payload["action"] == "antispyware_remediation_apply"
    with pytest.raises(ProtocolError):
        validate_request(_req("antispyware_remediation_apply", plan_id="bad", approved=True))


def test_v090b2_loaded_user_hive_inventory_is_explicit_in_collector_source():
    source = Path("sentinel/antispyware.py").read_text(encoding="utf-8")
    assert "HKEY_USERS" in source
    assert "user_sid" in source
    assert "S-1-5-21-" in source


def test_v090b2_database_plan_summary_and_result_persistence(tmp_path):
    db = Database(tmp_path / "sentinel.sqlite")
    backend = FakeRemediationBackend()
    finding_id = _suspicious(db)
    manager = AntispywareRemediationManager(
        db, integrity_key=b"w" * 32, vault_dir=tmp_path / "vault", backend=backend
    )
    plan = manager.create_plan(finding_id)
    assert db.antispyware_remediation_summary() == {"total": 1, "planned": 1, "applied": 0, "restored": 0}
    manager.apply(plan["plan_id"], approved=True)
    assert db.antispyware_remediation_summary()["applied"] == 1
    row = db.get_antispyware_remediation_plan(plan["plan_id"])
    result = json.loads(row["result_json"])
    assert result["disabled"] is True


def test_v090b2_version_and_acceptance_artifacts_present():
    from sentinel.config import APP_VERSION
    root = Path(__file__).resolve().parents[1]
    assert version_key(APP_VERSION) >= version_key("0.9.0-rc.1")
    assert (root / "sentinel" / "__init__.py").read_text(encoding="utf-8").strip() == f'__version__ = "{APP_VERSION}"'
    assert f'version = "{APP_VERSION.replace("-alpha.", "a").replace("-beta.", "b").replace("-rc.", "rc")}"' in (root / "pyproject.toml").read_text(encoding="utf-8")
    assert (root / "RELEASE-NOTES-v0.9.0-beta.3.md").exists()
    assert (root / "tools" / "antispyware_remediation_acceptance.py").exists()
    windows = (root / "tools" / "windows_acceptance.py").read_text(encoding="utf-8")
    assert "antispyware-v090-beta2-foundation" in windows
    assert "antispyware-v090-beta2-live" in windows

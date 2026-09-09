from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path

from sentinel.antispyware import PersistenceEntry, assess_persistence_entry
from sentinel.antispyware_remediation import (
    AntispywareRemediationManager,
    RemediationConflict,
    UnsupportedRemediation,
    WindowsRemediationBackend,
)
from sentinel.config import APP_VERSION
from sentinel.database import Database
from sentinel.protection_client import ProtectionServiceClient
from sentinel.protection_protocol import PRIVILEGED_OPERATIONS, READ_OPERATIONS


class _FakeBackend:
    def __init__(self):
        self.enabled = True
        self.conflict = False

    @staticmethod
    def supported() -> bool:
        return True

    def capture(self, finding: dict):
        return {"backend": "fake", "finding_id": str(finding["finding_id"]), "value": str(finding.get("command") or "")}

    def apply(self, snapshot: dict, *, vault_dir: Path, plan_id: str):
        if self.conflict:
            raise RemediationConflict("simulated race")
        if not self.enabled:
            raise RemediationConflict("already disabled")
        self.enabled = False
        return {"disabled": True, "mutation": "fake_disable"}

    def restore(self, snapshot: dict, *, vault_dir: Path, plan_id: str):
        if self.conflict:
            raise RemediationConflict("simulated race")
        self.enabled = True
        return {"restored": True, "mutation": "fake_restore"}


def _record_fixture(db: Database, *, kind: str = "registry_run") -> str:
    entry = PersistenceEntry(
        kind,
        r"HKU\S-1-5-21-1-2-3-1001\Software\Microsoft\Windows\CurrentVersion\Run",
        "BCS090B2HarmlessFixture",
        command="powershell.exe -EncodedCommand QkNTMDkwQjJfSEFSTUxFU1M=",
        target_path=r"C:\Users\Acceptance\AppData\Local\Temp\bcs090b2.ps1",
        target_exists=True,
        user_writable=True,
        signature_status="NotSigned",
        metadata={"harmless_fixture": True},
    )
    assessment = assess_persistence_entry(entry)
    return str(db.record_antispyware_finding(assessment)["finding_id"])


def _native_registry_probe() -> dict:
    result = {
        "supported": os.name == "nt",
        "created": False,
        "plan_created": False,
        "disabled": False,
        "restored": False,
        "cleanup": False,
        "error": "",
    }
    if os.name != "nt":
        return result
    import winreg

    key_path = r"Software\BCSentinelAcceptance\v090b2"
    value_name = "HarmlessFixture"
    value_data = r"C:\Users\Acceptance\AppData\Local\Temp\BCS090B2-harmless.exe"
    try:
        key = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ | winreg.KEY_WRITE)
        with key:
            winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, value_data)
        result["created"] = True
        with tempfile.TemporaryDirectory(prefix="bcs-v090b2-native-remediation-") as tmp:
            db = Database(Path(tmp) / "sentinel.sqlite")
            entry = PersistenceEntry(
                "registry_run", "HKCU\\" + key_path, value_name,
                command=value_data, target_path=value_data, target_exists=False,
                user_writable=True, signature_status="NotSigned", metadata={"harmless_fixture": True},
            )
            finding = db.record_antispyware_finding(assess_persistence_entry(entry))
            manager = AntispywareRemediationManager(
                db, integrity_key=b"n" * 32, vault_dir=Path(tmp) / "vault",
                backend=WindowsRemediationBackend(command_timeout=5.0),
            )
            plan = manager.create_plan(str(finding["finding_id"]))
            result["plan_created"] = bool(plan.get("integrity_verified"))
            manager.apply(plan["plan_id"], approved=True)
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_QUERY_VALUE) as check:
                    winreg.QueryValueEx(check, value_name)
                result["disabled"] = False
            except FileNotFoundError:
                result["disabled"] = True
            manager.restore(plan["plan_id"], approved=True)
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_QUERY_VALUE) as check:
                restored, reg_type = winreg.QueryValueEx(check, value_name)
            result["restored"] = restored == value_data and reg_type == winreg.REG_SZ
    except Exception as exc:
        result["error"] = str(exc)[:500]
    finally:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
                try:
                    winreg.DeleteValue(key, value_name)
                except FileNotFoundError:
                    pass
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key_path)
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, r"Software\BCSentinelAcceptance")
            except OSError:
                pass
            result["cleanup"] = True
        except Exception:
            pass
    return result


def run(*, service_live: bool = False) -> dict:
    with tempfile.TemporaryDirectory(prefix="bcs-v090b2-remediation-") as tmp:
        root = Path(tmp)
        db = Database(root / "sentinel.sqlite")
        backend = _FakeBackend()
        finding_id = _record_fixture(db)
        manager = AntispywareRemediationManager(
            db, integrity_key=b"k" * 32, vault_dir=root / "vault", backend=backend
        )
        plan = manager.create_plan(finding_id)
        approval_rejected = False
        try:
            manager.apply(plan["plan_id"], approved=False)
        except PermissionError:
            approval_rejected = True
        applied = manager.apply(plan["plan_id"], approved=True)
        restored = manager.restore(plan["plan_id"], approved=True)
        summary = db.antispyware_remediation_summary()

        # HMAC tamper probe on a second plan.
        second_id = _record_fixture(db, kind="registry_runonce")
        second = manager.create_plan(second_id)
        with db.connect() as con:
            con.execute(
                "UPDATE antispyware_remediation_plans SET snapshot_json=? WHERE plan_id=?",
                ('{"backend":"fake","tampered":true}', second["plan_id"]),
            )
        tamper_rejected = False
        try:
            manager.apply(second["plan_id"], approved=True)
        except RemediationConflict:
            tamper_rejected = True

        # Race probe using an untampered third plan.
        third_entry = PersistenceEntry(
            "registry_run", "HKU\\S-1-5-21-1-2-3-1002\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "BCS090B2RaceFixture",
            command="powershell.exe -EncodedCommand UkFDRQ==",
            target_path=r"C:\Users\Acceptance\AppData\Local\Temp\race.ps1",
            target_exists=True, user_writable=True, signature_status="NotSigned",
        )
        third = db.record_antispyware_finding(assess_persistence_entry(third_entry))
        backend2 = _FakeBackend()
        manager2 = AntispywareRemediationManager(
            db, integrity_key=b"k" * 32, vault_dir=root / "vault2", backend=backend2
        )
        third_plan = manager2.create_plan(str(third["finding_id"]))
        backend2.conflict = True
        race_rejected = False
        try:
            manager2.apply(third_plan["plan_id"], approved=True)
        except RemediationConflict:
            race_rejected = True

        review_only = False
        wmi = PersistenceEntry(
            "wmi_subscription", "root/subscription", "Fixture",
            command="powershell.exe -EncodedCommand V01J", target_path=r"C:\Users\Acceptance\AppData\Local\Temp\wmi.ps1",
            target_exists=True, user_writable=True, signature_status="NotSigned",
        )
        wmi_id = str(db.record_antispyware_finding(assess_persistence_entry(wmi))["finding_id"])
        try:
            manager.create_plan(wmi_id)
        except UnsupportedRemediation:
            review_only = True

    pup_entry = PersistenceEntry(
        "browser_policy",
        r"HKLM\Software\Policies\Google\Chrome\ExtensionInstallForcelist",
        "1",
        command="abcdefghijklmnopabcdefghijklmnop;https://updates.example.test/extension.xml",
        metadata={"browser": "chrome", "harmless_fixture": True},
    )
    pup = assess_persistence_entry(pup_entry)
    native = _native_registry_probe()

    result = {
        "product": "BC Sentinel",
        "version": APP_VERSION,
        "harmless_fixture": True,
        "service_live_requested": bool(service_live),
        "reversible_plan": {
            "integrity_verified": bool(plan.get("integrity_verified")),
            "hmac": "HMAC-SHA256",
            "explicit_approval_rejected": approval_rejected,
            "applied": applied.get("status") == "applied",
            "restored": restored.get("status") == "restored",
            "automatic_action": False,
            "summary": summary,
        },
        "safety": {
            "tamper_rejected": tamper_rejected,
            "race_rejected": race_rejected,
            "wmi_review_only": review_only,
            "automatic_registry_delete": False,
            "automatic_task_delete": False,
            "automatic_service_delete": False,
            "automatic_wmi_delete": False,
            "service_process_termination": False,
        },
        "pup_adware": {
            "candidate": pup.pup_adware_candidate,
            "classification": pup.classification,
            "score": pup.score,
            "below_high": pup.score < 70,
            "reversible_plan_recommended": pup.remediation == "reversible_plan_recommended",
            "automatic_destructive_action": pup.automatic_destructive_action,
        },
        "protocol": {
            "plan_read_only_surface": "antispyware_remediation_plan" in READ_OPERATIONS,
            "list_read_only_surface": "antispyware_remediation_plans" in READ_OPERATIONS,
            "apply_privileged": "antispyware_remediation_apply" in PRIVILEGED_OPERATIONS,
            "restore_privileged": "antispyware_remediation_restore" in PRIVILEGED_OPERATIONS,
            "one_action_uac_compatible": True,
        },
        "native_registry_probe": native,
    }
    native_ok = (not native["supported"]) or all([
        native["created"], native["plan_created"], native["disabled"], native["restored"], native["cleanup"], not native["error"],
    ])
    local_ok = all([
        result["reversible_plan"]["integrity_verified"],
        result["reversible_plan"]["explicit_approval_rejected"],
        result["reversible_plan"]["applied"],
        result["reversible_plan"]["restored"],
        result["safety"]["tamper_rejected"],
        result["safety"]["race_rejected"],
        result["safety"]["wmi_review_only"],
        result["pup_adware"]["candidate"],
        result["pup_adware"]["below_high"],
        result["pup_adware"]["automatic_destructive_action"] is False,
        result["protocol"]["apply_privileged"],
        result["protocol"]["restore_privileged"],
        native_ok,
    ])
    result["local_foundation_passed"] = bool(local_ok)

    service_status = None
    service_live_passed = None
    if service_live:
        client = ProtectionServiceClient(timeout=3.0)
        service_status = client.antispyware_status()
        remediation = (service_status or {}).get("remediation") if isinstance(service_status, dict) else None
        service_live_passed = bool(
            isinstance(service_status, dict)
            and isinstance(remediation, dict)
            and service_status.get("supported") is True
            and remediation.get("mode") == "explicit_reversible"
            and remediation.get("automatic_remediation") is False
            and remediation.get("automatic_destructive_action") is False
            and remediation.get("explicit_approval_required") is True
            and remediation.get("one_action_uac_compatible") is True
            and remediation.get("plan_integrity") == "HMAC-SHA256"
            and remediation.get("anti_race_snapshot_verification") is True
            and remediation.get("service_process_termination") is False
            and "registry_run" in (remediation.get("supported_kinds") or [])
            and "wmi_subscription" in (remediation.get("review_only_kinds") or [])
            and service_status.get("pup_adware_response") == "review_or_explicit_reversible_plan"
        )
    result["service"] = service_status
    result["service_live_passed"] = service_live_passed
    result["passed"] = bool(local_ok and (not service_live or service_live_passed))
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel v0.9 Beta2 reversible antispyware remediation acceptance")
    parser.add_argument("--service-live", action="store_true")
    parser.add_argument("--output", default="")
    args = parser.parse_args()
    result = run(service_live=bool(args.service_live))
    text = json.dumps(result, indent=2, ensure_ascii=False)
    print(text)
    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
    return 0 if result.get("passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())

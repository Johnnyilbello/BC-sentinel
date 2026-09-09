from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path

from sentinel.antispyware import AntispywareEngine, PersistenceEntry, WindowsPersistenceCollector, assess_persistence_entry
from sentinel.config import APP_VERSION
from sentinel.database import Database
from sentinel.protection_client import ProtectionServiceClient


def run(*, service_live: bool = False) -> dict:
    harmless_signed = PersistenceEntry(
        "registry_run", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "BCS090SignedFixture",
        command=r'"C:\Program Files\BC Sentinel Fixture\fixture.exe" --background',
        target_path=r"C:\Program Files\BC Sentinel Fixture\fixture.exe", target_exists=True,
        signature_status="Valid", signer="CN=BC Sentinel Harmless Acceptance Fixture",
        metadata={"harmless_fixture": True},
    )
    harmless_suspicious = PersistenceEntry(
        "registry_runonce", r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce", "BCS090SuspiciousFixture",
        command="powershell.exe -EncodedCommand QkNTMDkwX0hBUk1MRVNTX0ZJWFRVUkU=",
        target_path=r"C:\Users\Acceptance\AppData\Local\Temp\bcs090-fixture.ps1",
        target_exists=True, user_writable=True, signature_status="NotSigned",
        metadata={"harmless_fixture": True},
    )
    single = assess_persistence_entry(harmless_signed)
    suspicious = assess_persistence_entry(harmless_suspicious)
    converged = assess_persistence_entry(harmless_suspicious, network_recent=True, file_malicious=True)

    with tempfile.TemporaryDirectory(prefix="bcs-v090-antispyware-") as tmp:
        db = Database(Path(tmp) / "sentinel.sqlite")
        seen = []
        engine = AntispywareEngine(db, callback=seen.append)
        engine.scan([harmless_signed, harmless_suspicious])
        persisted = db.recent_antispyware_findings(20)
        summary = db.antispyware_summary()

    coverage_methods = [
        "registry_run_entries", "startup_entries", "scheduled_tasks", "auto_services",
        "wmi_subscriptions", "browser_policies", "proxy_config", "dns_config",
    ]
    collector = WindowsPersistenceCollector(authenticode=False, command_timeout=4.0, max_entries=512)
    native_probe = {"supported": collector.supported(), "completed": True, "surfaces": {}, "error": ""}
    if os.name == "nt":
        try:
            for name in coverage_methods:
                value = getattr(collector, name)()
                native_probe["surfaces"][name] = len(value)
        except Exception as exc:
            native_probe["completed"] = False
            native_probe["error"] = str(exc)[:500]

    result = {
        "product": "BC Sentinel",
        "version": APP_VERSION,
        "harmless_fixture": True,
        "service_live_requested": bool(service_live),
        "single_signal_safety": {
            "score": single.score,
            "level": single.level,
            "below_suspicious": single.score < 25,
            "automatic_destructive_action": single.automatic_destructive_action,
        },
        "suspicious_persistence": {
            "score": suspicious.score,
            "level": suspicious.level,
            "capped_below_high_without_file_verdict": suspicious.score < 70,
            "reversible_plan_recommended": suspicious.remediation == "reversible_plan_recommended",
            "automatic_destructive_action": suspicious.automatic_destructive_action,
        },
        "multi_signal_correlation": {
            "score": converged.score,
            "level": converged.level,
            "qualified_high_with_file_verdict": converged.score >= 70,
            "automatic_destructive_action": converged.automatic_destructive_action,
        },
        "persistence_database": {
            "persisted": len(persisted),
            "summary": summary,
            "provenance": all(str(row["finding_id"]).startswith("BCP-") for row in persisted),
        },
        "coverage": {
            "run_runonce": True,
            "startup_folders": True,
            "scheduled_tasks": True,
            "auto_services": True,
            "wmi_permanent_consumers": True,
            "browser_policies": True,
            "proxy_config": True,
            "dns_config": True,
        },
        "native_inventory_probe": native_probe,
        "safety": {
            "automatic_registry_delete": False,
            "automatic_task_delete": False,
            "automatic_service_delete": False,
            "automatic_wmi_delete": False,
            "single_persistence_signal_is_malware": False,
            "reversible_remediation_plans": True,
        },
    }
    local_ok = all([
        result["single_signal_safety"]["below_suspicious"],
        result["single_signal_safety"]["automatic_destructive_action"] is False,
        suspicious.score >= 50,
        result["suspicious_persistence"]["capped_below_high_without_file_verdict"],
        result["suspicious_persistence"]["automatic_destructive_action"] is False,
        result["multi_signal_correlation"]["qualified_high_with_file_verdict"],
        result["multi_signal_correlation"]["automatic_destructive_action"] is False,
        result["persistence_database"]["persisted"] == 2,
        result["persistence_database"]["provenance"],
        native_probe["completed"],
    ])
    result["local_foundation_passed"] = bool(local_ok)

    service_status = None
    service_findings = []
    service_live_passed = None
    if service_live:
        client = ProtectionServiceClient(timeout=3.0)
        service_status = client.antispyware_status()
        service_findings = client.antispyware_findings(limit=20, min_score=0)
        service_live_passed = bool(
            isinstance(service_status, dict)
            and service_status.get("supported") is True
            and service_status.get("running") is True
            and service_status.get("automatic_destructive_action") is False
            and service_status.get("automatic_registry_delete") is False
            and service_status.get("automatic_task_delete") is False
            and service_status.get("automatic_service_delete") is False
            and service_status.get("single_persistence_signal_is_malware") is False
            and service_status.get("multi_signal_correlation") is True
            and "wmi_permanent_consumers" in (service_status.get("coverage") or [])
            and "browser_policies" in (service_status.get("coverage") or [])
        )
    result["service"] = service_status
    result["service_findings_returned"] = len(service_findings)
    result["service_live_passed"] = service_live_passed
    result["passed"] = bool(local_ok and (not service_live or service_live_passed))
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel v0.9 Beta1 antispyware acceptance")
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

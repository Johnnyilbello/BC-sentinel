from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from pathlib import Path

from sentinel.rescue_offline_scanner import OfflineScanLimits, PROFILE, scan_offline_windows


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _make_offline_fixture(base: Path) -> tuple[Path, Path]:
    root = base / "offline-target"
    config = root / "Windows" / "System32" / "config"
    config.mkdir(parents=True)
    (config / "SYSTEM").write_bytes(b"RR3-SYSTEM-HIVE")
    (config / "SOFTWARE").write_bytes(b"RR3-SOFTWARE-HIVE")
    system32 = root / "Windows" / "System32"
    (system32 / "ntoskrnl.exe").write_bytes(b"MZ harmless RR3 kernel fixture")
    drivers = system32 / "drivers"
    drivers.mkdir()
    marker = drivers / "rr3-ioc-fixture.sys"
    marker.write_bytes(b"RR3 harmless deterministic IOC fixture")
    startup = root / "Users" / "Alice" / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
    startup.mkdir(parents=True)
    (startup / "harmless-startup.ps1").write_text("Write-Output 'RR3 harmless startup fixture'", encoding="utf-8")
    temp_dir = root / "Users" / "Alice" / "AppData" / "Local" / "Temp"
    temp_dir.mkdir(parents=True)
    (temp_dir / "invoice.pdf.exe").write_bytes(b"MZ harmless double-extension fixture")
    (root / "Users" / "Alice" / "NTUSER.DAT").write_bytes(b"RR3-NTUSER-HIVE")
    return root, marker


def run_acceptance() -> dict:
    with tempfile.TemporaryDirectory(prefix="bcs-rr3-") as tmp:
        base = Path(tmp)
        root, marker = _make_offline_fixture(base)
        before = {str(p.relative_to(root)): _sha(p) for p in root.rglob("*") if p.is_file()}
        catalog = base / "intel.json"
        catalog.write_text(
            json.dumps(
                {
                    "schema": "bc-sentinel-offline-intel-v1",
                    "approved": True,
                    "sha256": [{"value": _sha(marker), "name": "RR3.Acceptance.IOC", "source": "local_acceptance"}],
                }
            ),
            encoding="utf-8",
        )
        output = base / "evidence"
        result = scan_offline_windows(
            root,
            output,
            limits=OfflineScanLimits(max_files=128, max_file_bytes=1024 * 1024),
            intel_catalog=catalog,
        )
        after = {str(p.relative_to(root)): _sha(p) for p in root.rglob("*") if p.is_file()}
        ioc = [item for item in result["findings"] if item["ioc_name"] == "RR3.Acceptance.IOC"]
        startup = [item for item in result["findings"] if "startup_location_artifact" in item["reasons"]]
        lure = [item for item in result["findings"] if "double_extension_lure" in item["reasons"]]
        checks = {
            "profile": result["profile"] == PROFILE,
            "target_unchanged": before == after,
            "approved_ioc_detected": len(ioc) == 1 and ioc[0]["verdict"] == "deterministic_ioc",
            "ioc_review_only": len(ioc) == 1 and ioc[0]["automatic_action"] is False,
            "startup_evidence_detected": len(startup) >= 1,
            "double_extension_evidence_detected": len(lure) >= 1,
            "registry_hive_metadata": len(result["registry_hives"]) >= 3,
            "no_target_execution": result["safety"]["target_file_execution"] is False,
            "no_target_dll_load": result["safety"]["target_dll_loading"] is False,
            "no_shell_execution": result["safety"]["target_shell_execution"] is False,
            "no_registry_write": result["safety"]["registry_write"] is False,
            "no_boot_write": result["safety"]["boot_write"] is False,
            "no_target_write": result["safety"]["target_filesystem_write"] is False,
            "no_delete": result["safety"]["file_delete"] is False,
            "no_process_kill": result["safety"]["process_kill"] is False,
            "no_quarantine_execution": result["safety"]["quarantine_execution"] is False,
            "no_repair_engine": result["safety"]["repair_engine_enabled"] is False,
            "no_recovery_certification": result["safety"]["recovery_certification_enabled"] is False,
            "no_network_required": result["safety"]["network_required"] is False,
            "no_cloud_required": result["safety"]["cloud_required"] is False,
            "no_automatic_action": result["safety"]["automatic_action"] is False,
            "structured_audit_written": (output / "rr3-audit.jsonl").is_file(),
            "result_written_outside_target": (output / "rr3-offline-scan.json").is_file() and not str(output).startswith(str(root)),
        }
        return {
            "profile": PROFILE,
            "checkpoint": "RR-3-offline-threat-scanner",
            "passed": all(checks.values()),
            "checks": checks,
            "detail": {
                "summary": result["summary"],
                "ioc": ioc,
                "startup_review_count": len(startup),
                "double_extension_review_count": len(lure),
                "registry_hives": len(result["registry_hives"]),
                "yara_status": result["intel"]["yara_status"],
            },
            "destructive_runtime_actions_added": False,
            "repair_engine_enabled": False,
            "recovery_certification_enabled": False,
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output")
    args = parser.parse_args()
    payload = run_acceptance()
    text = json.dumps(payload, indent=2, ensure_ascii=False)
    print(text)
    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
    return 0 if payload["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())

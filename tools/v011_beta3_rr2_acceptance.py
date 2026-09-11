from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from sentinel.rescue_usb import PROFILE, discover_offline_windows, prepare_rescue_usb, verify_rescue_usb


def run_acceptance() -> dict:
    checks: dict[str, bool] = {}
    detail: dict[str, object] = {}
    with tempfile.TemporaryDirectory(prefix="bcs-rr2-") as tmp:
        root = Path(tmp)
        source = root / "portable"
        source.mkdir()
        exe = source / "BC-Sentinel-Rescue-Portable.exe"
        exe.write_bytes(b"harmless rr2 portable acceptance fixture")
        (source / "portable-integrity.json").write_text('{"profile":"v0.11.0-beta.3-rr1"}\n', encoding="utf-8")
        source_before = {p.name: p.read_bytes() for p in source.iterdir() if p.is_file()}

        destination = root / "usb-sim"
        destination.mkdir()
        prepared = prepare_rescue_usb(source, destination, simulation=True)
        verified = verify_rescue_usb(destination)
        source_after = {p.name: p.read_bytes() for p in source.iterdir() if p.is_file()}

        offline = root / "offline-target"
        cfg = offline / "Windows" / "System32" / "config"
        sys32 = offline / "Windows" / "System32"
        cfg.mkdir(parents=True)
        (cfg / "SYSTEM").write_bytes(b"fake system hive")
        (sys32 / "ntoskrnl.exe").write_bytes(b"fake kernel")
        offline_before = (cfg / "SYSTEM").read_bytes(), (sys32 / "ntoskrnl.exe").read_bytes()
        candidates = discover_offline_windows([offline])
        offline_after = (cfg / "SYSTEM").read_bytes(), (sys32 / "ntoskrnl.exe").read_bytes()

        copied_exe = destination / "payload" / exe.name
        original_copy = copied_exe.read_bytes()
        copied_exe.write_bytes(original_copy + b"tamper")
        tamper_result = verify_rescue_usb(destination)

        safety = prepared["safety"]
        checks = {
            "profile": prepared["profile"] == PROFILE,
            "source_unchanged": source_before == source_after,
            "payload_prepared": prepared["summary"]["files"] == 2,
            "verification_passed_before_tamper": verified["passed"] is True,
            "tamper_detected": tamper_result["passed"] is False,
            "offline_windows_discovered": len(candidates) == 1,
            "offline_target_unchanged": offline_before == offline_after,
            "no_format": safety["format_disk"] is False,
            "no_partition_write": safety["partition_write"] is False,
            "no_boot_sector_write": safety["boot_sector_write"] is False,
            "no_bootloader_install": safety["bootloader_install"] is False,
            "no_bcd_write": safety["bcd_write"] is False,
            "no_firmware_write": safety["firmware_write"] is False,
            "no_registry_write": safety["registry_write"] is False,
            "no_target_write": safety["target_filesystem_write"] is False,
            "no_delete": safety["file_delete"] is False,
            "no_repair_engine": safety["repair_engine_enabled"] is False,
            "no_quarantine_execution": safety["quarantine_execution_enabled"] is False,
            "no_recovery_certification": safety["recovery_certification_enabled"] is False,
            "no_network_required": safety["network_required"] is False,
            "no_cloud_required": safety["cloud_required"] is False,
        }
        detail = {
            "summary": prepared["summary"],
            "verified": verified,
            "tamper_errors": tamper_result["errors"],
            "offline_candidates": candidates,
        }
    return {
        "profile": PROFILE,
        "checkpoint": "RR-2-rescue-usb-safe-preparation",
        "passed": all(checks.values()),
        "checks": checks,
        "detail": detail,
        "destructive_disk_preparation_added": False,
        "repair_engine_enabled": False,
        "recovery_certification_enabled": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="")
    args = parser.parse_args()
    result = run_acceptance()
    text = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    print(text, end="")
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

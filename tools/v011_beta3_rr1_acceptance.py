from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from pathlib import Path

from sentinel.rescue_portable import PROFILE, PortableLimits, run_portable_acquisition


def run() -> dict:
    with tempfile.TemporaryDirectory(prefix="bcs-rr1-target-") as target_tmp, tempfile.TemporaryDirectory(prefix="bcs-rr1-output-") as output_tmp:
        target = Path(target_tmp)
        output = Path(output_tmp)
        (target / "sample.txt").write_text("BC Sentinel RR1 harmless evidence fixture\n", encoding="utf-8")
        nested = target / "nested"
        nested.mkdir()
        (nested / "sample.bin").write_bytes(b"RR1\x00fixture")
        before = {
            str(path.relative_to(target)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in target.rglob("*") if path.is_file()
        }

        result = run_portable_acquisition(
            target,
            output,
            limits=PortableLimits(max_items=32, max_file_bytes=1024 * 1024),
        )

        after = {
            str(path.relative_to(target)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in target.rglob("*") if path.is_file()
        }
        evidence_path = output / "rr1-evidence.json"
        parsed = json.loads(evidence_path.read_text(encoding="utf-8"))
        safety = result.get("safety") or {}
        checks = {
            "profile": result.get("profile") == PROFILE,
            "target_unchanged": before == after,
            "evidence_created_outside_target": evidence_path.is_file() and target not in evidence_path.parents,
            "two_files_hashed": int(result.get("summary", {}).get("hashed", -1)) == 2,
            "sha256_present": all(len(str(row.get("sha256") or "")) == 64 for row in result.get("records", [])),
            "manifest_read_only": parsed.get("manifest", {}).get("write_authorized") is False,
            "compromised_context": parsed.get("manifest", {}).get("execution_context") == "compromised_windows",
            "no_install": safety.get("installation_required") is False,
            "no_service_install": safety.get("service_install") is False,
            "no_driver_install": safety.get("driver_install") is False,
            "no_registry_write": safety.get("registry_write") is False,
            "no_boot_write": safety.get("boot_write") is False,
            "no_target_write": safety.get("target_filesystem_write") is False,
            "no_delete": safety.get("file_delete") is False,
            "no_process_kill": safety.get("process_kill") is False,
            "no_network_required": safety.get("network_required") is False,
            "no_cloud_required": safety.get("cloud_required") is False,
            "no_repair_engine": safety.get("repair_engine_enabled") is False,
            "no_quarantine_execution": safety.get("quarantine_execution_enabled") is False,
            "no_recovery_certification": safety.get("recovery_certification_enabled") is False,
        }
        return {
            "profile": PROFILE,
            "checkpoint": "RR-1-portable-read-only",
            "passed": all(checks.values()),
            "checks": checks,
            "summary": result.get("summary"),
            "limits": result.get("limits"),
            "portable_installation_required": False,
            "destructive_runtime_actions_added": False,
            "repair_engine_enabled": False,
        }


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel v0.11 Beta3 RR1 portable acceptance")
    parser.add_argument("--output", default="acceptance-v011-beta3-rr1.json")
    args = parser.parse_args()
    result = run()
    Path(args.output).write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())

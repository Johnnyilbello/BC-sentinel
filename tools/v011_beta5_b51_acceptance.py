from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from pathlib import Path

from sentinel import rescue_hostile_scenarios as b51


def make_windows(root: Path) -> Path:
    cfg = root / "Windows" / "System32" / "config"
    cfg.mkdir(parents=True)
    (cfg / "SYSTEM").write_bytes(b"B51 SYSTEM")
    (cfg / "SOFTWARE").write_bytes(b"B51 SOFTWARE")
    (root / "Windows" / "System32" / "ntoskrnl.exe").write_bytes(b"MZ B51 KERNEL")
    return root


def tree_hashes(root: Path) -> dict[str, str]:
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in root.rglob("*") if p.is_file()}


def run() -> dict:
    with tempfile.TemporaryDirectory(prefix="bcs-b51-") as td:
        base = Path(td)
        clean = make_windows(base / "clean")
        damaged = make_windows(base / "damaged")
        (damaged / "Windows" / "System32" / "config" / "SOFTWARE").unlink()
        persistence = make_windows(base / "persistence")
        startup = persistence / "ProgramData" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "StartUp"
        startup.mkdir(parents=True)
        (startup / "fixture.ps1").write_text("Write-Output fixture", encoding="utf-8")
        restricted = make_windows(base / "restricted")
        degraded = make_windows(base / "degraded")

        before = {name: tree_hashes(path) for name, path in {
            "clean": clean, "damaged": damaged, "persistence": persistence, "restricted": restricted, "degraded": degraded
        }.items()}

        clean_result = b51.assess_target(clean)
        damaged_result = b51.assess_target(damaged)
        persistence_result = b51.assess_target(persistence)

        restricted_target = restricted / "Windows" / "System32" / "config" / "SYSTEM"
        def restricted_reader(path: Path, _: int) -> bytes:
            if path == restricted_target:
                raise PermissionError("acceptance denied")
            return path.read_bytes()
        restricted_result = b51.assess_target(restricted, reader=restricted_reader)

        degraded_target = degraded / "Windows" / "System32" / "config" / "SYSTEM"
        def degraded_reader(path: Path, _: int) -> bytes:
            if path == degraded_target:
                raise OSError(5, "acceptance io")
            return path.read_bytes()
        degraded_result = b51.assess_target(degraded, reader=degraded_reader)

        out = base / "evidence" / "b51.json"
        b51.write_assessment(persistence_result, out, persistence)
        after = {name: tree_hashes(path) for name, path in {
            "clean": clean, "damaged": damaged, "persistence": persistence, "restricted": restricted, "degraded": degraded
        }.items()}

        checks = {
            "profile": clean_result["profile"] == b51.PROFILE,
            "clean_healthy": clean_result["state"] == b51.STATE_HEALTHY,
            "damaged_detected": damaged_result["state"] == b51.STATE_DAMAGED,
            "missing_software_hive_detected": "Windows/System32/config/SOFTWARE" in damaged_result["critical_missing"],
            "persistence_review_only": persistence_result["state"] == b51.STATE_REVIEW,
            "persistence_item_count": persistence_result["counters"]["persistence_review_items"] == 1,
            "permission_classified": restricted_result["state"] == b51.STATE_ACCESS_RESTRICTED,
            "io_degraded_classified": degraded_result["state"] == b51.STATE_IO_DEGRADED,
            "all_targets_unchanged": before == after,
            "output_outside_target": out.is_file() and not str(out).startswith(str(persistence)),
            "assessment_hash_present": len(persistence_result["assessment_sha256"]) == 64,
            "no_write_attempt": all(not r["safety"]["write_attempted"] for r in (clean_result, damaged_result, persistence_result, restricted_result, degraded_result)),
            "no_target_execution": all(not r["safety"]["target_execution"] for r in (clean_result, damaged_result, persistence_result, restricted_result, degraded_result)),
            "no_repair_execution": all(not r["safety"]["repair_execution"] for r in (clean_result, damaged_result, persistence_result, restricted_result, degraded_result)),
            "no_quarantine_execution": all(not r["safety"]["quarantine_execution"] for r in (clean_result, damaged_result, persistence_result, restricted_result, degraded_result)),
            "no_registry_write": all(not r["safety"]["registry_write"] for r in (clean_result, damaged_result, persistence_result, restricted_result, degraded_result)),
            "no_boot_write": all(not r["safety"]["boot_write"] for r in (clean_result, damaged_result, persistence_result, restricted_result, degraded_result)),
            "no_network_required": all(not r["safety"]["network_required"] for r in (clean_result, damaged_result, persistence_result, restricted_result, degraded_result)),
            "no_cloud_required": all(not r["safety"]["cloud_required"] for r in (clean_result, damaged_result, persistence_result, restricted_result, degraded_result)),
            "no_automatic_action": all(not r["safety"]["automatic_action"] for r in (clean_result, damaged_result, persistence_result, restricted_result, degraded_result)),
        }
        return {
            "profile": b51.PROFILE,
            "checkpoint": "B5-1-hostile-damaged-system-scenarios",
            "passed": all(checks.values()),
            "checks": checks,
            "detail": {
                "clean_state": clean_result["state"],
                "damaged_state": damaged_result["state"],
                "persistence_state": persistence_result["state"],
                "restricted_state": restricted_result["state"],
                "degraded_state": degraded_result["state"],
                "assessment_sha256": persistence_result["assessment_sha256"],
            },
            "new_mutation_authority_added": False,
            "automatic_destructive_action_enabled": False,
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output")
    args = parser.parse_args()
    result = run()
    text = json.dumps(result, indent=2, sort_keys=True)
    print(text)
    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

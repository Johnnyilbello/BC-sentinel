from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from pathlib import Path

from sentinel import rescue_target_discovery as b50


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _tree(root: Path) -> dict[str, str]:
    return {str(p.relative_to(root)): _sha(p) for p in root.rglob("*") if p.is_file()}


def _windows(root: Path, *, complete: bool = True, tag: str = "A") -> Path:
    cfg = root / "Windows/System32/config"
    cfg.mkdir(parents=True)
    (cfg / "SYSTEM").write_bytes(("B50 " + tag + " SYSTEM").encode())
    if complete:
        (cfg / "SOFTWARE").write_bytes(("B50 " + tag + " SOFTWARE").encode())
        (root / "Windows/System32/ntoskrnl.exe").write_bytes(("MZ B50 " + tag + " KERNEL").encode())
    return root


def run_acceptance() -> dict:
    with tempfile.TemporaryDirectory(prefix="bcs-b50-") as temp_name:
        base = Path(temp_name)
        container = base / "volumes"
        container.mkdir()
        ready_a = _windows(container / "VolumeA", tag="A")
        ready_b = _windows(container / "VolumeB", tag="B")
        partial = _windows(container / "Partial", complete=False, tag="P")
        data = container / "DataOnly"
        data.mkdir()
        (data / "notes.txt").write_text("not windows", encoding="utf-8")
        locked = container / "Locked"
        locked.mkdir()

        before = {str(p): _tree(p) for p in (ready_a, ready_b, partial, data, locked)}

        def probe(path: Path) -> dict:
            if path.name.casefold() == "locked":
                return {"provider": "acceptance", "available": True, "locked": True, "lock_status": 1}
            return {"provider": "acceptance", "available": True, "locked": False, "lock_status": 0}

        result = b50.discover_targets(
            [container],
            include_windows_volumes=False,
            limits=b50.DiscoveryLimits(max_roots=16, probe_children=True, max_children_per_root=16),
            bitlocker_probe=probe,
        )
        after = {str(p): _tree(p) for p in (ready_a, ready_b, partial, data, locked)}
        by_name = {Path(item["normalized_root"]).name: item for item in result["candidates"]}

        output = base / "evidence" / "b50-target-discovery.json"
        b50.write_discovery_result(result, output)
        payload = json.loads(output.read_text(encoding="utf-8"))

        permission_state, _ = b50._classify_exception(PermissionError("acceptance denied"), {"locked": False})
        locked_exc = OSError("acceptance locked")
        locked_exc.winerror = 33
        locked_state, _ = b50._classify_exception(locked_exc, {"locked": None})

        checks = {
            "profile": result["profile"] == b50.PROFILE,
            "schema": result["schema"] == b50.RESULT_SCHEMA,
            "two_ready_targets": result["counts"][b50.STATE_READY] == 2,
            "ready_rr6_fingerprints": all(len(by_name[name]["target_fingerprint"]) == 64 for name in ("VolumeA", "VolumeB")),
            "partial_incomplete": by_name["Partial"]["state"] == b50.STATE_INCOMPLETE,
            "data_unsupported": by_name["DataOnly"]["state"] == b50.STATE_UNSUPPORTED,
            "locked_refused": by_name["Locked"]["state"] == b50.STATE_LOCKED,
            "permission_classified": permission_state == b50.STATE_ACCESS_DENIED,
            "locked_error_classified": locked_state == b50.STATE_LOCKED,
            "child_discovery": all(by_name[name]["discovery_source"] == "explicit_child" for name in ("VolumeA", "VolumeB", "Partial", "DataOnly", "Locked")),
            "target_byte_identical": before == after,
            "output_written_outside_targets": output.is_file(),
            "output_roundtrip": payload["profile"] == b50.PROFILE and payload["counts"] == result["counts"],
            "bounded_roots": result["roots_considered"] <= 16,
            "no_write_attempt": result["safety"]["write_attempted"] is False,
            "no_unlock_attempt": result["safety"]["unlock_attempted"] is False,
            "no_mount_mutation": result["safety"]["mount_mutation"] is False,
            "no_format": result["safety"]["format_disk"] is False,
            "no_partition_write": result["safety"]["partition_write"] is False,
            "no_bcd_write": result["safety"]["bcd_write"] is False,
            "no_filesystem_repair": result["safety"]["filesystem_repair"] is False,
            "no_target_execution": result["safety"]["target_execution"] is False,
            "no_service_install": result["safety"]["service_install"] is False,
            "no_driver_install": result["safety"]["driver_install"] is False,
            "no_network_required": result["safety"]["network_required"] is False,
            "no_cloud_required": result["safety"]["cloud_required"] is False,
        }
        return {
            "profile": b50.PROFILE,
            "checkpoint": "B5-0-real-world-target-discovery",
            "passed": all(checks.values()),
            "checks": checks,
            "detail": {
                "counts": result["counts"],
                "roots_considered": result["roots_considered"],
                "ready_fingerprints": {name: by_name[name]["target_fingerprint"] for name in ("VolumeA", "VolumeB")},
                "session_id": result["session_id"],
                "correlation_id": result["correlation_id"],
            },
            "new_mutation_authority_added": False,
            "automatic_destructive_action_enabled": False,
            "unlock_enabled": False,
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output")
    args = parser.parse_args()
    result = run_acceptance()
    if args.output:
        Path(args.output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())

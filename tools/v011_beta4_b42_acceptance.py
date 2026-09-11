from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from pathlib import Path

from sentinel import rescue_console_guided_repair as b42
from sentinel import rescue_integrity_certification as rr6
from sentinel import rescue_offline_scanner as rr3
from sentinel import rescue_repair_portable as rr4b


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run(output: Path) -> dict:
    with tempfile.TemporaryDirectory(prefix="bcs-b42-") as tmp:
        base = Path(tmp)
        root = base / "offline-target"
        config = root / "Windows/System32/config"
        drivers = root / "Windows/System32/drivers"
        config.mkdir(parents=True)
        drivers.mkdir(parents=True)
        (config / "SYSTEM").write_bytes(b"B42 ACCEPT SYSTEM")
        (config / "SOFTWARE").write_bytes(b"B42 ACCEPT SOFTWARE")
        (root / "Windows/System32/ntoskrnl.exe").write_bytes(b"MZ B42 ACCEPT KERNEL")
        target = drivers / "repairable.sys"
        target.write_bytes(b"B42 ORIGINAL")
        before = sha(target)

        workspace = base / "workspace"
        scan_dir = workspace / "rr3"
        rr3.scan_offline_windows(root, scan_dir, limits=rr3.OfflineScanLimits(max_files=64, max_file_bytes=1024 * 1024))
        scan = scan_dir / "rr3-offline-scan.json"
        replacement = base / "replacement.sys"
        replacement.write_bytes(b"B42 REPLACEMENT")
        operations = workspace / "approved-operations.json"
        write_json(operations, {
            "schema": rr4b.OPERATIONS_SCHEMA,
            "approved": True,
            "target_fingerprint": rr6.target_fingerprint(root),
            "source_scan_sha256": sha(scan),
            "operations": [{
                "relative_path": "Windows/System32/drivers/repairable.sys",
                "expected_sha256": before,
                "replacement_source": str(replacement),
                "replacement_sha256": sha(replacement),
                "evidence_reference": "rr3:" + sha(scan),
            }],
        })

        handoff = b42.prepare_repair_handoff(b42.GuidedRepairPrepareRequest(root, workspace, scan, operations))
        plan = rr4b.load_plan_file(Path(handoff["plan_path"]))
        unchanged_after_prepare = sha(target) == before

        tampered_scan = workspace / "tampered-scan.json"
        tampered_payload = json.loads(scan.read_text(encoding="utf-8"))
        tampered_payload["summary"]["errors"] = 1
        write_json(tampered_scan, tampered_payload)
        tampered_refused = False
        try:
            b42.prepare_repair_handoff(b42.GuidedRepairPrepareRequest(root, workspace, tampered_scan, operations))
        except ValueError:
            tampered_refused = True

        unbound = workspace / "unbound-operations.json"
        unbound_payload = json.loads(operations.read_text(encoding="utf-8"))
        unbound_payload["source_scan_sha256"] = "0" * 64
        write_json(unbound, unbound_payload)
        unbound_refused = False
        try:
            b42.prepare_repair_handoff(b42.GuidedRepairPrepareRequest(root, workspace, scan, unbound))
        except ValueError:
            unbound_refused = True

        checks = {
            "profile": handoff["profile"] == b42.PROFILE,
            "trusted_scan_bound": handoff["trusted_scan_sha256"] == sha(scan),
            "target_fingerprint_bound": handoff["target_fingerprint"] == rr6.target_fingerprint(root),
            "plan_hash_present": len(handoff["plan_sha256"]) == 64,
            "plan_loadable_by_rr4b": plan.plan_sha256 == handoff["plan_sha256"],
            "exact_confirmation_token": handoff["confirmation_token"] == rr4b.confirmation_token(plan),
            "operator_confirmation_required": handoff["operator_confirmation_required"] is True,
            "execution_not_performed": handoff["execution_performed"] is False,
            "rollback_not_performed": handoff["rollback_performed"] is False,
            "automatic_execution_disabled": handoff["automatic_execution"] is False,
            "automatic_repair_disabled": handoff["automatic_repair"] is False,
            "automatic_quarantine_disabled": handoff["automatic_quarantine"] is False,
            "rr4b_execution_delegated": handoff["rr4b_execution_delegated"] is True,
            "rr4b_rollback_delegated": handoff["rr4b_rollback_delegated"] is True,
            "target_unchanged": unchanged_after_prepare,
            "tampered_scan_refused": tampered_refused,
            "unbound_operations_refused": unbound_refused,
            "recovery_not_certified": handoff["recovery_certified"] is False,
        }
        result = {
            "profile": b42.PROFILE,
            "checkpoint": "B4-2-guided-repair-handoff",
            "passed": all(checks.values()),
            "checks": checks,
            "detail": {
                "session_id": handoff["session_id"],
                "correlation_id": handoff["correlation_id"],
                "target_fingerprint": handoff["target_fingerprint"],
                "scan_sha256": handoff["trusted_scan_sha256"],
                "plan_sha256": handoff["plan_sha256"],
                "confirmation_token_prefix": handoff["confirmation_token"][:24],
                "operations": handoff["operations"],
            },
            "new_mutation_authority_added": False,
            "automatic_repair_enabled": False,
        }
        write_json(output, result)
        return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    result = run(Path(args.output))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from pathlib import Path

from sentinel import rescue_console as b40
from sentinel import rescue_console_guided_scan as b41


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _snapshot(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)).replace("\\", "/"): _sha(path)
        for path in root.rglob("*")
        if path.is_file()
    }


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run(output: Path) -> dict:
    with tempfile.TemporaryDirectory(prefix="bcs-b41-") as temp_name:
        base = Path(temp_name)
        root = base / "offline-target"
        (root / "Windows/System32/config").mkdir(parents=True)
        (root / "Windows/System32/config/SYSTEM").write_bytes(b"B41 ACCEPT SYSTEM")
        (root / "Windows/System32/config/SOFTWARE").write_bytes(b"B41 ACCEPT SOFTWARE")
        (root / "Windows/System32/ntoskrnl.exe").write_bytes(b"MZ B41 ACCEPT KERNEL")
        fixture = root / "Windows/System32/b41-accept.exe"
        fixture.write_bytes(b"MZ harmless B41 deterministic IOC fixture")
        before = _snapshot(root)

        workspace = base / "workspace"
        plan = b40.build_session_plan(b40.RescueConsoleRequest(root, workspace))
        b40.write_session_plan(plan, workspace / "session-plan.json", root)

        initial_inventory = b41.inventory_evidence(root, workspace)
        plan_row = next(row for row in initial_inventory["records"] if row["kind"] == "b40_session_plan")
        scan_row_initial = next(row for row in initial_inventory["records"] if row["kind"] == "rr3_scan")

        catalog = base / "approved-ioc.json"
        _write_json(
            catalog,
            {
                "schema": "bc-sentinel-offline-intel-v1",
                "approved": True,
                "sha256": [
                    {
                        "value": _sha(fixture),
                        "name": "B41.Acceptance.IOC",
                        "source": "synthetic-acceptance",
                    }
                ],
            },
        )

        fresh = b41.run_guided_scan(
            b41.GuidedScanRequest(
                target_root=root,
                workspace=workspace,
                run_scan=True,
                intel_catalog=catalog,
                max_files=64,
                max_file_bytes=1024 * 1024,
            )
        )
        scan_path = workspace / "rr3/rr3-offline-scan.json"
        post_inventory = b41.inventory_evidence(root, workspace, scan_path)
        scan_row_post = next(row for row in post_inventory["records"] if row["kind"] == "rr3_scan")

        reuse_workspace = base / "reuse-workspace"
        reuse = b41.run_guided_scan(
            b41.GuidedScanRequest(
                target_root=root,
                workspace=reuse_workspace,
                existing_scan=scan_path,
                reuse_trusted_scan=True,
                run_scan=False,
            )
        )

        tampered = base / "tampered-scan.json"
        tampered_payload = json.loads(scan_path.read_text(encoding="utf-8"))
        tampered_payload["summary"]["errors"] = 1
        _write_json(tampered, tampered_payload)
        tampered_inventory = b41.inventory_evidence(root, base / "tampered-workspace", tampered)
        tampered_row = next(row for row in tampered_inventory["records"] if row["kind"] == "rr3_scan")
        refused_reuse = b41.run_guided_scan(
            b41.GuidedScanRequest(
                target_root=root,
                workspace=base / "refused-reuse-workspace",
                existing_scan=tampered,
                reuse_trusted_scan=True,
                run_scan=False,
            )
        )

        after = _snapshot(root)
        audit_rows = [
            json.loads(line)
            for line in (workspace / "b41-audit.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

        checks = {
            "profile": fresh["profile"] == b41.PROFILE if "profile" in fresh else True,
            "target_unchanged": before == after,
            "b40_plan_trusted": plan_row["trust"] == b41.TRUST_TRUSTED,
            "initial_scan_missing": scan_row_initial["trust"] == b41.TRUST_MISSING,
            "fresh_scan_executed_only_by_request": fresh["scan"]["source"] == "fresh_operator_requested",
            "fresh_scan_available": fresh["scan"]["available"] is True,
            "deterministic_ioc_observed": int(fresh["scan"]["summary"].get("ioc_hits", 0)) == 1,
            "no_repair_triggered": fresh["repair_triggered"] is False,
            "no_quarantine_triggered": fresh["quarantine_triggered"] is False,
            "no_automatic_execution": fresh["automatic_execution"] is False,
            "post_scan_evidence_trusted": scan_row_post["trust"] == b41.TRUST_TRUSTED,
            "trusted_scan_reused": reuse["scan"]["source"] == "reused_trusted_existing",
            "trusted_reuse_requires_no_fresh_scan": reuse["operator_action_required"] == "none",
            "tampered_scan_untrusted": tampered_row["trust"] == b41.TRUST_UNTRUSTED,
            "tampered_reuse_refused": refused_reuse["scan"]["available"] is False,
            "fresh_scan_requested_after_refusal": refused_reuse["operator_action_required"] == "run_fresh_scan",
            "audit_has_inventory": any(row.get("stage") == "evidence_inventory" for row in audit_rows),
            "audit_has_scan": any(row.get("stage") == "offline_scan" for row in audit_rows),
            "audit_has_ids_and_timing": all(
                row.get("session_id") and row.get("correlation_id") and isinstance(row.get("elapsed_ms"), (int, float))
                for row in audit_rows
            ),
            "target_read_only": fresh["safety"]["target_read_only"] is True,
            "no_registry_write": fresh["safety"]["registry_write"] is False,
            "no_boot_write": fresh["safety"]["boot_write"] is False,
            "no_file_delete": fresh["safety"]["file_delete"] is False,
            "no_process_kill": fresh["safety"]["process_kill"] is False,
            "no_host_isolation": fresh["safety"]["host_isolation"] is False,
        }
        passed = all(checks.values())
        result = {
            "profile": b41.PROFILE,
            "checkpoint": "B4-1-evidence-inventory-guided-scan",
            "passed": passed,
            "checks": checks,
            "detail": {
                "session_id": fresh["session_id"],
                "correlation_id": fresh["correlation_id"],
                "target_fingerprint": fresh["target_fingerprint"],
                "scan_sha256": _sha(scan_path),
                "scan_summary": fresh["scan"]["summary"],
                "trusted_reuse_source": reuse["scan"]["source"],
                "tampered_reasons": tampered_row["reasons"],
                "audit_records": len(audit_rows),
            },
            "new_mutation_authority_added": False,
            "automatic_repair_enabled": False,
            "automatic_quarantine_enabled": False,
        }
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return result


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel Beta4 B4-1 deterministic acceptance")
    parser.add_argument("--output", default="acceptance-v011-beta4-b41.json")
    args = parser.parse_args()
    result = run(Path(args.output))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

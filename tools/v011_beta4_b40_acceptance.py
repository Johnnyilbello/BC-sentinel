from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from pathlib import Path

from sentinel import rescue_console as b40


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def snapshot(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)).replace("\\", "/"): sha256_file(path)
        for path in root.rglob("*")
        if path.is_file()
    }


def make_root(base: Path) -> Path:
    root = base / "offline-target"
    cfg = root / "Windows/System32/config"
    cfg.mkdir(parents=True)
    (cfg / "SYSTEM").write_bytes(b"B40 ACCEPT SYSTEM")
    (cfg / "SOFTWARE").write_bytes(b"B40 ACCEPT SOFTWARE")
    (root / "Windows/System32/ntoskrnl.exe").write_bytes(b"MZ B40 ACCEPT KERNEL")
    return root


def run_acceptance() -> dict:
    with tempfile.TemporaryDirectory(prefix="bcs-b40-") as temp_name:
        base = Path(temp_name)
        root = make_root(base)
        workspace = base / "workspace"
        before = snapshot(root)

        plan = b40.build_session_plan(b40.RescueConsoleRequest(root, workspace))
        output = b40.write_session_plan(plan, workspace / "session-plan.json", root)
        loaded = json.loads(output.read_text(encoding="utf-8"))
        after = snapshot(root)

        stages = tuple(item["stage"] for item in loaded["stages"])
        planned = [item for item in loaded["stages"] if item["mode"] == "planned_only"]
        checks = {
            "profile": loaded["profile"] == b40.PROFILE,
            "schema": loaded["schema"] == b40.PLAN_SCHEMA,
            "target_unchanged": before == after,
            "stage_order_exact": stages == b40.STAGE_ORDER,
            "module_inventory_complete": bool(loaded["module_inventory"]) and all(loaded["module_inventory"].values()),
            "plan_hash_present": len(str(loaded.get("plan_sha256", ""))) == 64,
            "session_id_present": str(loaded.get("session_id", "")).startswith("B40-"),
            "correlation_id_present": len(str(loaded.get("correlation_id", ""))) == 24,
            "all_planned_stages_operator_gated": bool(planned) and all(item["operator_gate"] is True for item in planned),
            "no_automatic_stage_execution": all(item["automatic_execution"] is False for item in loaded["stages"]),
            "target_read_only": loaded["safety"]["target_read_only"] is True,
            "no_automatic_execution": loaded["safety"]["automatic_execution"] is False,
            "no_automatic_repair": loaded["safety"]["automatic_repair"] is False,
            "no_automatic_quarantine": loaded["safety"]["automatic_quarantine"] is False,
            "no_process_kill": loaded["safety"]["process_kill"] is False,
            "no_host_isolation": loaded["safety"]["host_isolation"] is False,
            "no_registry_write": loaded["safety"]["registry_write"] is False,
            "no_boot_write": loaded["safety"]["boot_write"] is False,
            "no_file_delete": loaded["safety"]["file_delete"] is False,
            "reimage_not_suppressed": loaded["safety"]["format_or_reimage_suppressed"] is False,
            "plan_written_outside_target": output.is_file() and root.resolve() not in output.resolve().parents,
        }
        return {
            "profile": b40.PROFILE,
            "checkpoint": "B4-0-rescue-console-orchestrator-foundation",
            "passed": all(checks.values()),
            "checks": checks,
            "detail": {
                "target_fingerprint": loaded["target_fingerprint"],
                "session_id": loaded["session_id"],
                "correlation_id": loaded["correlation_id"],
                "plan_sha256": loaded["plan_sha256"],
                "stage_order": list(stages),
                "module_inventory": loaded["module_inventory"],
            },
            "automatic_execution_enabled": False,
            "live_host_mutation_enabled": False,
            "new_destructive_authority_added": False,
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output")
    args = parser.parse_args()
    result = run_acceptance()
    text = json.dumps(result, indent=2, sort_keys=True)
    print(text)
    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

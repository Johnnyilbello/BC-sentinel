from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from sentinel import rescue_repair_engine as core
from sentinel import rescue_repair_portable as rr4b


def _offline_root(base: Path) -> Path:
    root = base / "offline"
    config = root / "Windows" / "System32" / "config"
    config.mkdir(parents=True)
    (config / "SYSTEM").write_bytes(b"RR4B ACCEPT SYSTEM")
    system32 = root / "Windows" / "System32"
    (system32 / "ntoskrnl.exe").write_bytes(b"MZ RR4B accept kernel")
    target = root / "Program Files" / "Demo" / "component.dll"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"RR4B accept original")
    return root


def run_acceptance(base: Path) -> dict:
    root = _offline_root(base)
    target = root / "Program Files" / "Demo" / "component.dll"
    replacement = base / "trusted" / "component.dll"
    replacement.parent.mkdir(parents=True)
    replacement.write_bytes(b"RR4B accept replacement")
    before = core.sha256_file(target)

    operations = base / "operations.json"
    operations.write_text(
        json.dumps(
            {
                "schema": rr4b.OPERATIONS_SCHEMA,
                "approved": True,
                "operations": [
                    {
                        "relative_path": "Program Files/Demo/component.dll",
                        "expected_sha256": before,
                        "replacement_source": str(replacement),
                        "replacement_sha256": core.sha256_file(replacement),
                        "evidence_reference": "RR3:rr4b-acceptance",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    plan_path = base / "plan.json"
    planned = rr4b.create_plan_file(root, operations, plan_path)
    wrong_refused = False
    unchanged_after_wrong = False
    try:
        rr4b.execute_plan_file(plan_path, base / "rollback", "WRONG")
    except PermissionError:
        wrong_refused = True
        unchanged_after_wrong = core.sha256_file(target) == before

    executed = rr4b.execute_plan_file(plan_path, base / "rollback", planned["confirmation_token"])
    transaction = Path(executed["transaction_path"])
    replacement_applied = core.sha256_file(target) == core.sha256_file(replacement)
    rolled = rr4b.rollback_transaction_file(transaction, planned["confirmation_token"])
    restored = core.sha256_file(target) == before

    executed2 = rr4b.execute_plan_file(plan_path, base / "rollback2", planned["confirmation_token"])
    transaction2 = Path(executed2["transaction_path"])
    target.write_bytes(b"RR4B third-party post repair change")
    changed_hash = core.sha256_file(target)
    changed_state_refused = False
    changed_state_preserved = False
    try:
        rr4b.rollback_transaction_file(transaction2, planned["confirmation_token"])
    except RuntimeError:
        changed_state_refused = True
        changed_state_preserved = core.sha256_file(target) == changed_hash

    checks = {
        "profile": rr4b.PROFILE == "v0.11.0-beta.3-rr4b",
        "plan_hash_present": bool(planned["plan_sha256"]),
        "wrong_confirmation_refused": wrong_refused,
        "unchanged_after_wrong_confirmation": unchanged_after_wrong,
        "execute_passed": bool(executed.get("passed")),
        "replacement_applied": replacement_applied,
        "manual_rollback_passed": bool(rolled.get("passed")),
        "manual_rollback_restored": restored,
        "post_repair_change_refused_before_rollback": changed_state_refused,
        "post_repair_change_preserved": changed_state_preserved,
        "no_automatic_action": executed.get("automatic_action") is False and rolled.get("automatic_action") is False,
        "no_recovery_certification": executed.get("recovery_certified") is False and rolled.get("recovery_certified") is False,
    }
    return {
        "profile": rr4b.PROFILE,
        "checkpoint": "RR-4B-portable-repair-engine",
        "passed": all(checks.values()),
        "checks": checks,
        "detail": {
            "plan_sha256": planned["plan_sha256"],
            "confirmation_token_prefix": planned["confirmation_token"][:18],
            "transaction": str(transaction),
            "rollback_preflight_checked": rolled.get("preflight_checked"),
        },
        "live_host_repair_enabled": False,
        "automatic_repair_enabled": False,
        "registry_write_enabled": False,
        "boot_write_enabled": False,
        "recovery_certification_enabled": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--base")
    args = parser.parse_args()
    if args.base:
        base = Path(args.base)
        base.mkdir(parents=True, exist_ok=True)
        result = run_acceptance(base)
    else:
        with tempfile.TemporaryDirectory(prefix="bcs-rr4b-") as tmp:
            result = run_acceptance(Path(tmp))
    Path(args.output).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

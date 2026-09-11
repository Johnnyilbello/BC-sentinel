from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from pathlib import Path

from sentinel import rescue_repair_engine as rr4


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run_acceptance() -> dict:
    with tempfile.TemporaryDirectory(prefix="bcs-rr4a-") as temp_name:
        base = Path(temp_name)
        root = base / "offline-target"
        config = root / "Windows" / "System32" / "config"
        drivers = root / "Windows" / "System32" / "drivers"
        trusted = base / "trusted-media"
        rollback = base / "rollback-vault"
        config.mkdir(parents=True)
        drivers.mkdir(parents=True)
        trusted.mkdir()
        (config / "SYSTEM").write_bytes(b"RR4A ACCEPTANCE SYSTEM")
        (root / "Windows" / "System32" / "ntoskrnl.exe").write_bytes(b"MZ RR4A ACCEPTANCE KERNEL")

        target = drivers / "acceptance.sys"
        replacement = trusted / "acceptance-clean.sys"
        target.write_bytes(b"RR4A harmless original fixture")
        replacement.write_bytes(b"RR4A harmless replacement fixture")
        before_hash = _sha(target)
        replacement_hash = _sha(replacement)

        op = rr4.RepairOperation(
            relative_path="Windows/System32/drivers/acceptance.sys",
            expected_sha256=before_hash,
            replacement_source=str(replacement),
            replacement_sha256=replacement_hash,
            evidence_reference="RR3.Acceptance.IOC:harmless",
        )
        plan = rr4.build_repair_plan(root, [op])

        wrong_confirmation_refused = False
        try:
            rr4.execute_repair_plan(plan, rollback, operator_confirmation="WRONG")
        except PermissionError:
            wrong_confirmation_refused = True
        unchanged_after_wrong_confirmation = _sha(target) == before_hash

        applied = rr4.execute_repair_plan(plan, rollback, operator_confirmation=rr4.confirmation_token(plan))
        repair_applied = _sha(target) == replacement_hash
        transaction_path = Path(applied["transaction_path"])
        transaction = json.loads(transaction_path.read_text(encoding="utf-8"))
        backup_path = Path(transaction["operations"][0]["backup_path"])
        backup_verified = backup_path.is_file() and _sha(backup_path) == before_hash

        rolled_back = rr4.rollback_repair_session(transaction_path, operator_confirmation=rr4.confirmation_token(plan))
        restored = _sha(target) == before_hash
        final_transaction = json.loads(transaction_path.read_text(encoding="utf-8"))

        stale_target = drivers / "stale.sys"
        stale_replacement = trusted / "stale-clean.sys"
        stale_target.write_bytes(b"stale original")
        stale_replacement.write_bytes(b"stale replacement")
        stale_op = rr4.RepairOperation(
            relative_path="Windows/System32/drivers/stale.sys",
            expected_sha256=_sha(stale_target),
            replacement_source=str(stale_replacement),
            replacement_sha256=_sha(stale_replacement),
            evidence_reference="RR3.Acceptance.IOC:stale",
        )
        stale_plan = rr4.build_repair_plan(root, [stale_op])
        stale_target.write_bytes(b"changed after planning")
        changed_hash = _sha(stale_target)
        stale_refused = False
        try:
            rr4.execute_repair_plan(stale_plan, base / "rollback-stale", operator_confirmation=rr4.confirmation_token(stale_plan))
        except RuntimeError as exc:
            stale_refused = "stale_precondition" in str(exc)
        stale_preserved = _sha(stale_target) == changed_hash

        one = drivers / "one.sys"
        two = drivers / "two.sys"
        one_replacement = trusted / "one-clean.sys"
        two_replacement = trusted / "two-clean.sys"
        one.write_bytes(b"one-old")
        two.write_bytes(b"two-old")
        one_replacement.write_bytes(b"one-new")
        two_replacement.write_bytes(b"two-new")
        before_one = _sha(one)
        before_two = _sha(two)
        plan2 = rr4.build_repair_plan(
            root,
            [
                rr4.RepairOperation("Windows/System32/drivers/one.sys", before_one, str(one_replacement), _sha(one_replacement), "RR3:one"),
                rr4.RepairOperation("Windows/System32/drivers/two.sys", before_two, str(two_replacement), _sha(two_replacement), "RR3:two"),
            ],
        )
        two_replacement.write_bytes(b"changed-after-plan")
        partial_failure_rolled_back = False
        try:
            rr4.execute_repair_plan(plan2, base / "rollback-partial", operator_confirmation=rr4.confirmation_token(plan2))
        except RuntimeError as exc:
            partial_failure_rolled_back = "rollback succeeded" in str(exc)
        partial_restored = _sha(one) == before_one and _sha(two) == before_two

        checks = {
            "profile": rr4.PROFILE == "v0.11.0-beta.3-rr4a",
            "wrong_confirmation_refused": wrong_confirmation_refused,
            "unchanged_after_wrong_confirmation": unchanged_after_wrong_confirmation,
            "plan_hash_present": len(plan.plan_sha256) == 64,
            "repair_applied": repair_applied,
            "verified_backup_before_write": backup_verified,
            "transaction_applied_state": transaction.get("state") == "applied",
            "manual_rollback_passed": rolled_back.get("passed") is True,
            "manual_rollback_restored": restored,
            "transaction_rolled_back_state": final_transaction.get("state") == "rolled_back",
            "stale_precondition_refused": stale_refused,
            "stale_target_preserved": stale_preserved,
            "partial_failure_rollback_triggered": partial_failure_rolled_back,
            "partial_failure_restored_all": partial_restored,
            "no_automatic_action": applied.get("automatic_action") is False and rolled_back.get("automatic_action") is False,
            "no_recovery_certification": applied.get("recovery_certified") is False and rolled_back.get("recovery_certified") is False,
        }
        return {
            "profile": rr4.PROFILE,
            "checkpoint": "RR-4A-reversible-transaction-core",
            "passed": all(checks.values()),
            "checks": checks,
            "detail": {
                "plan_sha256": plan.plan_sha256,
                "session_id": applied["session_id"],
                "backup_sha256": _sha(backup_path),
                "before_sha256": before_hash,
                "replacement_sha256": replacement_hash,
                "final_transaction_state": final_transaction.get("state"),
            },
            "automatic_repair_enabled": False,
            "live_host_repair_enabled": False,
            "registry_write_enabled": False,
            "boot_write_enabled": False,
            "recovery_certification_enabled": False,
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output")
    args = parser.parse_args()
    result = run_acceptance()
    if args.output:
        _write_json(Path(args.output), result)
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())

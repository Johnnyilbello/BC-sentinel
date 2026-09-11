from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Final

from .rescue_repair_engine import (
    CONFIRM_PREFIX,
    PLAN_SCHEMA,
    PROFILE as CORE_PROFILE,
    RepairOperation,
    RepairPlan,
    build_repair_plan,
    confirmation_token,
    execute_repair_plan,
    plan_to_dict,
    rollback_repair_session,
    sha256_file,
)

PROFILE: Final[str] = "v0.11.0-beta.3-rr4b"
OPERATIONS_SCHEMA: Final[str] = "bc-sentinel-rr4b-operations-v1"


def _atomic_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    os.close(fd)
    temp = Path(temp_name)
    try:
        temp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(temp, path)
    finally:
        try:
            temp.unlink(missing_ok=True)
        except OSError:
            pass


def _is_inside(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def load_operations_file(path: Path) -> list[RepairOperation]:
    payload = json.loads(path.read_text(encoding="utf-8-sig"))
    if payload.get("schema") != OPERATIONS_SCHEMA:
        raise ValueError("RR4B operations schema mismatch")
    if payload.get("approved") is not True:
        raise ValueError("RR4B operations file is not explicitly approved")
    raw_ops = payload.get("operations")
    if not isinstance(raw_ops, list) or not raw_ops:
        raise ValueError("RR4B operations file requires a non-empty operations list")
    operations: list[RepairOperation] = []
    for item in raw_ops:
        if not isinstance(item, dict):
            raise ValueError("RR4B operation must be an object")
        operation = RepairOperation(
            relative_path=str(item.get("relative_path") or ""),
            expected_sha256=str(item.get("expected_sha256") or ""),
            replacement_source=str(item.get("replacement_source") or ""),
            replacement_sha256=str(item.get("replacement_sha256") or ""),
            evidence_reference=str(item.get("evidence_reference") or ""),
        )
        operation.validate()
        operations.append(operation)
    return operations


def _canonical_plan_hash(plan: RepairPlan) -> str:
    data = json.dumps(
        plan.canonical_without_hash(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def load_plan_file(path: Path) -> RepairPlan:
    payload = json.loads(path.read_text(encoding="utf-8-sig"))
    if payload.get("schema") != PLAN_SCHEMA:
        raise ValueError("RR4B plan schema mismatch")
    raw_ops = payload.get("operations")
    if not isinstance(raw_ops, list) or not raw_ops:
        raise ValueError("RR4B plan operations missing")
    operations = tuple(
        RepairOperation(
            relative_path=str(item.get("relative_path") or ""),
            expected_sha256=str(item.get("expected_sha256") or ""),
            replacement_source=str(item.get("replacement_source") or ""),
            replacement_sha256=str(item.get("replacement_sha256") or ""),
            evidence_reference=str(item.get("evidence_reference") or ""),
        )
        for item in raw_ops
    )
    plan = RepairPlan(
        target_root=str(payload.get("target_root") or ""),
        target_fingerprint=str(payload.get("target_fingerprint") or ""),
        created_utc=str(payload.get("created_utc") or ""),
        operations=operations,
        schema=str(payload.get("schema") or ""),
        automatic_execution=bool(payload.get("automatic_execution", False)),
        recovery_certification=bool(payload.get("recovery_certification", False)),
        plan_sha256=str(payload.get("plan_sha256") or "").casefold(),
    )
    for operation in plan.operations:
        operation.validate()
    if plan.automatic_execution or plan.recovery_certification:
        raise ValueError("RR4B unsafe plan flags refused")
    if _canonical_plan_hash(plan) != plan.plan_sha256:
        raise ValueError("RR4B plan integrity mismatch")
    return plan


def create_plan_file(target_root: Path, operations_file: Path, output_plan: Path) -> dict:
    root = target_root.resolve(strict=True)
    output = output_plan.resolve()
    if _is_inside(output, root):
        raise ValueError("RR4B plan output must be outside offline target")
    operations = load_operations_file(operations_file)
    plan = build_repair_plan(root, operations)
    payload = plan_to_dict(plan)
    payload["portable_profile"] = PROFILE
    payload["core_profile"] = CORE_PROFILE
    payload["confirmation_required"] = True
    payload["automatic_action"] = False
    _atomic_json(output, payload)
    return {
        "profile": PROFILE,
        "passed": True,
        "phase": "plan",
        "plan_path": str(output),
        "plan_sha256": plan.plan_sha256,
        "confirmation_token": confirmation_token(plan),
        "operations": len(plan.operations),
        "automatic_action": False,
        "recovery_certified": False,
    }


def execute_plan_file(plan_path: Path, rollback_root: Path, confirmation: str) -> dict:
    plan = load_plan_file(plan_path)
    result = execute_repair_plan(plan, rollback_root, operator_confirmation=confirmation)
    return {
        **result,
        "profile": PROFILE,
        "core_profile": CORE_PROFILE,
        "phase": "execute",
        "automatic_action": False,
        "recovery_certified": False,
    }


def _preflight_manual_rollback(transaction_path: Path, confirmation: str) -> dict:
    payload = json.loads(transaction_path.read_text(encoding="utf-8-sig"))
    if str(payload.get("profile") or "") != CORE_PROFILE:
        raise ValueError("RR4B transaction core profile mismatch")
    plan_hash = str(payload.get("plan_sha256") or "").casefold()
    if not plan_hash:
        raise ValueError("RR4B transaction plan hash missing")
    expected_confirmation = CONFIRM_PREFIX + plan_hash[:16].upper()
    if confirmation != expected_confirmation:
        raise PermissionError("RR4B rollback confirmation does not match plan hash")
    if payload.get("state") != "applied":
        raise ValueError("RR4B rollback requires an applied transaction")
    target_root = Path(str(payload.get("target_root") or "")).resolve(strict=True)
    operations = payload.get("operations")
    if not isinstance(operations, list) or not operations:
        raise ValueError("RR4B transaction operations missing")

    checked = 0
    for item in operations:
        if not isinstance(item, dict):
            raise ValueError("RR4B transaction operation invalid")
        rel = str(item.get("relative_path") or "").replace("/", os.sep)
        target = (target_root / rel).resolve(strict=True)
        if not _is_inside(target, target_root):
            raise ValueError("RR4B rollback target escapes offline root")
        expected_after = str(item.get("after_sha256") or "").casefold()
        if len(expected_after) != 64:
            raise ValueError("RR4B rollback expected post-state hash missing")
        if sha256_file(target) != expected_after:
            raise RuntimeError(f"RR4B rollback post-state changed: {item.get('relative_path')}")
        backup = Path(str(item.get("backup_path") or "")).resolve(strict=True)
        expected_backup = str(item.get("backup_sha256") or "").casefold()
        if len(expected_backup) != 64 or sha256_file(backup) != expected_backup:
            raise RuntimeError(f"RR4B rollback backup provenance mismatch: {item.get('relative_path')}")
        checked += 1
    return {"payload": payload, "checked": checked}


def rollback_transaction_file(transaction_path: Path, confirmation: str) -> dict:
    preflight = _preflight_manual_rollback(transaction_path, confirmation)
    result = rollback_repair_session(transaction_path, operator_confirmation=confirmation)
    return {
        **result,
        "profile": PROFILE,
        "core_profile": CORE_PROFILE,
        "phase": "rollback",
        "preflight_checked": preflight["checked"],
        "automatic_action": False,
        "recovery_certified": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel RR4B Portable Repair Engine")
    sub = parser.add_subparsers(dest="command", required=True)

    plan_cmd = sub.add_parser("plan", help="Create an immutable RR4A repair plan from approved operations")
    plan_cmd.add_argument("--target-root", required=True)
    plan_cmd.add_argument("--operations-file", required=True)
    plan_cmd.add_argument("--output-plan", required=True)

    token_cmd = sub.add_parser("confirmation", help="Show the exact plan-bound operator confirmation token")
    token_cmd.add_argument("--plan", required=True)

    execute_cmd = sub.add_parser("execute", help="Execute an accepted plan against an offline target")
    execute_cmd.add_argument("--plan", required=True)
    execute_cmd.add_argument("--rollback-root", required=True)
    execute_cmd.add_argument("--confirmation", required=True)

    rollback_cmd = sub.add_parser("rollback", help="Rollback a completed RR4A transaction after post-state preflight")
    rollback_cmd.add_argument("--transaction", required=True)
    rollback_cmd.add_argument("--confirmation", required=True)

    args = parser.parse_args()
    try:
        if args.command == "plan":
            result = create_plan_file(Path(args.target_root), Path(args.operations_file), Path(args.output_plan))
        elif args.command == "confirmation":
            plan = load_plan_file(Path(args.plan))
            result = {
                "profile": PROFILE,
                "passed": True,
                "phase": "confirmation",
                "plan_sha256": plan.plan_sha256,
                "confirmation_token": confirmation_token(plan),
                "automatic_action": False,
            }
        elif args.command == "execute":
            result = execute_plan_file(Path(args.plan), Path(args.rollback_root), str(args.confirmation))
        else:
            result = rollback_transaction_file(Path(args.transaction), str(args.confirmation))
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except Exception as exc:
        print(
            json.dumps(
                {
                    "profile": PROFILE,
                    "passed": False,
                    "phase": str(getattr(args, "command", "unknown")),
                    "reason": f"{type(exc).__name__}: {exc}",
                    "automatic_action": False,
                    "recovery_certified": False,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

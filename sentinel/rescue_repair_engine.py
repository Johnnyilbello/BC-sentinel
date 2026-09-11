from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Final

PROFILE: Final[str] = "v0.11.0-beta.3-rr4a"
PLAN_SCHEMA: Final[str] = "bc-sentinel-rr4a-plan-v1"
TRANSACTION_SCHEMA: Final[str] = "bc-sentinel-rr4a-transaction-v1"
CONFIRM_PREFIX: Final[str] = "CONFIRM-RR4A-"


@dataclass(frozen=True)
class RepairOperation:
    relative_path: str
    expected_sha256: str
    replacement_source: str
    replacement_sha256: str
    evidence_reference: str

    def validate(self) -> None:
        rel = str(self.relative_path or "").strip().replace("\\", "/")
        if not rel or rel.startswith("/") or ":" in rel or any(part in {"", ".", ".."} for part in rel.split("/")):
            raise ValueError("RR4A operation relative_path invalid")
        for label, value in (("expected_sha256", self.expected_sha256), ("replacement_sha256", self.replacement_sha256)):
            digest = str(value or "").casefold()
            if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
                raise ValueError(f"RR4A {label} invalid")
        if not str(self.evidence_reference or "").strip():
            raise ValueError("RR4A evidence_reference required")


@dataclass(frozen=True)
class RepairPlan:
    target_root: str
    target_fingerprint: str
    created_utc: str
    operations: tuple[RepairOperation, ...]
    schema: str = PLAN_SCHEMA
    automatic_execution: bool = False
    recovery_certification: bool = False
    plan_sha256: str = ""

    def canonical_without_hash(self) -> dict:
        return {
            "schema": self.schema,
            "target_root": self.target_root,
            "target_fingerprint": self.target_fingerprint,
            "created_utc": self.created_utc,
            "automatic_execution": False,
            "recovery_certification": False,
            "operations": [asdict(op) for op in self.operations],
        }


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_json(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _is_reparse_or_symlink(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        st = path.stat(follow_symlinks=False)
        attrs = int(getattr(st, "st_file_attributes", 0) or 0)
        reparse = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
        return bool(attrs & reparse)
    except OSError:
        return True


def _validate_offline_root(root: Path) -> Path:
    resolved = root.resolve(strict=True)
    if not resolved.is_dir() or _is_reparse_or_symlink(resolved):
        raise ValueError("RR4A offline target root invalid")
    system_hive = resolved / "Windows" / "System32" / "config" / "SYSTEM"
    kernel = resolved / "Windows" / "System32" / "ntoskrnl.exe"
    if not system_hive.is_file() or not kernel.is_file():
        raise ValueError("RR4A target is not a validated offline Windows root")
    return resolved


def _fingerprint_root(root: Path) -> str:
    resolved = _validate_offline_root(root)
    system_hive = resolved / "Windows" / "System32" / "config" / "SYSTEM"
    kernel = resolved / "Windows" / "System32" / "ntoskrnl.exe"
    seed = "|".join((str(resolved).casefold(), sha256_file(system_hive), sha256_file(kernel)))
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def _relative_is_forbidden(relative_path: str) -> bool:
    rel = relative_path.replace("\\", "/").casefold().strip("/")
    forbidden_prefixes = (
        "boot/",
        "efi/",
        "windows/boot/",
        "windows/system32/config/",
    )
    forbidden_exact = {
        "bootmgr",
        "windows/system32/ntoskrnl.exe",
    }
    return rel in forbidden_exact or any(rel.startswith(prefix) for prefix in forbidden_prefixes)


def _resolve_target(root: Path, relative_path: str) -> Path:
    rel_text = relative_path.replace("\\", "/")
    if _relative_is_forbidden(rel_text):
        raise ValueError("RR4A boot/registry/identity target refused in first checkpoint")
    rel = Path(rel_text.replace("/", os.sep))
    if rel.is_absolute() or ".." in rel.parts:
        raise ValueError("RR4A target path traversal refused")
    candidate = root / rel
    parent = candidate.parent.resolve(strict=True)
    root_resolved = root.resolve(strict=True)
    try:
        parent.relative_to(root_resolved)
    except ValueError as exc:
        raise ValueError("RR4A target path escapes offline root") from exc
    current = root_resolved
    for part in rel.parts[:-1]:
        current = current / part
        if _is_reparse_or_symlink(current):
            raise ValueError("RR4A symlink/reparse path refused")
    if candidate.exists() and _is_reparse_or_symlink(candidate):
        raise ValueError("RR4A symlink/reparse target refused")
    return candidate


def _assert_external_source(source: Path, root: Path) -> None:
    source_resolved = source.resolve(strict=True)
    try:
        source_resolved.relative_to(root.resolve(strict=True))
        raise ValueError("RR4A replacement source must be outside offline target")
    except ValueError as exc:
        if str(exc).startswith("RR4A replacement source"):
            raise


def build_repair_plan(target_root: Path, operations: list[RepairOperation]) -> RepairPlan:
    root = _validate_offline_root(target_root)
    fingerprint = _fingerprint_root(root)
    if not operations:
        raise ValueError("RR4A repair plan requires at least one operation")
    normalized: list[RepairOperation] = []
    seen: set[str] = set()
    for op in operations:
        op.validate()
        key = op.relative_path.replace("\\", "/").casefold()
        if key in seen:
            raise ValueError("RR4A duplicate target operation refused")
        seen.add(key)
        target = _resolve_target(root, op.relative_path)
        replacement = Path(op.replacement_source).resolve(strict=True)
        _assert_external_source(replacement, root)
        if not target.is_file():
            raise ValueError(f"RR4A target file missing: {op.relative_path}")
        if not replacement.is_file() or _is_reparse_or_symlink(replacement):
            raise ValueError("RR4A replacement source invalid")
        if sha256_file(target) != op.expected_sha256.casefold():
            raise ValueError(f"RR4A pre-state hash mismatch while planning: {op.relative_path}")
        if sha256_file(replacement) != op.replacement_sha256.casefold():
            raise ValueError(f"RR4A replacement provenance mismatch: {op.relative_path}")
        normalized.append(op)
    created = _utc_now()
    draft = RepairPlan(str(root), fingerprint, created, tuple(normalized))
    plan_hash = _sha256_bytes(_canonical_json(draft.canonical_without_hash()))
    return RepairPlan(str(root), fingerprint, created, tuple(normalized), plan_sha256=plan_hash)


def confirmation_token(plan: RepairPlan) -> str:
    return CONFIRM_PREFIX + plan.plan_sha256[:16].upper()


def plan_to_dict(plan: RepairPlan) -> dict:
    payload = plan.canonical_without_hash()
    payload["plan_sha256"] = plan.plan_sha256
    return payload


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


def _atomic_copy(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=destination.name + ".", suffix=".rr4tmp", dir=str(destination.parent))
    os.close(fd)
    temp = Path(temp_name)
    try:
        shutil.copy2(source, temp, follow_symlinks=False)
        os.replace(temp, destination)
    finally:
        try:
            temp.unlink(missing_ok=True)
        except OSError:
            pass


def _validate_rollback_root(rollback_root: Path, target_root: Path) -> Path:
    rollback = rollback_root.resolve()
    root = target_root.resolve(strict=True)
    try:
        rollback.relative_to(root)
        raise ValueError("RR4A rollback store must be outside offline target")
    except ValueError as exc:
        if str(exc).startswith("RR4A rollback store"):
            raise
    rollback.mkdir(parents=True, exist_ok=True)
    if _is_reparse_or_symlink(rollback):
        raise ValueError("RR4A rollback root symlink/reparse refused")
    return rollback


def execute_repair_plan(plan: RepairPlan, rollback_root: Path, *, operator_confirmation: str) -> dict:
    expected_hash = _sha256_bytes(_canonical_json(plan.canonical_without_hash()))
    if plan.schema != PLAN_SCHEMA or expected_hash != plan.plan_sha256:
        raise ValueError("RR4A plan integrity mismatch")
    if operator_confirmation != confirmation_token(plan):
        raise PermissionError("RR4A explicit operator confirmation does not match plan hash")
    if plan.automatic_execution or plan.recovery_certification:
        raise ValueError("RR4A unsafe plan flags refused")

    root = _validate_offline_root(Path(plan.target_root))
    if _fingerprint_root(root) != plan.target_fingerprint:
        raise ValueError("RR4A target fingerprint mismatch")
    rollback = _validate_rollback_root(rollback_root, root)
    session_id = "RR4A-" + plan.plan_sha256[:16].upper()
    session_root = rollback / session_id
    audit_path = rollback / f"{session_id}-audit.jsonl"
    transaction_path = session_root / "transaction.json"
    applied: list[dict] = []

    def audit(stage: str, status: str, reason: str, **extra: object) -> None:
        record = {
            "profile": PROFILE,
            "session_id": session_id,
            "plan_sha256": plan.plan_sha256,
            "stage": stage,
            "status": status,
            "reason": reason,
            "utc": _utc_now(),
            **extra,
        }
        with audit_path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")

    def persist_transaction(state: str) -> None:
        _atomic_json(
            transaction_path,
            {
                "schema": TRANSACTION_SCHEMA,
                "profile": PROFILE,
                "session_id": session_id,
                "plan_sha256": plan.plan_sha256,
                "target_root": str(root),
                "target_fingerprint": plan.target_fingerprint,
                "state": state,
                "automatic_action": False,
                "recovery_certified": False,
                "operations": applied,
            },
        )

    try:
        audit("transaction_start", "ok", "operator_confirmed_exact_plan", operations=len(plan.operations))
        persist_transaction("started")
        for index, op in enumerate(plan.operations):
            op.validate()
            target = _resolve_target(root, op.relative_path)
            replacement = Path(op.replacement_source).resolve(strict=True)
            _assert_external_source(replacement, root)
            before_hash = sha256_file(target)
            if before_hash != op.expected_sha256.casefold():
                raise RuntimeError(f"stale_precondition:{op.relative_path}")
            replacement_hash = sha256_file(replacement)
            if replacement_hash != op.replacement_sha256.casefold():
                raise RuntimeError(f"replacement_provenance_changed:{op.relative_path}")
            backup = session_root / "backup" / f"{index:04d}" / Path(op.relative_path).name
            backup.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(target, backup, follow_symlinks=False)
            backup_hash = sha256_file(backup)
            if backup_hash != before_hash:
                raise RuntimeError(f"rollback_copy_verification_failed:{op.relative_path}")
            record = {
                "relative_path": op.relative_path,
                "before_sha256": before_hash,
                "after_sha256": op.replacement_sha256.casefold(),
                "backup_path": str(backup),
                "backup_sha256": backup_hash,
                "evidence_reference": op.evidence_reference,
                "status": "backup_verified",
            }
            applied.append(record)
            persist_transaction("applying")
            _atomic_copy(replacement, target)
            after_hash = sha256_file(target)
            if after_hash != op.replacement_sha256.casefold():
                raise RuntimeError(f"post_state_verification_failed:{op.relative_path}")
            record["status"] = "applied_verified"
            persist_transaction("applying")
            audit("operation_applied", "ok", "replacement_verified", relative_path=op.relative_path, before_sha256=before_hash, after_sha256=after_hash, rollback_sha256=backup_hash)
        persist_transaction("applied")
        audit("transaction_complete", "ok", "all_operations_applied_and_verified", applied=len(applied))
        return {
            "profile": PROFILE,
            "passed": True,
            "session_id": session_id,
            "plan_sha256": plan.plan_sha256,
            "applied": len(applied),
            "rollback_available": True,
            "recovery_certified": False,
            "automatic_action": False,
            "transaction_path": str(transaction_path),
            "audit_path": str(audit_path),
        }
    except Exception as exc:
        rollback_errors = _rollback_records(root, applied, audit)
        persist_transaction("rolled_back_after_failure" if not rollback_errors else "rollback_failed")
        audit("transaction_fail", "fail", f"{type(exc).__name__}: {exc}", applied=len(applied), rollback_errors=rollback_errors)
        raise RuntimeError(f"RR4A transaction failed and rollback {'succeeded' if not rollback_errors else 'had errors'}: {type(exc).__name__}: {exc}") from exc


def _rollback_records(root: Path, records: list[dict], audit) -> list[str]:
    rollback_errors: list[str] = []
    for record in reversed(records):
        try:
            target = _resolve_target(root, str(record["relative_path"]))
            backup = Path(str(record["backup_path"])).resolve(strict=True)
            if sha256_file(backup) != str(record["backup_sha256"]):
                raise RuntimeError("backup_hash_mismatch")
            _atomic_copy(backup, target)
            restored = sha256_file(target)
            if restored != str(record["before_sha256"]):
                raise RuntimeError("restored_hash_mismatch")
            record["status"] = "rolled_back_verified"
            audit("rollback_operation", "ok", "restored_verified", relative_path=record["relative_path"], restored_sha256=restored)
        except Exception as rollback_exc:
            msg = f"{record.get('relative_path')}:{type(rollback_exc).__name__}:{rollback_exc}"
            rollback_errors.append(msg)
            audit("rollback_operation", "fail", msg, relative_path=record.get("relative_path", ""))
    audit("rollback_complete", "ok" if not rollback_errors else "fail", "rollback_finished", rollback_errors=rollback_errors)
    return rollback_errors


def rollback_repair_session(transaction_path: Path, *, operator_confirmation: str) -> dict:
    payload = json.loads(transaction_path.read_text(encoding="utf-8"))
    if payload.get("schema") != TRANSACTION_SCHEMA or payload.get("profile") != PROFILE:
        raise ValueError("RR4A transaction manifest schema/profile mismatch")
    plan_hash = str(payload.get("plan_sha256") or "")
    expected_confirmation = CONFIRM_PREFIX + plan_hash[:16].upper()
    if operator_confirmation != expected_confirmation:
        raise PermissionError("RR4A rollback confirmation does not match plan hash")
    if payload.get("state") != "applied":
        raise ValueError("RR4A manual rollback requires an applied transaction")
    root = _validate_offline_root(Path(str(payload["target_root"])))
    if _fingerprint_root(root) != str(payload["target_fingerprint"]):
        raise ValueError("RR4A rollback target fingerprint mismatch")
    audit_path = transaction_path.parent.parent / f"{payload['session_id']}-audit.jsonl"

    def audit(stage: str, status: str, reason: str, **extra: object) -> None:
        with audit_path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps({"profile": PROFILE, "session_id": payload["session_id"], "plan_sha256": plan_hash, "stage": stage, "status": status, "reason": reason, "utc": _utc_now(), **extra}, sort_keys=True) + "\n")

    records = list(payload.get("operations") or [])
    errors = _rollback_records(root, records, audit)
    payload["operations"] = records
    payload["state"] = "rolled_back" if not errors else "rollback_failed"
    payload["recovery_certified"] = False
    _atomic_json(transaction_path, payload)
    if errors:
        raise RuntimeError("RR4A manual rollback had errors: " + "; ".join(errors))
    return {"profile": PROFILE, "passed": True, "session_id": payload["session_id"], "rolled_back": len(records), "recovery_certified": False, "automatic_action": False}

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

PROFILE: Final[str] = "v0.11.0-beta.3-rr4"
PLAN_SCHEMA: Final[str] = "bc-sentinel-rr4-plan-v1"
CONFIRM_PREFIX: Final[str] = "CONFIRM-RR4-"


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
            raise ValueError("RR4 operation relative_path invalid")
        for label, value in (("expected_sha256", self.expected_sha256), ("replacement_sha256", self.replacement_sha256)):
            digest = str(value or "").casefold()
            if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
                raise ValueError(f"RR4 {label} invalid")
        if not str(self.evidence_reference or "").strip():
            raise ValueError("RR4 evidence_reference required")


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


def _fingerprint_root(root: Path) -> str:
    resolved = root.resolve(strict=True)
    marker = resolved / "Windows" / "System32" / "config" / "SYSTEM"
    kernel = resolved / "Windows" / "System32" / "ntoskrnl.exe"
    if not marker.is_file() or not kernel.is_file():
        raise ValueError("RR4 target is not a validated offline Windows root")
    seed = f"{resolved}|{marker.stat().st_size}|{kernel.stat().st_size}".casefold().encode("utf-8")
    return hashlib.sha256(seed).hexdigest()


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


def _resolve_target(root: Path, relative_path: str) -> Path:
    rel = Path(relative_path.replace("/", os.sep))
    if rel.is_absolute() or ".." in rel.parts:
        raise ValueError("RR4 target path traversal refused")
    candidate = root / rel
    parent = candidate.parent.resolve(strict=True)
    root_resolved = root.resolve(strict=True)
    try:
        parent.relative_to(root_resolved)
    except ValueError as exc:
        raise ValueError("RR4 target path escapes offline root") from exc
    current = root_resolved
    for part in rel.parts[:-1]:
        current = current / part
        if _is_reparse_or_symlink(current):
            raise ValueError("RR4 symlink/reparse path refused")
    if candidate.exists() and _is_reparse_or_symlink(candidate):
        raise ValueError("RR4 symlink/reparse target refused")
    return candidate


def build_repair_plan(target_root: Path, operations: list[RepairOperation]) -> RepairPlan:
    root = target_root.resolve(strict=True)
    fingerprint = _fingerprint_root(root)
    if not operations:
        raise ValueError("RR4 repair plan requires at least one operation")
    normalized: list[RepairOperation] = []
    for op in operations:
        op.validate()
        target = _resolve_target(root, op.relative_path)
        replacement = Path(op.replacement_source).resolve(strict=True)
        if not target.is_file():
            raise ValueError(f"RR4 target file missing: {op.relative_path}")
        if not replacement.is_file() or _is_reparse_or_symlink(replacement):
            raise ValueError("RR4 replacement source invalid")
        if sha256_file(target) != op.expected_sha256.casefold():
            raise ValueError(f"RR4 pre-state hash mismatch while planning: {op.relative_path}")
        if sha256_file(replacement) != op.replacement_sha256.casefold():
            raise ValueError(f"RR4 replacement provenance mismatch: {op.relative_path}")
        normalized.append(op)
    created = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    draft = RepairPlan(str(root), fingerprint, created, tuple(normalized))
    plan_hash = _sha256_bytes(_canonical_json(draft.canonical_without_hash()))
    return RepairPlan(str(root), fingerprint, created, tuple(normalized), plan_sha256=plan_hash)


def confirmation_token(plan: RepairPlan) -> str:
    return CONFIRM_PREFIX + plan.plan_sha256[:16].upper()


def plan_to_dict(plan: RepairPlan) -> dict:
    payload = plan.canonical_without_hash()
    payload["plan_sha256"] = plan.plan_sha256
    return payload


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


def execute_repair_plan(plan: RepairPlan, rollback_root: Path, *, operator_confirmation: str) -> dict:
    expected_hash = _sha256_bytes(_canonical_json(plan.canonical_without_hash()))
    if plan.schema != PLAN_SCHEMA or expected_hash != plan.plan_sha256:
        raise ValueError("RR4 plan integrity mismatch")
    if operator_confirmation != confirmation_token(plan):
        raise PermissionError("RR4 explicit operator confirmation does not match plan hash")
    if plan.automatic_execution or plan.recovery_certification:
        raise ValueError("RR4 unsafe plan flags refused")

    root = Path(plan.target_root).resolve(strict=True)
    if _fingerprint_root(root) != plan.target_fingerprint:
        raise ValueError("RR4 target fingerprint mismatch")
    rollback = rollback_root.resolve()
    try:
        rollback.relative_to(root)
        raise ValueError("RR4 rollback store must be outside offline target")
    except ValueError as exc:
        if str(exc).startswith("RR4 rollback store"):
            raise
    rollback.mkdir(parents=True, exist_ok=True)
    session_id = "RR4-" + plan.plan_sha256[:16].upper()
    audit_path = rollback / f"{session_id}-audit.jsonl"
    applied: list[tuple[Path, Path, str]] = []

    def audit(stage: str, status: str, reason: str, **extra: object) -> None:
        record = {
            "profile": PROFILE,
            "session_id": session_id,
            "plan_sha256": plan.plan_sha256,
            "stage": stage,
            "status": status,
            "reason": reason,
            "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            **extra,
        }
        with audit_path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")

    try:
        audit("transaction_start", "ok", "operator_confirmed_exact_plan", operations=len(plan.operations))
        for index, op in enumerate(plan.operations):
            op.validate()
            target = _resolve_target(root, op.relative_path)
            replacement = Path(op.replacement_source).resolve(strict=True)
            before_hash = sha256_file(target)
            if before_hash != op.expected_sha256.casefold():
                raise RuntimeError(f"stale_precondition:{op.relative_path}")
            replacement_hash = sha256_file(replacement)
            if replacement_hash != op.replacement_sha256.casefold():
                raise RuntimeError(f"replacement_provenance_changed:{op.relative_path}")
            backup = rollback / session_id / f"{index:04d}" / Path(op.relative_path).name
            backup.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(target, backup, follow_symlinks=False)
            backup_hash = sha256_file(backup)
            if backup_hash != before_hash:
                raise RuntimeError(f"rollback_copy_verification_failed:{op.relative_path}")
            _atomic_copy(replacement, target)
            after_hash = sha256_file(target)
            if after_hash != op.replacement_sha256.casefold():
                raise RuntimeError(f"post_state_verification_failed:{op.relative_path}")
            applied.append((target, backup, before_hash))
            audit("operation_applied", "ok", "replacement_verified", relative_path=op.relative_path, before_sha256=before_hash, after_sha256=after_hash, rollback_sha256=backup_hash)
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
            "audit_path": str(audit_path),
        }
    except Exception as exc:
        rollback_errors: list[str] = []
        audit("transaction_fail", "fail", f"{type(exc).__name__}: {exc}", applied=len(applied))
        for target, backup, before_hash in reversed(applied):
            try:
                _atomic_copy(backup, target)
                restored = sha256_file(target)
                if restored != before_hash:
                    raise RuntimeError("restored_hash_mismatch")
                audit("rollback_operation", "ok", "restored_verified", target=str(target), restored_sha256=restored)
            except Exception as rollback_exc:
                msg = f"{target}:{type(rollback_exc).__name__}:{rollback_exc}"
                rollback_errors.append(msg)
                audit("rollback_operation", "fail", msg, target=str(target))
        audit("rollback_complete", "ok" if not rollback_errors else "fail", "rollback_finished", rollback_errors=rollback_errors)
        raise RuntimeError(f"RR4 transaction failed and rollback {'succeeded' if not rollback_errors else 'had errors'}: {type(exc).__name__}: {exc}") from exc

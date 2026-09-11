from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from sentinel import rescue_console as b40
from sentinel import rescue_console_guided_scan as b41
from sentinel import rescue_integrity_certification as rr6
from sentinel import rescue_repair_portable as rr4b

PROFILE: Final[str] = "v0.11.0-beta.4-b42"
HANDOFF_SCHEMA: Final[str] = "bc-sentinel-beta4-guided-repair-handoff-v1"


@dataclass(frozen=True)
class GuidedRepairPrepareRequest:
    target_root: Path
    workspace: Path
    trusted_scan: Path
    operations_file: Path


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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


def _append_jsonl(path: Path, row: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(row, sort_keys=True) + "\n")


def _outside_target(path: Path, root: Path, *, must_exist: bool = False) -> Path:
    resolved = path.resolve(strict=must_exist)
    target = root.resolve(strict=True)
    try:
        resolved.relative_to(target)
        raise ValueError("B4-2 repair evidence/output must remain outside offline target")
    except ValueError as exc:
        if str(exc).startswith("B4-2 repair evidence/output"):
            raise
    return resolved


def _load_json(path: Path) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(payload, dict):
        raise ValueError("B4-2 JSON root must be an object")
    return payload


def _trusted_scan_record(root: Path, workspace: Path, scan_path: Path) -> dict:
    inventory = b41.inventory_evidence(root, workspace, scan_path)
    record = next(item for item in inventory["records"] if item["kind"] == "rr3_scan")
    if record["trust"] != b41.TRUST_TRUSTED:
        raise ValueError("B4-2 repair handoff requires TRUSTED RR3 evidence: " + ",".join(record["reasons"]))
    return record


def _validate_operations_binding(operations_file: Path, root: Path, scan_record: dict) -> dict:
    resolved = _outside_target(operations_file, root, must_exist=True)
    if not resolved.is_file():
        raise ValueError("B4-2 operations file missing")
    payload = _load_json(resolved)
    if payload.get("schema") != rr4b.OPERATIONS_SCHEMA:
        raise ValueError("B4-2 operations schema mismatch")
    if payload.get("approved") is not True:
        raise PermissionError("B4-2 operations file is not explicitly approved")
    if str(payload.get("target_fingerprint") or "").casefold() != rr6.target_fingerprint(root):
        raise ValueError("B4-2 operations target fingerprint mismatch")
    scan_sha = str(scan_record.get("sha256") or "").casefold()
    if len(scan_sha) != 64:
        raise ValueError("B4-2 trusted scan SHA256 missing")
    if str(payload.get("source_scan_sha256") or "").casefold() != scan_sha:
        raise ValueError("B4-2 operations are not bound to trusted RR3 evidence")
    operations = payload.get("operations")
    if not isinstance(operations, list) or not operations:
        raise ValueError("B4-2 approved operations list missing")
    for item in operations:
        if not isinstance(item, dict) or not str(item.get("evidence_reference") or "").strip():
            raise ValueError("B4-2 operation lacks evidence reference")
    return payload


def prepare_repair_handoff(request: GuidedRepairPrepareRequest) -> dict:
    started = time.perf_counter()
    root = rr6.validate_offline_windows_root(request.target_root)
    workspace = b40.validate_workspace(request.workspace, root)
    fingerprint = rr6.target_fingerprint(root)
    session_id = "B42-" + fingerprint[:16].upper()
    correlation_id = hashlib.sha256((session_id + "|guided-repair-handoff").encode("utf-8")).hexdigest()[:24]
    audit_path = workspace / "b42-audit.jsonl"

    def audit(stage: str, status: str, reason: str, **extra: object) -> None:
        _append_jsonl(audit_path, {
            "profile": PROFILE,
            "session_id": session_id,
            "correlation_id": correlation_id,
            "target_fingerprint": fingerprint,
            "stage": stage,
            "status": status,
            "reason": reason,
            "elapsed_ms": round((time.perf_counter() - started) * 1000.0, 3),
            **extra,
        })

    audit("repair_handoff_prepare", "start", "validating_trusted_scan_and_operator_operations")
    scan_record = _trusted_scan_record(root, workspace, request.trusted_scan)
    operations_payload = _validate_operations_binding(request.operations_file, root, scan_record)

    repair_dir = workspace / "rr4b"
    repair_dir.mkdir(parents=True, exist_ok=True)
    plan_path = repair_dir / "repair-plan.json"
    plan_result = rr4b.create_plan_file(root, request.operations_file, plan_path)
    plan = rr4b.load_plan_file(plan_path)
    token = rr4b.confirmation_token(plan)

    summary = {
        "schema": HANDOFF_SCHEMA,
        "profile": PROFILE,
        "created_utc": _utc_now(),
        "session_id": session_id,
        "correlation_id": correlation_id,
        "target_fingerprint": fingerprint,
        "trusted_scan_path": str(Path(scan_record["path"]).resolve(strict=True)),
        "trusted_scan_sha256": scan_record["sha256"],
        "operations_file": str(request.operations_file.resolve(strict=True)),
        "operations": len(operations_payload["operations"]),
        "plan_path": str(plan_path.resolve(strict=True)),
        "plan_sha256": plan_result["plan_sha256"],
        "confirmation_token": token,
        "operator_confirmation_required": True,
        "execution_performed": False,
        "rollback_performed": False,
        "automatic_execution": False,
        "automatic_repair": False,
        "automatic_quarantine": False,
        "recovery_certified": False,
        "rr4b_execution_delegated": True,
        "rr4b_rollback_delegated": True,
        "audit_path": str(audit_path),
    }
    _atomic_json(workspace / "b42-repair-handoff.json", summary)
    audit(
        "repair_handoff_prepare",
        "ok",
        "rr4b_plan_created_operator_confirmation_required",
        operations=summary["operations"],
        plan_sha256=summary["plan_sha256"],
        scan_sha256=summary["trusted_scan_sha256"],
        execution_performed=False,
    )
    return summary


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="BC Sentinel Beta4 B4-2 Guided RR4B Repair Handoff")
    parser.add_argument("--target-root", required=True)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--trusted-scan", required=True)
    parser.add_argument("--operations-file", required=True)
    args = parser.parse_args(argv)
    try:
        result = prepare_repair_handoff(GuidedRepairPrepareRequest(
            Path(args.target_root), Path(args.workspace), Path(args.trusted_scan), Path(args.operations_file)
        ))
        print(json.dumps({"passed": True, **result}, indent=2, sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({
            "passed": False,
            "profile": PROFILE,
            "stage": "b42_prepare_handoff",
            "reason": f"{type(exc).__name__}: {exc}",
            "automatic_execution": False,
            "recovery_certified": False,
        }, indent=2, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

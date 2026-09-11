from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from sentinel import rescue_integrity_certification as rr6

PROFILE: Final[str] = "v0.11.0-beta.4-b40"
PLAN_SCHEMA: Final[str] = "bc-sentinel-beta4-rescue-console-plan-v1"
STAGE_ORDER: Final[tuple[str, ...]] = (
    "target_validation",
    "evidence_inventory",
    "offline_scan",
    "repair_review",
    "safe_data_rescue",
    "integrity_certification",
)


@dataclass(frozen=True)
class RescueConsoleRequest:
    target_root: Path
    workspace: Path


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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


def _outside_target(path: Path, target_root: Path, *, must_exist: bool = False) -> Path:
    resolved = path.resolve(strict=must_exist)
    root = target_root.resolve(strict=True)
    try:
        resolved.relative_to(root)
        raise ValueError("B4-0 workspace/output must be outside offline target")
    except ValueError as exc:
        if str(exc).startswith("B4-0 workspace/output"):
            raise
    return resolved


def validate_workspace(workspace: Path, target_root: Path) -> Path:
    root = rr6.validate_offline_windows_root(target_root)
    resolved = _outside_target(workspace, root, must_exist=False)
    resolved.mkdir(parents=True, exist_ok=True)
    if not resolved.is_dir() or _is_reparse_or_symlink(resolved):
        raise ValueError("B4-0 workspace symlink/reparse or invalid directory refused")
    return resolved.resolve(strict=True)


def _module_inventory() -> dict[str, bool]:
    modules = {
        "rr1_portable": "sentinel.rescue_portable",
        "rr2_rescue_usb": "sentinel.rescue_usb",
        "rr3_offline_scanner": "sentinel.rescue_offline_scanner",
        "rr4a_repair_core": "sentinel.rescue_repair_engine",
        "rr4b_repair_portable": "sentinel.rescue_repair_portable",
        "rr5_safe_data_rescue": "sentinel.rescue_data_rescue",
        "rr6_integrity_certification": "sentinel.rescue_integrity_certification",
    }
    result: dict[str, bool] = {}
    for label, module_name in modules.items():
        try:
            __import__(module_name)
            result[label] = True
        except Exception:
            result[label] = False
    return result


def _stage_contracts() -> list[dict]:
    return [
        {
            "stage": "target_validation",
            "mode": "read_only",
            "operator_gate": False,
            "automatic_execution": False,
            "purpose": "validate_offline_windows_target",
        },
        {
            "stage": "evidence_inventory",
            "mode": "read_only",
            "operator_gate": False,
            "automatic_execution": False,
            "purpose": "inventory_existing_rescue_evidence",
        },
        {
            "stage": "offline_scan",
            "mode": "planned_only",
            "operator_gate": True,
            "automatic_execution": False,
            "purpose": "rr3_offline_threat_scan",
        },
        {
            "stage": "repair_review",
            "mode": "planned_only",
            "operator_gate": True,
            "automatic_execution": False,
            "purpose": "rr4_plan_review_confirmation_required",
        },
        {
            "stage": "safe_data_rescue",
            "mode": "planned_only",
            "operator_gate": True,
            "automatic_execution": False,
            "purpose": "rr5_explicit_selection_data_rescue",
        },
        {
            "stage": "integrity_certification",
            "mode": "planned_only",
            "operator_gate": True,
            "automatic_execution": False,
            "purpose": "rr6_evidence_based_certification",
        },
    ]


def build_session_plan(request: RescueConsoleRequest) -> dict:
    root = rr6.validate_offline_windows_root(request.target_root)
    workspace = validate_workspace(request.workspace, root)
    fingerprint = rr6.target_fingerprint(root)
    session_id = "B40-" + fingerprint[:16].upper()
    correlation_id = _sha256_bytes((session_id + "|rescue-console").encode("utf-8"))[:24]
    modules = _module_inventory()
    stages = _stage_contracts()
    if tuple(item["stage"] for item in stages) != STAGE_ORDER:
        raise RuntimeError("B4-0 stage contract order mismatch")

    stable_core = {
        "schema": PLAN_SCHEMA,
        "profile": PROFILE,
        "target_fingerprint": fingerprint,
        "session_id": session_id,
        "correlation_id": correlation_id,
        "module_inventory": modules,
        "stages": stages,
        "safety": {
            "target_read_only": True,
            "automatic_execution": False,
            "automatic_repair": False,
            "automatic_quarantine": False,
            "process_kill": False,
            "host_isolation": False,
            "registry_write": False,
            "boot_write": False,
            "file_delete": False,
            "format_or_reimage_suppressed": False,
        },
    }
    plan_hash = _sha256_bytes(_canonical_json(stable_core))
    return {
        **stable_core,
        "created_utc": _utc_now(),
        "target_root": str(root),
        "workspace": str(workspace),
        "plan_sha256": plan_hash,
    }


def write_session_plan(plan: dict, output_path: Path, target_root: Path) -> Path:
    root = rr6.validate_offline_windows_root(target_root)
    output = _outside_target(output_path, root, must_exist=False)
    output.parent.mkdir(parents=True, exist_ok=True)
    if _is_reparse_or_symlink(output.parent):
        raise ValueError("B4-0 output parent symlink/reparse refused")
    fd, temp_name = tempfile.mkstemp(prefix=output.name + ".", suffix=".tmp", dir=str(output.parent))
    os.close(fd)
    temp = Path(temp_name)
    try:
        temp.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(temp, output)
    finally:
        try:
            temp.unlink(missing_ok=True)
        except OSError:
            pass
    return output


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="BC Sentinel Beta4 Rescue Console B4-0 read-only planner")
    parser.add_argument("--target-root", required=True)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--output-plan", required=True)
    args = parser.parse_args(argv)
    try:
        request = RescueConsoleRequest(Path(args.target_root), Path(args.workspace))
        plan = build_session_plan(request)
        path = write_session_plan(plan, Path(args.output_plan), Path(args.target_root))
        print(json.dumps({
            "passed": True,
            "profile": PROFILE,
            "session_id": plan["session_id"],
            "correlation_id": plan["correlation_id"],
            "target_fingerprint": plan["target_fingerprint"],
            "plan_sha256": plan["plan_sha256"],
            "output_plan": str(path),
            "automatic_execution": False,
        }, indent=2))
        return 0
    except Exception as exc:
        print(json.dumps({"passed": False, "profile": PROFILE, "error": f"{type(exc).__name__}: {exc}"}, indent=2))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

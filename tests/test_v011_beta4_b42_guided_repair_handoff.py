from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from sentinel import rescue_console_guided_repair as b42
from sentinel import rescue_integrity_certification as rr6
from sentinel import rescue_offline_scanner as rr3
from sentinel import rescue_repair_portable as rr4b


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _fixture(tmp_path: Path):
    root = tmp_path / "offline-target"
    config = root / "Windows/System32/config"
    drivers = root / "Windows/System32/drivers"
    config.mkdir(parents=True)
    drivers.mkdir(parents=True)
    (config / "SYSTEM").write_bytes(b"B42 SYSTEM")
    (config / "SOFTWARE").write_bytes(b"B42 SOFTWARE")
    (root / "Windows/System32/ntoskrnl.exe").write_bytes(b"MZ B42 KERNEL")
    target = drivers / "demo.sys"
    target.write_bytes(b"ORIGINAL B42 DRIVER")

    workspace = tmp_path / "workspace"
    scan_dir = workspace / "rr3"
    rr3.scan_offline_windows(root, scan_dir, limits=rr3.OfflineScanLimits(max_files=128, max_file_bytes=1024 * 1024))
    scan = scan_dir / "rr3-offline-scan.json"

    replacement = tmp_path / "trusted-replacement.sys"
    replacement.write_bytes(b"REPLACEMENT B42 DRIVER")
    operations = workspace / "approved-operations.json"
    operations.parent.mkdir(parents=True, exist_ok=True)
    operations.write_text(json.dumps({
        "schema": rr4b.OPERATIONS_SCHEMA,
        "approved": True,
        "target_fingerprint": rr6.target_fingerprint(root),
        "source_scan_sha256": _sha(scan),
        "operations": [{
            "relative_path": "Windows/System32/drivers/demo.sys",
            "expected_sha256": _sha(target),
            "replacement_source": str(replacement),
            "replacement_sha256": _sha(replacement),
            "evidence_reference": "rr3:" + _sha(scan),
        }],
    }, indent=2), encoding="utf-8")
    return root, workspace, scan, operations, target


def _prepare(tmp_path: Path):
    root, workspace, scan, operations, target = _fixture(tmp_path)
    result = b42.prepare_repair_handoff(b42.GuidedRepairPrepareRequest(root, workspace, scan, operations))
    return root, workspace, scan, operations, target, result


def test_prepare_creates_handoff_without_target_mutation(tmp_path: Path):
    root, workspace, scan, operations, target = _fixture(tmp_path)
    before = _sha(target)
    result = b42.prepare_repair_handoff(b42.GuidedRepairPrepareRequest(root, workspace, scan, operations))
    assert result["profile"] == b42.PROFILE
    assert result["execution_performed"] is False
    assert result["automatic_execution"] is False
    assert _sha(target) == before


def test_prepare_requires_trusted_rr3_scan(tmp_path: Path):
    root, workspace, scan, operations, target = _fixture(tmp_path)
    payload = json.loads(scan.read_text(encoding="utf-8"))
    payload["summary"]["errors"] = 1
    scan.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="TRUSTED RR3"):
        b42.prepare_repair_handoff(b42.GuidedRepairPrepareRequest(root, workspace, scan, operations))


def test_operations_require_explicit_approval(tmp_path: Path):
    root, workspace, scan, operations, target = _fixture(tmp_path)
    payload = json.loads(operations.read_text(encoding="utf-8"))
    payload["approved"] = False
    operations.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(PermissionError, match="explicitly approved"):
        b42.prepare_repair_handoff(b42.GuidedRepairPrepareRequest(root, workspace, scan, operations))


def test_operations_target_fingerprint_must_match(tmp_path: Path):
    root, workspace, scan, operations, target = _fixture(tmp_path)
    payload = json.loads(operations.read_text(encoding="utf-8"))
    payload["target_fingerprint"] = "0" * 64
    operations.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="target fingerprint mismatch"):
        b42.prepare_repair_handoff(b42.GuidedRepairPrepareRequest(root, workspace, scan, operations))


def test_operations_must_bind_to_trusted_scan_hash(tmp_path: Path):
    root, workspace, scan, operations, target = _fixture(tmp_path)
    payload = json.loads(operations.read_text(encoding="utf-8"))
    payload["source_scan_sha256"] = "f" * 64
    operations.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="bound to trusted RR3"):
        b42.prepare_repair_handoff(b42.GuidedRepairPrepareRequest(root, workspace, scan, operations))


def test_plan_is_created_outside_target_and_loadable_by_rr4b(tmp_path: Path):
    root, workspace, scan, operations, target, result = _prepare(tmp_path)
    plan_path = Path(result["plan_path"])
    plan_path.resolve().relative_to(workspace.resolve())
    with pytest.raises(ValueError):
        plan_path.resolve().relative_to(root.resolve())
    plan = rr4b.load_plan_file(plan_path)
    assert plan.plan_sha256 == result["plan_sha256"]
    assert plan.automatic_execution is False
    assert plan.recovery_certification is False


def test_confirmation_token_is_exactly_plan_bound(tmp_path: Path):
    root, workspace, scan, operations, target, result = _prepare(tmp_path)
    plan = rr4b.load_plan_file(Path(result["plan_path"]))
    assert result["confirmation_token"] == rr4b.confirmation_token(plan)
    assert result["confirmation_token"].startswith(rr4b.CONFIRM_PREFIX)
    assert plan.plan_sha256[:16].upper() in result["confirmation_token"]


def test_handoff_delegates_execution_and_rollback_without_auto_action(tmp_path: Path):
    root, workspace, scan, operations, target, result = _prepare(tmp_path)
    assert result["rr4b_execution_delegated"] is True
    assert result["rr4b_rollback_delegated"] is True
    assert result["automatic_repair"] is False
    assert result["automatic_quarantine"] is False
    assert result["rollback_performed"] is False
    assert result["recovery_certified"] is False


def test_operations_file_inside_target_is_refused(tmp_path: Path):
    root, workspace, scan, operations, target = _fixture(tmp_path)
    inside = root / "inside-operations.json"
    inside.write_bytes(operations.read_bytes())
    with pytest.raises(ValueError, match="outside offline target"):
        b42.prepare_repair_handoff(b42.GuidedRepairPrepareRequest(root, workspace, scan, inside))


def test_audit_contains_ids_hashes_and_zero_execution(tmp_path: Path):
    root, workspace, scan, operations, target, result = _prepare(tmp_path)
    rows = [json.loads(line) for line in Path(result["audit_path"]).read_text(encoding="utf-8").splitlines()]
    assert len(rows) >= 2
    assert all(row["session_id"] == result["session_id"] for row in rows)
    assert all(row["correlation_id"] == result["correlation_id"] for row in rows)
    assert all(row["target_fingerprint"] == result["target_fingerprint"] for row in rows)
    assert all("elapsed_ms" in row for row in rows)
    completed = rows[-1]
    assert completed["plan_sha256"] == result["plan_sha256"]
    assert completed["execution_performed"] is False

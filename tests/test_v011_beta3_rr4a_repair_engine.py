from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from sentinel import rescue_repair_engine as rr4


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _offline_root(base: Path) -> Path:
    root = base / "offline"
    config = root / "Windows" / "System32" / "config"
    drivers = root / "Windows" / "System32" / "drivers"
    config.mkdir(parents=True)
    drivers.mkdir(parents=True)
    (config / "SYSTEM").write_bytes(b"RR4A SYSTEM HIVE")
    (root / "Windows" / "System32" / "ntoskrnl.exe").write_bytes(b"MZ RR4A harmless kernel fixture")
    return root


def _operation(root: Path, trusted: Path, name: str = "sample.sys", old: bytes = b"old", new: bytes = b"new"):
    target = root / "Windows" / "System32" / "drivers" / name
    target.write_bytes(old)
    replacement = trusted / (name + ".replacement")
    replacement.parent.mkdir(parents=True, exist_ok=True)
    replacement.write_bytes(new)
    return target, replacement, rr4.RepairOperation(
        relative_path=f"Windows/System32/drivers/{name}",
        expected_sha256=_sha(target),
        replacement_source=str(replacement),
        replacement_sha256=_sha(replacement),
        evidence_reference=f"RR3:deterministic:{name}",
    )


def test_plan_requires_validated_offline_root(tmp_path: Path):
    trusted = tmp_path / "trusted"
    trusted.mkdir()
    replacement = trusted / "r.bin"
    replacement.write_bytes(b"x")
    op = rr4.RepairOperation("Windows/System32/drivers/x.sys", "0" * 64, str(replacement), _sha(replacement), "evidence")
    bad = tmp_path / "bad"
    bad.mkdir()
    with pytest.raises(ValueError, match="validated offline Windows"):
        rr4.build_repair_plan(bad, [op])


def test_plan_hash_and_confirmation_are_bound(tmp_path: Path):
    root = _offline_root(tmp_path)
    trusted = tmp_path / "trusted"
    target, replacement, op = _operation(root, trusted)
    plan = rr4.build_repair_plan(root, [op])
    assert len(plan.plan_sha256) == 64
    assert rr4.confirmation_token(plan).startswith("CONFIRM-RR4A-")
    assert rr4.plan_to_dict(plan)["plan_sha256"] == plan.plan_sha256
    assert target.read_bytes() == b"old"


def test_replacement_must_be_outside_target(tmp_path: Path):
    root = _offline_root(tmp_path)
    target = root / "Windows" / "System32" / "drivers" / "x.sys"
    target.write_bytes(b"old")
    replacement = root / "Users" / "Alice" / "replacement.bin"
    replacement.parent.mkdir(parents=True)
    replacement.write_bytes(b"new")
    op = rr4.RepairOperation("Windows/System32/drivers/x.sys", _sha(target), str(replacement), _sha(replacement), "RR3:ioc")
    with pytest.raises(ValueError, match="outside offline target"):
        rr4.build_repair_plan(root, [op])


def test_boot_and_registry_targets_are_refused(tmp_path: Path):
    root = _offline_root(tmp_path)
    trusted = tmp_path / "trusted"
    trusted.mkdir()
    replacement = trusted / "clean.bin"
    replacement.write_bytes(b"clean")
    system = root / "Windows" / "System32" / "config" / "SYSTEM"
    op = rr4.RepairOperation("Windows/System32/config/SYSTEM", _sha(system), str(replacement), _sha(replacement), "RR3:review")
    with pytest.raises(ValueError, match="boot/registry/identity"):
        rr4.build_repair_plan(root, [op])


def test_wrong_confirmation_refuses_without_mutation(tmp_path: Path):
    root = _offline_root(tmp_path)
    trusted = tmp_path / "trusted"
    target, replacement, op = _operation(root, trusted)
    before = _sha(target)
    plan = rr4.build_repair_plan(root, [op])
    with pytest.raises(PermissionError, match="confirmation"):
        rr4.execute_repair_plan(plan, tmp_path / "rollback", operator_confirmation="WRONG")
    assert _sha(target) == before


def test_successful_repair_creates_verified_rollback_and_can_be_rolled_back(tmp_path: Path):
    root = _offline_root(tmp_path)
    trusted = tmp_path / "trusted"
    target, replacement, op = _operation(root, trusted)
    old_hash = _sha(target)
    new_hash = _sha(replacement)
    plan = rr4.build_repair_plan(root, [op])
    result = rr4.execute_repair_plan(plan, tmp_path / "rollback", operator_confirmation=rr4.confirmation_token(plan))
    assert result["passed"] is True
    assert result["automatic_action"] is False
    assert result["recovery_certified"] is False
    assert result["rollback_available"] is True
    assert _sha(target) == new_hash
    tx = Path(result["transaction_path"])
    payload = json.loads(tx.read_text(encoding="utf-8"))
    assert payload["state"] == "applied"
    assert payload["operations"][0]["before_sha256"] == old_hash
    assert payload["operations"][0]["after_sha256"] == new_hash
    rollback = rr4.rollback_repair_session(tx, operator_confirmation=rr4.confirmation_token(plan))
    assert rollback["passed"] is True
    assert rollback["recovery_certified"] is False
    assert _sha(target) == old_hash
    assert json.loads(tx.read_text(encoding="utf-8"))["state"] == "rolled_back"


def test_stale_precondition_aborts_without_overwriting(tmp_path: Path):
    root = _offline_root(tmp_path)
    trusted = tmp_path / "trusted"
    target, replacement, op = _operation(root, trusted)
    plan = rr4.build_repair_plan(root, [op])
    target.write_bytes(b"changed after planning")
    changed_hash = _sha(target)
    with pytest.raises(RuntimeError, match="stale_precondition"):
        rr4.execute_repair_plan(plan, tmp_path / "rollback", operator_confirmation=rr4.confirmation_token(plan))
    assert _sha(target) == changed_hash


def test_changed_replacement_provenance_aborts(tmp_path: Path):
    root = _offline_root(tmp_path)
    trusted = tmp_path / "trusted"
    target, replacement, op = _operation(root, trusted)
    before = _sha(target)
    plan = rr4.build_repair_plan(root, [op])
    replacement.write_bytes(b"replacement changed")
    with pytest.raises(RuntimeError, match="replacement_provenance_changed"):
        rr4.execute_repair_plan(plan, tmp_path / "rollback", operator_confirmation=rr4.confirmation_token(plan))
    assert _sha(target) == before


def test_partial_failure_rolls_back_already_applied_operation(tmp_path: Path):
    root = _offline_root(tmp_path)
    trusted = tmp_path / "trusted"
    target1, replacement1, op1 = _operation(root, trusted, "one.sys", b"one-old", b"one-new")
    target2, replacement2, op2 = _operation(root, trusted, "two.sys", b"two-old", b"two-new")
    before1 = _sha(target1)
    before2 = _sha(target2)
    plan = rr4.build_repair_plan(root, [op1, op2])
    replacement2.write_bytes(b"changed after planning")
    with pytest.raises(RuntimeError, match="rollback succeeded"):
        rr4.execute_repair_plan(plan, tmp_path / "rollback", operator_confirmation=rr4.confirmation_token(plan))
    assert _sha(target1) == before1
    assert _sha(target2) == before2


def test_rollback_store_inside_target_is_refused(tmp_path: Path):
    root = _offline_root(tmp_path)
    trusted = tmp_path / "trusted"
    target, replacement, op = _operation(root, trusted)
    before = _sha(target)
    plan = rr4.build_repair_plan(root, [op])
    with pytest.raises(ValueError, match="outside offline target"):
        rr4.execute_repair_plan(plan, root / "rollback", operator_confirmation=rr4.confirmation_token(plan))
    assert _sha(target) == before


def test_duplicate_target_operations_are_refused(tmp_path: Path):
    root = _offline_root(tmp_path)
    trusted = tmp_path / "trusted"
    target, replacement, op = _operation(root, trusted)
    with pytest.raises(ValueError, match="duplicate"):
        rr4.build_repair_plan(root, [op, op])


def test_path_traversal_is_refused(tmp_path: Path):
    root = _offline_root(tmp_path)
    trusted = tmp_path / "trusted"
    trusted.mkdir()
    replacement = trusted / "clean.bin"
    replacement.write_bytes(b"clean")
    op = rr4.RepairOperation("../outside.bin", "0" * 64, str(replacement), _sha(replacement), "evidence")
    with pytest.raises(ValueError):
        rr4.build_repair_plan(root, [op])


def test_audit_records_exact_stages_and_reasons(tmp_path: Path):
    root = _offline_root(tmp_path)
    trusted = tmp_path / "trusted"
    target, replacement, op = _operation(root, trusted)
    plan = rr4.build_repair_plan(root, [op])
    result = rr4.execute_repair_plan(plan, tmp_path / "rollback", operator_confirmation=rr4.confirmation_token(plan))
    records = [json.loads(line) for line in Path(result["audit_path"]).read_text(encoding="utf-8").splitlines()]
    assert records[0]["stage"] == "transaction_start"
    assert any(item["stage"] == "operation_applied" for item in records)
    assert records[-1]["stage"] == "transaction_complete"
    assert all(item["reason"] for item in records)
    assert all(item["plan_sha256"] == plan.plan_sha256 for item in records)

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel import rescue_repair_engine as core
from sentinel import rescue_repair_portable as rr4b


def _sha(path: Path) -> str:
    return core.sha256_file(path)


def _offline_root(base: Path) -> Path:
    root = base / "offline"
    config = root / "Windows" / "System32" / "config"
    config.mkdir(parents=True)
    (config / "SYSTEM").write_bytes(b"RR4B SYSTEM HIVE")
    system32 = root / "Windows" / "System32"
    (system32 / "ntoskrnl.exe").write_bytes(b"MZ RR4B harmless kernel fixture")
    target = root / "Program Files" / "Demo" / "component.dll"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"RR4B original component")
    return root


def _operations_file(base: Path, root: Path, replacement: Path, *, approved: bool = True) -> Path:
    target = root / "Program Files" / "Demo" / "component.dll"
    path = base / "operations.json"
    path.write_text(
        json.dumps(
            {
                "schema": rr4b.OPERATIONS_SCHEMA,
                "approved": approved,
                "operations": [
                    {
                        "relative_path": "Program Files/Demo/component.dll",
                        "expected_sha256": _sha(target),
                        "replacement_source": str(replacement),
                        "replacement_sha256": _sha(replacement),
                        "evidence_reference": "RR3:test-fixture",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


def _prepare(base: Path):
    root = _offline_root(base)
    replacement = base / "trusted" / "component.dll"
    replacement.parent.mkdir(parents=True)
    replacement.write_bytes(b"RR4B trusted replacement")
    operations = _operations_file(base, root, replacement)
    plan_path = base / "plans" / "repair-plan.json"
    planned = rr4b.create_plan_file(root, operations, plan_path)
    return root, replacement, plan_path, planned


def test_operations_file_requires_explicit_approval(tmp_path: Path):
    root = _offline_root(tmp_path)
    replacement = tmp_path / "replacement.dll"
    replacement.write_bytes(b"replacement")
    operations = _operations_file(tmp_path, root, replacement, approved=False)
    with pytest.raises(ValueError, match="not explicitly approved"):
        rr4b.load_operations_file(operations)


def test_plan_file_is_outside_target_and_hash_valid(tmp_path: Path):
    root, _, plan_path, planned = _prepare(tmp_path)
    assert plan_path.is_file()
    assert planned["plan_sha256"]
    assert planned["confirmation_token"].startswith(core.CONFIRM_PREFIX)
    plan = rr4b.load_plan_file(plan_path)
    assert plan.plan_sha256 == planned["plan_sha256"]
    assert not rr4b._is_inside(plan_path, root)


def test_plan_output_inside_target_is_refused(tmp_path: Path):
    root = _offline_root(tmp_path)
    replacement = tmp_path / "replacement.dll"
    replacement.write_bytes(b"replacement")
    operations = _operations_file(tmp_path, root, replacement)
    with pytest.raises(ValueError, match="outside offline target"):
        rr4b.create_plan_file(root, operations, root / "repair-plan.json")


def test_tampered_plan_is_refused(tmp_path: Path):
    _, _, plan_path, _ = _prepare(tmp_path)
    payload = json.loads(plan_path.read_text(encoding="utf-8"))
    payload["operations"][0]["evidence_reference"] = "tampered"
    plan_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="plan integrity mismatch"):
        rr4b.load_plan_file(plan_path)


def test_wrong_execute_confirmation_is_zero_mutation(tmp_path: Path):
    root, _, plan_path, _ = _prepare(tmp_path)
    target = root / "Program Files" / "Demo" / "component.dll"
    before = _sha(target)
    with pytest.raises(PermissionError):
        rr4b.execute_plan_file(plan_path, tmp_path / "rollback", "WRONG")
    assert _sha(target) == before


def test_execute_and_manual_rollback_roundtrip(tmp_path: Path):
    root, replacement, plan_path, planned = _prepare(tmp_path)
    target = root / "Program Files" / "Demo" / "component.dll"
    before = _sha(target)
    result = rr4b.execute_plan_file(plan_path, tmp_path / "rollback", planned["confirmation_token"])
    assert result["passed"] is True
    assert result["phase"] == "execute"
    assert result["automatic_action"] is False
    assert _sha(target) == _sha(replacement)
    transaction = Path(result["transaction_path"])
    rolled = rr4b.rollback_transaction_file(transaction, planned["confirmation_token"])
    assert rolled["passed"] is True
    assert rolled["phase"] == "rollback"
    assert rolled["preflight_checked"] == 1
    assert _sha(target) == before


def test_manual_rollback_refuses_changed_post_state_before_mutation(tmp_path: Path):
    root, _, plan_path, planned = _prepare(tmp_path)
    target = root / "Program Files" / "Demo" / "component.dll"
    result = rr4b.execute_plan_file(plan_path, tmp_path / "rollback", planned["confirmation_token"])
    transaction = Path(result["transaction_path"])
    target.write_bytes(b"RR4B third-party post-repair change")
    changed = _sha(target)
    with pytest.raises(RuntimeError, match="post-state changed"):
        rr4b.rollback_transaction_file(transaction, planned["confirmation_token"])
    assert _sha(target) == changed
    payload = json.loads(transaction.read_text(encoding="utf-8"))
    assert payload["state"] == "applied"


def test_manual_rollback_refuses_changed_backup_before_mutation(tmp_path: Path):
    root, _, plan_path, planned = _prepare(tmp_path)
    target = root / "Program Files" / "Demo" / "component.dll"
    result = rr4b.execute_plan_file(plan_path, tmp_path / "rollback", planned["confirmation_token"])
    transaction = Path(result["transaction_path"])
    payload = json.loads(transaction.read_text(encoding="utf-8"))
    backup = Path(payload["operations"][0]["backup_path"])
    backup.write_bytes(b"RR4B tampered backup")
    post_repair = _sha(target)
    with pytest.raises(RuntimeError, match="backup provenance mismatch"):
        rr4b.rollback_transaction_file(transaction, planned["confirmation_token"])
    assert _sha(target) == post_repair


def test_no_automatic_or_certification_flags(tmp_path: Path):
    _, _, plan_path, planned = _prepare(tmp_path)
    result = rr4b.execute_plan_file(plan_path, tmp_path / "rollback", planned["confirmation_token"])
    assert result["automatic_action"] is False
    assert result["recovery_certified"] is False

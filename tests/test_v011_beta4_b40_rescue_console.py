from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from sentinel import rescue_console as b40


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _root(tmp_path: Path) -> Path:
    root = tmp_path / "offline-target"
    cfg = root / "Windows/System32/config"
    cfg.mkdir(parents=True)
    (cfg / "SYSTEM").write_bytes(b"B40 SYSTEM")
    (cfg / "SOFTWARE").write_bytes(b"B40 SOFTWARE")
    (root / "Windows/System32/ntoskrnl.exe").write_bytes(b"MZ B40 KERNEL")
    return root


def _target_hashes(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)): _sha(path)
        for path in root.rglob("*")
        if path.is_file()
    }


def test_plan_has_exact_stage_order_and_profile(tmp_path: Path):
    root = _root(tmp_path)
    plan = b40.build_session_plan(b40.RescueConsoleRequest(root, tmp_path / "workspace"))
    assert plan["profile"] == b40.PROFILE
    assert plan["schema"] == b40.PLAN_SCHEMA
    assert tuple(item["stage"] for item in plan["stages"]) == b40.STAGE_ORDER


def test_plan_has_deterministic_identity_for_same_target(tmp_path: Path):
    root = _root(tmp_path)
    first = b40.build_session_plan(b40.RescueConsoleRequest(root, tmp_path / "workspace-a"))
    second = b40.build_session_plan(b40.RescueConsoleRequest(root, tmp_path / "workspace-b"))
    assert first["target_fingerprint"] == second["target_fingerprint"]
    assert first["session_id"] == second["session_id"]
    assert first["correlation_id"] == second["correlation_id"]
    assert first["plan_sha256"] == second["plan_sha256"]


def test_plan_is_strictly_non_automatic(tmp_path: Path):
    root = _root(tmp_path)
    plan = b40.build_session_plan(b40.RescueConsoleRequest(root, tmp_path / "workspace"))
    assert plan["safety"] == {
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
    }
    assert all(item["automatic_execution"] is False for item in plan["stages"])


def test_mutating_stages_require_operator_gate(tmp_path: Path):
    root = _root(tmp_path)
    plan = b40.build_session_plan(b40.RescueConsoleRequest(root, tmp_path / "workspace"))
    by_stage = {item["stage"]: item for item in plan["stages"]}
    for stage in ("offline_scan", "repair_review", "safe_data_rescue", "integrity_certification"):
        assert by_stage[stage]["operator_gate"] is True
        assert by_stage[stage]["mode"] == "planned_only"


def test_workspace_inside_target_is_refused(tmp_path: Path):
    root = _root(tmp_path)
    with pytest.raises(ValueError, match="outside offline target"):
        b40.build_session_plan(b40.RescueConsoleRequest(root, root / "workspace"))


def test_output_plan_inside_target_is_refused(tmp_path: Path):
    root = _root(tmp_path)
    plan = b40.build_session_plan(b40.RescueConsoleRequest(root, tmp_path / "workspace"))
    with pytest.raises(ValueError, match="outside offline target"):
        b40.write_session_plan(plan, root / "plan.json", root)


def test_target_remains_byte_identical_after_plan_and_write(tmp_path: Path):
    root = _root(tmp_path)
    before = _target_hashes(root)
    workspace = tmp_path / "workspace"
    plan = b40.build_session_plan(b40.RescueConsoleRequest(root, workspace))
    out = b40.write_session_plan(plan, workspace / "session-plan.json", root)
    after = _target_hashes(root)
    assert before == after
    assert out.is_file()


def test_written_plan_preserves_plan_hash(tmp_path: Path):
    root = _root(tmp_path)
    workspace = tmp_path / "workspace"
    plan = b40.build_session_plan(b40.RescueConsoleRequest(root, workspace))
    out = b40.write_session_plan(plan, workspace / "session-plan.json", root)
    loaded = json.loads(out.read_text(encoding="utf-8"))
    assert loaded["plan_sha256"] == plan["plan_sha256"]
    assert len(loaded["plan_sha256"]) == 64


def test_required_rescue_modules_are_visible(tmp_path: Path):
    root = _root(tmp_path)
    plan = b40.build_session_plan(b40.RescueConsoleRequest(root, tmp_path / "workspace"))
    assert all(plan["module_inventory"].values())
    assert set(plan["module_inventory"]) == {
        "rr1_portable",
        "rr2_rescue_usb",
        "rr3_offline_scanner",
        "rr4a_repair_core",
        "rr4b_repair_portable",
        "rr5_safe_data_rescue",
        "rr6_integrity_certification",
    }


def test_invalid_windows_target_is_refused(tmp_path: Path):
    root = tmp_path / "not-windows"
    root.mkdir()
    with pytest.raises((ValueError, FileNotFoundError)):
        b40.build_session_plan(b40.RescueConsoleRequest(root, tmp_path / "workspace"))

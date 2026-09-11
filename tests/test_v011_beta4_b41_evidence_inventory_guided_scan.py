from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from sentinel import rescue_console as b40
from sentinel import rescue_console_guided_scan as b41


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _offline_fixture(tmp_path: Path) -> Path:
    root = tmp_path / "offline"
    (root / "Windows/System32/config").mkdir(parents=True)
    (root / "Windows/System32/config/SYSTEM").write_bytes(b"B41 SYSTEM")
    (root / "Windows/System32/config/SOFTWARE").write_bytes(b"B41 SOFTWARE")
    (root / "Windows/System32/ntoskrnl.exe").write_bytes(b"MZ B41 KERNEL")
    return root


def _snapshot(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)).replace("\\", "/"): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in root.rglob("*")
        if path.is_file()
    }


def _run_fresh(root: Path, workspace: Path, **kwargs) -> dict:
    return b41.run_guided_scan(
        b41.GuidedScanRequest(
            target_root=root,
            workspace=workspace,
            run_scan=True,
            **kwargs,
        )
    )


def test_profile_and_schemas_are_b41():
    assert b41.PROFILE == "v0.11.0-beta.4-b41"
    assert b41.INVENTORY_SCHEMA.endswith("evidence-inventory-v1")
    assert b41.SUMMARY_SCHEMA.endswith("guided-scan-summary-v1")


def test_missing_scan_is_inventory_missing(tmp_path: Path):
    root = _offline_fixture(tmp_path)
    inv = b41.inventory_evidence(root, tmp_path / "work")
    scan = next(row for row in inv["records"] if row["kind"] == "rr3_scan")
    assert scan["trust"] == b41.TRUST_MISSING
    assert inv["trusted_rr3_scan_available"] is False
    assert inv["counts"]["missing"] >= 1


def test_b40_plan_is_trusted_when_bound_to_same_target(tmp_path: Path):
    root = _offline_fixture(tmp_path)
    work = tmp_path / "work"
    plan = b40.build_session_plan(b40.RescueConsoleRequest(root, work))
    b40.write_session_plan(plan, work / "session-plan.json", root)
    inv = b41.inventory_evidence(root, work)
    row = next(item for item in inv["records"] if item["kind"] == "b40_session_plan")
    assert row["trust"] == b41.TRUST_TRUSTED
    assert row["sha256"]


def test_fresh_rr3_scan_becomes_trusted_reusable_evidence(tmp_path: Path):
    root = _offline_fixture(tmp_path)
    work = tmp_path / "work"
    result = _run_fresh(root, work)
    assert result["scan"]["available"] is True
    assert result["scan"]["source"] == "fresh_operator_requested"
    inv = b41.inventory_evidence(root, work, work / "rr3/rr3-offline-scan.json")
    assert inv["trusted_rr3_scan_available"] is True


def test_stale_hive_makes_existing_scan_untrusted(tmp_path: Path):
    root = _offline_fixture(tmp_path)
    work = tmp_path / "work"
    _run_fresh(root, work)
    scan = work / "rr3/rr3-offline-scan.json"
    (root / "Windows/System32/config/SYSTEM").write_bytes(b"CHANGED AFTER SCAN")
    inv = b41.inventory_evidence(root, work, scan)
    row = next(item for item in inv["records"] if item["kind"] == "rr3_scan")
    assert row["trust"] == b41.TRUST_UNTRUSTED
    assert any("rr3_required_hive_stale" in reason for reason in row["reasons"])


def test_scan_with_errors_is_untrusted(tmp_path: Path):
    root = _offline_fixture(tmp_path)
    work = tmp_path / "work"
    _run_fresh(root, work)
    scan = work / "rr3/rr3-offline-scan.json"
    payload = json.loads(scan.read_text(encoding="utf-8"))
    payload["summary"]["errors"] = 1
    scan.write_text(json.dumps(payload), encoding="utf-8")
    inv = b41.inventory_evidence(root, work, scan)
    row = next(item for item in inv["records"] if item["kind"] == "rr3_scan")
    assert row["trust"] == b41.TRUST_UNTRUSTED
    assert "rr3_scan_contains_errors" in row["reasons"]


def test_untrusted_reuse_refuses_and_requests_fresh_scan(tmp_path: Path):
    root = _offline_fixture(tmp_path)
    work = tmp_path / "work"
    result = b41.run_guided_scan(
        b41.GuidedScanRequest(
            target_root=root,
            workspace=work,
            existing_scan=tmp_path / "missing.json",
            reuse_trusted_scan=True,
            run_scan=False,
        )
    )
    assert result["scan"]["available"] is False
    assert result["operator_action_required"] == "run_fresh_scan"
    assert result["repair_triggered"] is False


def test_trusted_existing_scan_can_be_reused_without_rerun(tmp_path: Path):
    root = _offline_fixture(tmp_path)
    source_work = tmp_path / "source-work"
    first = _run_fresh(root, source_work)
    scan_path = source_work / "rr3/rr3-offline-scan.json"
    original_rr3_session = json.loads(scan_path.read_text(encoding="utf-8"))["session_id"]

    reuse_work = tmp_path / "reuse-work"
    result = b41.run_guided_scan(
        b41.GuidedScanRequest(
            target_root=root,
            workspace=reuse_work,
            existing_scan=scan_path,
            reuse_trusted_scan=True,
            run_scan=False,
        )
    )
    reused_payload = json.loads(scan_path.read_text(encoding="utf-8"))
    assert result["scan"]["source"] == "reused_trusted_existing"
    assert reused_payload["session_id"] == original_rr3_session
    assert result["operator_action_required"] == "none"
    assert first["repair_triggered"] is False


def test_explicit_fresh_scan_does_not_mutate_target(tmp_path: Path):
    root = _offline_fixture(tmp_path)
    before = _snapshot(root)
    result = _run_fresh(root, tmp_path / "work")
    after = _snapshot(root)
    assert after == before
    assert result["safety"]["target_read_only"] is True
    assert result["repair_triggered"] is False
    assert result["quarantine_triggered"] is False
    assert result["automatic_execution"] is False


def test_ioc_hit_never_triggers_repair_or_quarantine(tmp_path: Path):
    root = _offline_fixture(tmp_path)
    suspicious = root / "Windows/System32/b41-fixture.exe"
    suspicious.write_bytes(b"MZ harmless B41 IOC fixture")
    catalog = tmp_path / "ioc.json"
    catalog.write_text(
        json.dumps(
            {
                "schema": "bc-sentinel-offline-intel-v1",
                "approved": True,
                "sha256": [
                    {
                        "value": _sha(suspicious.read_bytes()),
                        "name": "B41.Acceptance.IOC",
                        "source": "synthetic-test",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    result = _run_fresh(root, tmp_path / "work", intel_catalog=catalog)
    assert result["scan"]["summary"]["ioc_hits"] == 1
    assert result["repair_triggered"] is False
    assert result["quarantine_triggered"] is False


def test_audit_contains_stage_reason_timing_and_ids(tmp_path: Path):
    root = _offline_fixture(tmp_path)
    work = tmp_path / "work"
    result = _run_fresh(root, work)
    rows = [json.loads(line) for line in (work / "b41-audit.jsonl").read_text(encoding="utf-8").splitlines()]
    assert rows
    assert {row["stage"] for row in rows} >= {"evidence_inventory", "offline_scan", "guided_scan_complete"}
    for row in rows:
        assert row["reason"]
        assert row["session_id"] == result["session_id"]
        assert row["correlation_id"] == result["correlation_id"]
        assert row["target_fingerprint"] == result["target_fingerprint"]
        assert isinstance(row["elapsed_ms"], (int, float))


def test_existing_scan_inside_target_is_never_trusted(tmp_path: Path):
    root = _offline_fixture(tmp_path)
    inside = root / "evidence.json"
    inside.write_text("{}", encoding="utf-8")
    inv = b41.inventory_evidence(root, tmp_path / "work", inside)
    row = next(item for item in inv["records"] if item["kind"] == "rr3_scan")
    assert row["trust"] == b41.TRUST_UNTRUSTED
    assert any(reason.startswith("unsafe_scan_path") for reason in row["reasons"])


def test_workspace_inside_target_remains_refused(tmp_path: Path):
    root = _offline_fixture(tmp_path)
    with pytest.raises(ValueError):
        b41.inventory_evidence(root, root / "workspace")

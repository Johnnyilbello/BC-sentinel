from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from sentinel import guided_resolution_action_plan as planning
from sentinel import guided_resolution_confirmation as confirmation
from sentinel import guided_resolution_execution_gate as execution_gate
from sentinel import guided_resolution_fixture_execution as fixture_execution
from sentinel import guided_resolution_provider_loader as provider_loader
from sentinel import home_guided_resolution as guided
from sentinel import home_smart_scan as smart
from sentinel import home_threat_cards as threat


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _result(target: Path, digest: str) -> smart.SmartScanResult:
    finding = smart.SmartScanFinding(
        finding_id="b655-fixture-finding",
        title="B6-5.5 harmless fixture",
        severity=smart.SEVERITY_HIGH,
        category="fixture",
        reason="Harmless deterministic reversible execution fixture",
        source_check_id="files",
        path=str(target),
        confidence=0.90,
        evidence={"sha256": digest, "signals": ["b655_fixture"]},
    )
    scan_plan = smart.SmartScanPlan(
        provider_name="b655-fixture-source",
        provider_profile="b655-fixture-source-v1",
        provider_provenance="b655_unit_test",
        checks=(smart.SmartScanCheck("files", "Files", "Fixture", True, "b655_unit_test"),),
    )
    check = smart.SmartScanCheckResult(
        "files",
        smart.CHECK_COMPLETED,
        "Fixture complete",
        findings=(finding,),
        evidence={"fixture": True},
    )
    return smart.SmartScanResult(
        session_id="b655-session",
        correlation_id="b655-correlation",
        state=smart.STATE_COMPLETED_FINDINGS,
        started_at=1.0,
        finished_at=2.0,
        elapsed_ms=1000.0,
        coverage=smart.COVERAGE_COMPLETE,
        completed_checks=1,
        total_checks=1,
        findings=(finding,),
        highest_severity=smart.SEVERITY_HIGH,
        summary="Fixture summary",
        recommendation="Verifica il rilevamento.",
        provider_name="b655-fixture-source",
        provider_profile="b655-fixture-source-v1",
        provider_provenance="b655_unit_test",
        plan=scan_plan,
        check_results=(check,),
        raw_evidence={"fixture": True},
    )


def _source_chain(target: Path, digest: str, *, decision: str = "CONFIRM"):
    card = threat.build_threat_cards(_result(target, digest))[0]
    resolution = guided.build_guided_resolution(card)
    source_provider = provider_loader.load_default_provider()
    assert source_provider.accepted is True
    plan = planning.build_action_plan(card, resolution, source_provider, requested_action="QUARANTINE")
    request = confirmation.build_confirmation_request(
        plan,
        source_provider,
        confirmation.TargetRevalidation(
            locator=str(target),
            observed_sha256=digest,
            observed_at=1000.0,
            provenance="b655_initial_read_only_probe",
        ),
        now=1000.0,
        ttl_seconds=180,
        nonce="0123456789abcdef0123456789abcdef",
    )
    receipt = confirmation.record_explicit_decision(
        request,
        plan,
        source_provider,
        confirmation.TargetRevalidation(
            locator=str(target),
            observed_sha256=digest,
            observed_at=1001.0,
            provenance="b655_confirmation_read_only_probe",
        ),
        decision=decision,
        now=1001.0,
    )
    return plan, source_provider, receipt


def _environment(tmp_path: Path):
    root = tmp_path / "BCSentinel-B655-unit"
    fixture_execution.prepare_fixture_environment(root)
    target = root / "input" / "harmless.txt"
    data = b"BC Sentinel B6-5.5 harmless reversible fixture\n"
    target.write_bytes(data)
    digest = _digest(data)
    provider = fixture_execution.FixtureQuarantineProvider(root)
    plan, source_provider, receipt = _source_chain(target, digest)
    revalidation = confirmation.TargetRevalidation(
        locator=str(target),
        observed_sha256=digest,
        observed_at=1002.0,
        provenance="b655_post_confirmation_read_only_probe",
    )
    permit = fixture_execution.issue_fixture_execution_permit(
        plan,
        receipt,
        source_provider,
        provider,
        revalidation,
        now=1002.0,
        ttl_seconds=30,
        nonce="abcdef0123456789abcdef0123456789",
    )
    return root, target, data, digest, provider, plan, source_provider, receipt, permit


def test_b655_contract_is_harmless_fixture_only_and_keeps_home_non_executing() -> None:
    predecessor = execution_gate.validate_b654_execution_gate_contract()
    contract = fixture_execution.validate_b655_fixture_execution_contract()
    assert predecessor["passed"] is True
    assert contract["passed"] is True
    assert contract["b654_predecessor_green"] is True
    assert contract["execution_provider_loaded_by_home"] is False
    assert contract["live_home_execution_authorized"] is False
    assert contract["authority_scope"] == fixture_execution.AUTHORITY_SCOPE
    assert contract["supported_mutating_actions"] == ["QUARANTINE"]
    assert contract["quarantine_is_reversible"] is True
    assert contract["explicit_confirmation_required"] is True
    assert contract["one_shot_short_lived_permit_required"] is True
    assert contract["hash_chained_journal_required"] is True
    assert contract["verified_rollback_snapshot_required"] is True
    assert contract["automatic_action"] is False
    assert contract["destructive_authority"] is False
    assert contract["real_user_or_system_file_scope"] is False


def test_fixture_provider_requires_exact_marker(tmp_path: Path) -> None:
    root = tmp_path / "BCSentinel-B655-marker"
    fixture_execution.prepare_fixture_environment(root)
    (root / fixture_execution.FIXTURE_MARKER_NAME).write_text("wrong\n", encoding="utf-8")
    with pytest.raises(ValueError, match="b655_fixture_marker_invalid"):
        fixture_execution.FixtureQuarantineProvider(root)


def test_confirmed_plan_can_issue_only_fixture_scoped_short_lived_permit(tmp_path: Path) -> None:
    _, target, _, digest, provider, plan, _, receipt, permit = _environment(tmp_path)
    permit.validate()
    assert permit.plan_sha256 == plan.plan_sha256
    assert permit.receipt_sha256 == receipt.receipt_sha256
    assert permit.execution_provider_snapshot_sha256 == provider.snapshot_sha256()
    assert permit.target_locator == str(target.resolve())
    assert permit.target_sha256 == digest
    assert permit.execution_authorized is True
    assert permit.live_home_execution_authorized is False
    assert permit.journal_write_authority is True
    assert permit.rollback_execution_authority is True
    assert permit.automatic_action is False
    assert permit.destructive_authority is False


def test_refusal_can_never_issue_execution_permit(tmp_path: Path) -> None:
    root = tmp_path / "BCSentinel-B655-refusal"
    fixture_execution.prepare_fixture_environment(root)
    target = root / "input" / "harmless.txt"
    data = b"refusal fixture\n"
    target.write_bytes(data)
    digest = _digest(data)
    provider = fixture_execution.FixtureQuarantineProvider(root)
    plan, source_provider, receipt = _source_chain(target, digest, decision="REFUSE")
    evidence = confirmation.TargetRevalidation(
        locator=str(target),
        observed_sha256=digest,
        observed_at=1002.0,
        provenance="b655_refusal_probe",
    )
    with pytest.raises(ValueError, match="b655_explicit_confirmation_required"):
        fixture_execution.issue_fixture_execution_permit(
            plan,
            receipt,
            source_provider,
            provider,
            evidence,
            now=1002.0,
            ttl_seconds=30,
            nonce="abcdef0123456789abcdef0123456789",
        )


def test_fixture_quarantine_and_rollback_are_hash_verified_and_journaled(tmp_path: Path) -> None:
    _, target, data, digest, provider, _, _, _, permit = _environment(tmp_path)
    result = provider.execute_quarantine(permit, now=1003.0)
    result.validate()
    assert result.state == "QUARANTINED_VERIFIED"
    assert target.exists() is False
    assert Path(result.quarantine_path).is_file()
    assert Path(result.snapshot_path).is_file()
    assert hashlib.sha256(Path(result.quarantine_path).read_bytes()).hexdigest() == digest
    assert hashlib.sha256(Path(result.snapshot_path).read_bytes()).hexdigest() == digest

    rollback = provider.rollback_quarantine(permit, result, now=1004.0)
    rollback.validate()
    assert rollback.state == "RESTORED_VERIFIED"
    assert target.read_bytes() == data
    assert hashlib.sha256(target.read_bytes()).hexdigest() == digest
    assert Path(result.quarantine_path).exists() is False

    journal = fixture_execution.validate_fixture_journal(provider)
    assert journal["passed"] is True
    assert journal["events"] == [
        "PRE_STATE_RECORDED",
        "PERMIT_CONSUMED",
        "ACTION_RESULT",
        "ROLLBACK_STARTED",
        "ROLLBACK_RESULT",
        "FINAL_OUTCOME",
    ]
    assert journal["entry_count"] == 6


def test_execution_permit_is_one_shot_even_after_success(tmp_path: Path) -> None:
    _, _, _, _, provider, _, _, _, permit = _environment(tmp_path)
    provider.execute_quarantine(permit, now=1003.0)
    with pytest.raises(ValueError, match="b655_permit_replay_refused"):
        provider.execute_quarantine(permit, now=1003.5)


def test_expired_execution_permit_fails_closed_before_mutation(tmp_path: Path) -> None:
    _, target, data, _, provider, _, _, _, permit = _environment(tmp_path)
    with pytest.raises(ValueError, match="b655_permit_expired"):
        provider.execute_quarantine(permit, now=permit.expires_at + 1.0)
    assert target.read_bytes() == data


def test_hash_drift_after_permit_issue_fails_closed_before_mutation(tmp_path: Path) -> None:
    _, target, _, _, provider, _, _, _, permit = _environment(tmp_path)
    target.write_bytes(b"changed harmless fixture\n")
    with pytest.raises(ValueError, match="b655_target_sha256_drift"):
        provider.execute_quarantine(permit, now=1003.0)
    assert target.is_file()


def test_rollback_replay_is_refused(tmp_path: Path) -> None:
    _, _, _, _, provider, _, _, _, permit = _environment(tmp_path)
    result = provider.execute_quarantine(permit, now=1003.0)
    provider.rollback_quarantine(permit, result, now=1004.0)
    with pytest.raises(ValueError, match="b655_rollback_replay_refused"):
        provider.rollback_quarantine(permit, result, now=1005.0)

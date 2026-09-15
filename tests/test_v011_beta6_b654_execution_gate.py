from __future__ import annotations

from dataclasses import replace

import pytest

from sentinel import guided_resolution_action_plan as planning
from sentinel import guided_resolution_confirmation as confirmation
from sentinel import guided_resolution_execution_gate as execution_gate
from sentinel import guided_resolution_provider_loader as provider_loader
from sentinel import home_guided_resolution as guided
from sentinel import home_smart_scan as smart
from sentinel import home_threat_cards as threat


DIGEST = "a" * 64
TARGET = r"C:\Fixture\b654.test"


def _result() -> smart.SmartScanResult:
    finding = smart.SmartScanFinding(
        finding_id="b654-fixture-finding",
        title="B6-5.4 execution gate fixture",
        severity=smart.SEVERITY_HIGH,
        category="heuristic",
        reason="Harmless deterministic execution-boundary fixture",
        source_check_id="files",
        path=TARGET,
        confidence=0.81,
        evidence={"sha256": DIGEST, "signals": ["fixture"]},
    )
    scan_plan = smart.SmartScanPlan(
        provider_name="b654-fixture-provider",
        provider_profile="b654-fixture-v1",
        provider_provenance="b654_unit_test",
        checks=(smart.SmartScanCheck("files", "Files", "Fixture", True, "b654_unit_test"),),
    )
    check = smart.SmartScanCheckResult(
        "files",
        smart.CHECK_COMPLETED,
        "Fixture complete",
        findings=(finding,),
        evidence={"fixture": True},
    )
    return smart.SmartScanResult(
        session_id="b654-session",
        correlation_id="b654-correlation",
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
        recommendation="Review the finding.",
        provider_name="b654-fixture-provider",
        provider_profile="b654-fixture-v1",
        provider_provenance="b654_unit_test",
        plan=scan_plan,
        check_results=(check,),
        raw_evidence={"fixture": True},
    )


def _sources():
    card = threat.build_threat_cards(_result())[0]
    resolution = guided.build_guided_resolution(card)
    provider = provider_loader.load_default_provider()
    assert provider.accepted is True
    plan = planning.build_action_plan(
        card,
        resolution,
        provider,
        requested_action="QUARANTINE",
    )
    return plan, provider


def _revalidation(observed_at: float, *, digest: str = DIGEST, locator: str = TARGET):
    return confirmation.TargetRevalidation(
        locator=locator,
        observed_sha256=digest,
        observed_at=observed_at,
        provenance="b654_read_only_test_probe",
    )


def _receipt(*, decision: str = "CONFIRM"):
    plan, provider = _sources()
    request = confirmation.build_confirmation_request(
        plan,
        provider,
        _revalidation(1000.0),
        now=1000.0,
        ttl_seconds=180,
        nonce="0123456789abcdef0123456789abcdef",
    )
    receipt = confirmation.record_explicit_decision(
        request,
        plan,
        provider,
        _revalidation(1005.0),
        decision=decision,
        now=1005.0,
    )
    return plan, provider, receipt


def test_b654_contract_separates_confirmation_from_execution_authority() -> None:
    contract = execution_gate.validate_b654_execution_gate_contract()
    assert contract["passed"] is True
    assert contract["confirmed_receipt_is_not_execution_authority"] is True
    assert contract["fresh_target_revalidation_after_confirmation_required"] is True
    assert contract["provider_execution_boundary_required"] is True
    assert contract["journal_storage_binding_required"] is True
    assert contract["rollback_binding_required"] is True
    assert contract["execution_api"] is False
    assert contract["execution_authorized"] is False
    assert contract["execution_nonce_issued"] is False
    assert contract["journal_write_authority"] is False
    assert contract["rollback_execution_authority"] is False
    assert contract["automatic_destructive_action"] is False


def test_confirmed_receipt_still_blocks_current_passive_provider_and_unbound_recovery() -> None:
    plan, provider, receipt = _receipt()
    gate = execution_gate.assess_execution_readiness(
        plan,
        receipt,
        provider,
        _revalidation(1006.0),
        now=1006.0,
    )
    gate.validate()
    assert gate.state == execution_gate.STATE_BLOCKED_EXECUTION_PREREQUISITES
    assert "provider_execution_boundary_unavailable" in gate.blockers
    assert "provider_action_unavailable" in gate.blockers
    assert "journal_storage_not_bound" in gate.blockers
    assert "rollback_not_bound" in gate.blockers
    assert gate.execution_authorized is False
    assert gate.execution_nonce_issued is False
    assert gate.journal_write_authority is False
    assert gate.rollback_execution_authority is False
    assert gate.destructive_authority is False


def test_confirmation_without_post_confirmation_target_revalidation_is_blocked() -> None:
    plan, provider, receipt = _receipt()
    gate = execution_gate.assess_execution_readiness(
        plan,
        receipt,
        provider,
        None,
        now=1006.0,
    )
    assert gate.state == execution_gate.STATE_BLOCKED_TARGET_REVALIDATION
    assert "post_confirmation_target_revalidation_required" in gate.blockers
    assert gate.execution_authorized is False


def test_refusal_can_never_cross_execution_gate() -> None:
    plan, provider, receipt = _receipt(decision="REFUSE")
    gate = execution_gate.assess_execution_readiness(
        plan,
        receipt,
        provider,
        None,
        now=1006.0,
    )
    assert gate.state == execution_gate.STATE_BLOCKED_CONFIRMATION
    assert gate.blockers == ("explicit_confirmation_not_currently_valid",)
    assert gate.execution_authorized is False


def test_target_hash_drift_after_confirmation_fails_closed() -> None:
    plan, provider, receipt = _receipt()
    with pytest.raises(ValueError, match="b654_target_sha256_drift"):
        execution_gate.assess_execution_readiness(
            plan,
            receipt,
            provider,
            _revalidation(1006.0, digest="b" * 64),
            now=1006.0,
        )


def test_target_revalidation_must_be_after_confirmation() -> None:
    plan, provider, receipt = _receipt()
    with pytest.raises(ValueError, match="b654_target_revalidation_precedes_confirmation"):
        execution_gate.assess_execution_readiness(
            plan,
            receipt,
            provider,
            _revalidation(1004.0),
            now=1006.0,
        )


def test_provider_snapshot_drift_after_confirmation_fails_closed() -> None:
    plan, provider, receipt = _receipt()
    drifted = replace(provider, reason="accepted_passive_capability_provider_changed")
    with pytest.raises(ValueError, match="b654_provider_snapshot_drift_from_plan"):
        execution_gate.assess_execution_readiness(
            plan,
            receipt,
            drifted,
            _revalidation(1006.0),
            now=1006.0,
        )


def test_tampered_gate_integrity_is_rejected() -> None:
    plan, provider, receipt = _receipt()
    gate = execution_gate.assess_execution_readiness(
        plan,
        receipt,
        provider,
        _revalidation(1006.0),
        now=1006.0,
    )
    tampered = replace(gate, finding_id="tampered")
    with pytest.raises(ValueError, match="b654_gate_integrity_mismatch"):
        tampered.validate()

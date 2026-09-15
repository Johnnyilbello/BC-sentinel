from __future__ import annotations

from dataclasses import replace

import pytest

from sentinel import guided_resolution_action_plan as planning
from sentinel import guided_resolution_confirmation as confirmation
from sentinel import guided_resolution_provider_loader as provider_loader
from sentinel import home_guided_resolution as guided
from sentinel import home_smart_scan as smart
from sentinel import home_threat_cards as threat


DIGEST = "a" * 64
TARGET = r"C:\Fixture\b653.test"


def _result() -> smart.SmartScanResult:
    finding = smart.SmartScanFinding(
        finding_id="b653-fixture-finding",
        title="B6-5.3 confirmation fixture",
        severity=smart.SEVERITY_HIGH,
        category="heuristic",
        reason="Harmless deterministic confirmation fixture",
        source_check_id="files",
        path=TARGET,
        confidence=0.72,
        evidence={"sha256": DIGEST, "signals": ["fixture"]},
    )
    scan_plan = smart.SmartScanPlan(
        provider_name="b653-fixture-provider",
        provider_profile="b653-fixture-v1",
        provider_provenance="b653_unit_test",
        checks=(smart.SmartScanCheck("files", "Files", "Fixture", True, "b653_unit_test"),),
    )
    check = smart.SmartScanCheckResult(
        "files",
        smart.CHECK_COMPLETED,
        "Fixture complete",
        findings=(finding,),
        evidence={"fixture": True},
    )
    return smart.SmartScanResult(
        session_id="b653-session",
        correlation_id="b653-correlation",
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
        provider_name="b653-fixture-provider",
        provider_profile="b653-fixture-v1",
        provider_provenance="b653_unit_test",
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
    assert plan.plan_status == planning.PLAN_STATUS_PLANNED_NOT_AUTHORIZED
    return plan, provider


def _revalidation(observed_at: float, *, digest: str = DIGEST, locator: str = TARGET):
    return confirmation.TargetRevalidation(
        locator=locator,
        observed_sha256=digest,
        observed_at=observed_at,
        provenance="b653_read_only_test_probe",
    )


def _request(*, issued_at: float = 1000.0, ttl: int = 180):
    plan, provider = _sources()
    request = confirmation.build_confirmation_request(
        plan,
        provider,
        _revalidation(issued_at),
        now=issued_at,
        ttl_seconds=ttl,
        nonce="0123456789abcdef0123456789abcdef",
    )
    return plan, provider, request


def test_b653_static_contract_is_explicit_confirmation_only() -> None:
    contract = confirmation.validate_b653_confirmation_contract()
    assert contract["passed"] is True
    assert contract["confirmation_requires_explicit_intent"] is True
    assert contract["implicit_confirmation"] is False
    assert contract["target_revalidation_required_at_request"] is True
    assert contract["target_revalidation_required_at_confirmation"] is True
    assert contract["provider_snapshot_revalidation_required"] is True
    assert contract["confirmation_is_execution_authority"] is False
    assert contract["execution_api"] is False
    assert contract["execution_authorized"] is False
    assert contract["execution_nonce_issued"] is False
    assert contract["journal_write_authority"] is False
    assert contract["rollback_execution_authority"] is False
    assert contract["automatic_quarantine"] is False
    assert contract["automatic_repair"] is False
    assert contract["automatic_destructive_action"] is False
    assert contract["execution_owned_by"] == "B6-5.4+"


def test_confirmation_request_binds_plan_provider_and_fresh_target_without_authority() -> None:
    plan, provider, request = _request()
    request.validate()
    assert request.status == confirmation.STATE_AWAITING_EXPLICIT_CONFIRMATION
    assert request.plan_sha256 == plan.plan_sha256
    assert request.provider_snapshot_sha256 == plan.provider_snapshot_sha256
    assert request.target_sha256 == DIGEST
    assert request.target_fingerprint == plan.target.fingerprint
    assert request.explicit_decision_required is True
    assert request.execution_authorized is False
    assert request.execution_nonce_issued is False
    assert request.journal_write_authority is False
    assert request.rollback_execution_authority is False
    assert request.automatic_action is False
    assert request.destructive_authority is False


def test_explicit_confirm_records_receipt_but_still_cannot_execute() -> None:
    plan, provider, request = _request(issued_at=1000.0)
    receipt = confirmation.record_explicit_decision(
        request,
        plan,
        provider,
        _revalidation(1005.0),
        decision="CONFIRM",
        now=1005.0,
    )
    assert receipt.state == confirmation.STATE_CONFIRMED_NOT_EXECUTABLE
    assert receipt.decision == confirmation.DECISION_CONFIRM
    assert receipt.explicit_human_decision is True
    assert receipt.confirmed is True
    assert receipt.execution_authorized is False
    assert receipt.execution_nonce_issued is False
    assert receipt.journal_write_authority is False
    assert receipt.rollback_execution_authority is False
    assert receipt.automatic_action is False
    assert receipt.destructive_authority is False


def test_explicit_refusal_is_integrity_bound_and_never_authorizes() -> None:
    plan, provider, request = _request(issued_at=1000.0)
    receipt = confirmation.record_explicit_decision(
        request,
        plan,
        provider,
        _revalidation(1002.0),
        decision="REFUSE",
        now=1002.0,
    )
    assert receipt.state == confirmation.STATE_REFUSED
    assert receipt.confirmed is False
    assert receipt.execution_authorized is False


def test_expired_confirmation_cannot_become_confirmed() -> None:
    plan, provider, request = _request(issued_at=1000.0, ttl=10)
    receipt = confirmation.record_explicit_decision(
        request,
        plan,
        provider,
        _revalidation(1020.0),
        decision="CONFIRM",
        now=1020.0,
    )
    assert receipt.state == confirmation.STATE_EXPIRED
    assert receipt.confirmed is False
    assert receipt.execution_authorized is False


@pytest.mark.parametrize("decision", ["", "YES", "TRUE", "1", "OK"])
def test_implicit_or_ambiguous_confirmation_words_are_rejected(decision: str) -> None:
    plan, provider, request = _request()
    with pytest.raises(ValueError, match="b653_explicit_confirm_or_refuse_required"):
        confirmation.record_explicit_decision(
            request,
            plan,
            provider,
            _revalidation(1001.0),
            decision=decision,
            now=1001.0,
        )


def test_target_hash_drift_fails_closed_before_confirmation() -> None:
    plan, provider, request = _request()
    with pytest.raises(ValueError, match="b653_target_sha256_drift"):
        confirmation.record_explicit_decision(
            request,
            plan,
            provider,
            _revalidation(1001.0, digest="b" * 64),
            decision="CONFIRM",
            now=1001.0,
        )


def test_target_locator_drift_fails_closed_before_confirmation() -> None:
    plan, provider, request = _request()
    with pytest.raises(ValueError, match="b653_target_locator_drift"):
        confirmation.record_explicit_decision(
            request,
            plan,
            provider,
            _revalidation(1001.0, locator=r"C:\Fixture\different.test"),
            decision="CONFIRM",
            now=1001.0,
        )


def test_confirmation_requires_revalidation_at_or_after_request_issue() -> None:
    plan, provider, request = _request(issued_at=1000.0)
    with pytest.raises(ValueError, match="b653_confirmation_revalidation_precedes_request"):
        confirmation.record_explicit_decision(
            request,
            plan,
            provider,
            _revalidation(999.0),
            decision="CONFIRM",
            now=1001.0,
        )


def test_stale_revalidation_is_rejected() -> None:
    plan, provider = _sources()
    with pytest.raises(ValueError, match="b653_revalidation_too_old"):
        confirmation.build_confirmation_request(
            plan,
            provider,
            _revalidation(900.0),
            now=1000.0,
            nonce="0123456789abcdef0123456789abcdef",
        )


def test_provider_snapshot_drift_fails_closed() -> None:
    plan, provider, request = _request()
    drifted_provider = replace(provider, reason="accepted_passive_capability_provider_changed")
    with pytest.raises(ValueError, match="b653_provider_snapshot_drift"):
        confirmation.record_explicit_decision(
            request,
            plan,
            drifted_provider,
            _revalidation(1001.0),
            decision="CONFIRM",
            now=1001.0,
        )


def test_tampered_request_integrity_is_rejected() -> None:
    _, _, request = _request()
    tampered = replace(request, finding_id="tampered")
    with pytest.raises(ValueError, match="b653_request_integrity_mismatch"):
        tampered.validate()

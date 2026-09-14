from __future__ import annotations

from dataclasses import replace

import pytest

from sentinel import guided_resolution_action_plan as planning
from sentinel import guided_resolution_provider_loader as provider_loader
from sentinel import home_guided_resolution as guided
from sentinel import home_smart_scan as smart
from sentinel import home_threat_cards as threat


def _result(*, evidence: dict, confidence: float | None = None) -> smart.SmartScanResult:
    finding = smart.SmartScanFinding(
        finding_id="b652-fixture-finding",
        title="B6-5.2 planning fixture",
        severity=smart.SEVERITY_HIGH,
        category="heuristic",
        reason="Harmless deterministic planning fixture",
        source_check_id="files",
        path=r"C:\Fixture\b652.test",
        confidence=confidence,
        evidence=evidence,
    )
    plan = smart.SmartScanPlan(
        provider_name="b652-fixture-provider",
        provider_profile="b652-fixture-v1",
        provider_provenance="b652_unit_test",
        checks=(smart.SmartScanCheck("files", "Files", "Fixture", True, "b652_unit_test"),),
    )
    check = smart.SmartScanCheckResult(
        "files",
        smart.CHECK_COMPLETED,
        "Fixture complete",
        findings=(finding,),
        evidence={"fixture": True},
    )
    return smart.SmartScanResult(
        session_id="b652-session",
        correlation_id="b652-correlation",
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
        provider_name="b652-fixture-provider",
        provider_profile="b652-fixture-v1",
        provider_provenance="b652_unit_test",
        plan=plan,
        check_results=(check,),
        raw_evidence={"fixture": True},
    )


def _sources(*, evidence: dict, confidence: float | None = None):
    result = _result(evidence=evidence, confidence=confidence)
    card = threat.build_threat_cards(result)[0]
    resolution = guided.build_guided_resolution(card)
    provider = provider_loader.load_default_provider()
    assert provider.accepted is True
    return card, resolution, provider


def test_b652_static_contract_is_planning_only() -> None:
    contract = planning.validate_b652_planning_contract()
    assert contract["passed"] is True
    assert contract["authority"] == "PLANNING_ONLY"
    assert contract["execution_api"] is False
    assert contract["execution_authorized"] is False
    assert contract["confirmation_issued"] is False
    assert contract["journal_write_authority"] is False
    assert contract["rollback_execution_authority"] is False
    assert contract["automatic_quarantine"] is False
    assert contract["automatic_repair"] is False
    assert contract["automatic_destructive_action"] is False


def test_sha256_bound_quarantine_plan_is_integrity_bound_but_not_authorized() -> None:
    digest = "a" * 64
    card, resolution, provider = _sources(
        evidence={"sha256": digest, "signals": ["fixture"]},
        confidence=None,
    )
    plan = planning.build_action_plan(
        card,
        resolution,
        provider,
        requested_action="QUARANTINE",
    )

    assert plan.plan_status == planning.PLAN_STATUS_PLANNED_NOT_AUTHORIZED
    assert plan.requested_action == "QUARANTINE"
    assert plan.canonical_severity == smart.SEVERITY_HIGH
    assert plan.canonical_confidence is None
    assert plan.target.kind == planning.TARGET_KIND_FILE
    assert plan.target.identity_state == planning.TARGET_IDENTITY_VERIFIED
    assert plan.target.sha256 == digest
    assert plan.provider_action_available is False
    assert plan.authority_state == "PLANNING_ONLY"
    assert plan.execution_authorized is False
    assert plan.confirmation_issued is False
    assert plan.automatic_action is False
    assert plan.destructive_authority is False
    assert plan.plan_id == planning.PLAN_PREFIX + plan.plan_sha256[:16].upper()
    assert len(plan.plan_sha256) == 64
    assert plan.raw_binding["remediation_provider_boundary_verified"] is False
    assert plan.raw_binding["confirmation_owned_by"] == "B6-5.3"
    assert plan.raw_binding["execution_owned_by"] == "B6-5.4+"


def test_plan_hash_binds_source_card_resolution_and_provider_snapshot() -> None:
    card, resolution, provider = _sources(evidence={"file_sha256": "b" * 64}, confidence=0.71)
    first = planning.build_action_plan(card, resolution, provider, requested_action="QUARANTINE")
    second = planning.build_action_plan(card, resolution, provider, requested_action="QUARANTINE")
    assert first.plan_sha256 == second.plan_sha256
    assert first.source_card_sha256 == second.source_card_sha256
    assert first.source_resolution_sha256 == second.source_resolution_sha256
    assert first.provider_snapshot_sha256 == second.provider_snapshot_sha256

    tampered = replace(first, finding_id="tampered")
    with pytest.raises(ValueError, match="b652_plan_integrity_mismatch"):
        tampered.validate()


def test_missing_sha256_blocks_target_identity_without_choosing_a_hash() -> None:
    card, resolution, provider = _sources(evidence={"signals": ["fixture"]})
    plan = planning.build_action_plan(card, resolution, provider, requested_action="QUARANTINE")
    assert plan.plan_status == planning.PLAN_STATUS_BLOCKED_TARGET_IDENTITY
    assert plan.target.identity_state == planning.TARGET_IDENTITY_UNVERIFIED
    assert plan.target.sha256 is None
    assert plan.target.fingerprint == ""
    assert plan.execution_authorized is False


def test_multiple_explicit_sha256_values_fail_closed_as_ambiguous() -> None:
    card, resolution, provider = _sources(
        evidence={"sha256": "c" * 64, "nested": {"file_sha256": "d" * 64}}
    )
    plan = planning.build_action_plan(card, resolution, provider, requested_action="QUARANTINE")
    assert plan.plan_status == planning.PLAN_STATUS_BLOCKED_TARGET_IDENTITY
    assert plan.target.identity_state == planning.TARGET_IDENTITY_AMBIGUOUS
    assert plan.target.sha256 is None
    assert plan.execution_authorized is False


def test_non_mutating_or_unknown_action_is_not_turned_into_action_plan() -> None:
    card, resolution, provider = _sources(evidence={"sha256": "e" * 64})
    with pytest.raises(ValueError, match="b652_unknown_or_non_mutating_action"):
        planning.build_action_plan(
            card,
            resolution,
            provider,
            requested_action=guided.ACTION_REVIEW_DETAILS,
        )
    with pytest.raises(ValueError, match="b652_unknown_or_non_mutating_action"):
        planning.build_action_plan(card, resolution, provider, requested_action="FORMAT")


def test_unaccepted_provider_boundary_refuses_plan_construction() -> None:
    card, resolution, _ = _sources(evidence={"sha256": "f" * 64})

    def _missing(name: str) -> object:
        exc = ModuleNotFoundError(name)
        exc.name = name
        raise exc

    unavailable = provider_loader.load_default_provider(import_module=_missing)
    assert unavailable.accepted is False
    with pytest.raises(ValueError, match="b652_capability_provider_boundary_not_accepted"):
        planning.build_action_plan(card, resolution, unavailable, requested_action="QUARANTINE")


def test_journal_and_rollback_are_blueprints_only_and_require_full_safety_record() -> None:
    card, resolution, provider = _sources(evidence={"sha256": "1" * 64})
    plan = planning.build_action_plan(card, resolution, provider, requested_action="REPAIR")
    assert plan.journal.status == "BLUEPRINT_ONLY"
    assert plan.journal.storage_binding == "NOT_BOUND"
    assert plan.journal.required_stages == planning.JOURNAL_STAGES
    assert plan.rollback.status == "REQUIRED_NOT_BOUND"
    assert plan.rollback.rollback_binding == "NOT_BOUND"
    assert plan.rollback.snapshot_required is True
    assert plan.rollback.restore_verification_required is True
    assert plan.rollback.rollback_on_failure_required is True
    assert plan.execution_authorized is False

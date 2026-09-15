from __future__ import annotations

from copy import deepcopy

from sentinel import coverage_campaign


def test_self_check_is_green_and_conservative() -> None:
    result = coverage_campaign.self_check()
    assert result["passed"] is True
    assert result["summary"] == {"PARTIAL": 3, "GAP": 3, "VERIFIED": 0}
    assert result["scenario_count"] == 6
    assert result["unsupported_verified_claims_allowed"] is False
    assert result["base_ledger_mutated"] is False
    assert result["authority_granted"] is False


def test_campaign_contains_exact_six_expected_families() -> None:
    report = coverage_campaign.run_campaign()
    assert tuple(item.scenario_id for item in report.scenarios) == coverage_campaign.EXPECTED_SCENARIOS
    assert len({item.family for item in report.scenarios}) == 6


def test_partial_scenarios_are_b74_evidence_bound_but_not_detector_verified() -> None:
    report = coverage_campaign.run_campaign()
    partial = [item for item in report.scenarios if item.coverage_status == "PARTIAL"]
    assert {item.scenario_id for item in partial} == coverage_campaign.PARTIAL_SCENARIOS
    for item in partial:
        assert item.synthetic_observed is True
        assert item.correlated is True
        assert item.detector_verified is False
        assert any(ref == f"b74-report:{report.b74_report_digest}" for ref in item.evidence_refs)
        assert item.gap_reason
        assert item.next_engineering_step


def test_missing_families_become_explicit_engineering_gaps() -> None:
    report = coverage_campaign.run_campaign()
    gaps = [item for item in report.scenarios if item.coverage_status == "GAP"]
    assert {item.scenario_id for item in gaps} == coverage_campaign.GAP_SCENARIOS
    for item in gaps:
        assert item.synthetic_observed is False
        assert item.correlated is False
        assert item.detector_verified is False
        assert item.gap_reason
        assert item.next_engineering_step


def test_no_synthetic_fixture_can_be_promoted_to_verified() -> None:
    payload = coverage_campaign.run_campaign().to_dict()
    broken = deepcopy(payload)
    broken["scenarios"][0]["coverage_status"] = "VERIFIED"
    broken["scenarios"][0]["detector_verified"] = True
    validation = coverage_campaign.validate_report(broken)
    assert validation.passed is False
    assert any("unsupported_verified_claim" in failure for failure in validation.failures)


def test_validation_rejects_missing_gap_reason_or_next_step() -> None:
    payload = coverage_campaign.run_campaign().to_dict()
    broken = deepcopy(payload)
    broken["scenarios"][0]["gap_reason"] = ""
    broken["scenarios"][0]["next_engineering_step"] = ""
    validation = coverage_campaign.validate_report(broken)
    assert validation.passed is False
    assert any("gap_or_next_step_missing" in failure for failure in validation.failures)


def test_validation_rejects_side_effect_or_authority_expansion() -> None:
    payload = coverage_campaign.run_campaign().to_dict()
    broken = deepcopy(payload)
    broken["network_io"] = True
    broken["credential_access"] = True
    broken["authority_granted"] = True
    validation = coverage_campaign.validate_report(broken)
    assert validation.passed is False
    assert "campaign:network_io_must_be_false" in validation.failures
    assert "campaign:credential_access_must_be_false" in validation.failures
    assert "campaign:authority_must_remain_false" in validation.failures


def test_report_is_deterministic_and_round_trip_stable() -> None:
    first = coverage_campaign.run_campaign()
    second = coverage_campaign.run_campaign()
    restored = coverage_campaign.CampaignReport.from_dict(first.to_dict())
    assert first.stable_json() == second.stable_json()
    assert first.digest() == second.digest()
    assert restored.stable_json() == first.stable_json()


def test_campaign_contract_is_non_executing() -> None:
    assert coverage_campaign.CAMPAIGN_EXECUTES_PROCESSES is False
    assert coverage_campaign.CAMPAIGN_WRITES_FILES is False
    assert coverage_campaign.CAMPAIGN_NETWORK_IO is False
    assert coverage_campaign.CAMPAIGN_MUTATES_REGISTRY is False
    assert coverage_campaign.CAMPAIGN_ACCESSES_CREDENTIALS is False
    assert coverage_campaign.CAMPAIGN_EXECUTES_REMEDIATION is False

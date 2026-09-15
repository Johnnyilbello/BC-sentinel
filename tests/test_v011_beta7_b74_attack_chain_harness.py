from __future__ import annotations

from copy import deepcopy

from sentinel import attack_chain_harness as harness
from sentinel import confidence_gate


def test_self_check_is_green_deterministic_and_side_effect_free() -> None:
    result = harness.self_check()
    assert result["passed"] is True
    assert result["stage_order"] == list(harness.EXPECTED_STAGE_ORDER)
    assert result["stage_count"] == 5
    assert result["graph_edge_count"] == 4
    assert result["detection_latency"] == 4.0
    assert result["stable_round_trip"] is True
    assert result["deterministic_serialization"] is True
    assert result["synthetic_fixture_only"] is True
    assert result["process_execution"] is False
    assert result["file_write"] is False
    assert result["network_io"] is False
    assert result["registry_mutation"] is False
    assert result["remediation_execution"] is False
    assert result["authority_granted"] is False


def test_controlled_graph_has_exact_order_and_one_correlated_chain() -> None:
    report = harness.run_controlled_harness()
    assert report.stage_order == harness.EXPECTED_STAGE_ORDER
    assert len(report.stage_node_ids) == 5
    assert len(set(report.stage_node_ids)) == 5
    assert len(report.graph_edge_ids) == 4
    assert report.correlation_link_count >= 4
    assert harness.validate_report(report).passed is True


def test_detection_latency_is_derived_from_fixture_timestamps() -> None:
    report = harness.run_controlled_harness()
    assert report.first_observed_at == 10.0
    assert report.detection_observed_at == 14.0
    assert report.detection_latency == report.detection_observed_at - report.first_observed_at
    assert report.detection_latency == 4.0


def test_gate_cases_cover_recommend_review_and_blocked_without_authority() -> None:
    report = harness.run_controlled_harness()
    cases = {case.case_id: case for case in report.gate_cases}
    assert cases["b74-case-recommend"].actual_outcome == confidence_gate.OUTCOME_RECOMMEND
    assert cases["b74-case-review"].actual_outcome == confidence_gate.OUTCOME_REVIEW
    assert cases["b74-case-blocked"].actual_outcome == confidence_gate.OUTCOME_BLOCKED
    assert cases["b74-case-recommend"].advisory_interruption_eligible is True
    assert cases["b74-case-review"].advisory_interruption_eligible is False
    assert cases["b74-case-blocked"].advisory_interruption_eligible is False
    assert all(case.authority_granted is False for case in cases.values())
    assert all(case.passed is True for case in cases.values())


def test_recommendation_evidence_is_incident_bound() -> None:
    report = harness.run_controlled_harness()
    recommend = next(case for case in report.gate_cases if case.case_id == "b74-case-recommend")
    assert set(recommend.matched_evidence_ids) == {
        "ev-b74-script",
        "ev-b74-persistence",
        "ev-b74-dns",
        "ev-b74-detection",
    }


def test_report_is_deterministic_and_round_trip_stable() -> None:
    first = harness.run_controlled_harness()
    second = harness.run_controlled_harness()
    restored = harness.AttackChainReport.from_dict(first.to_dict())
    assert first.stable_json() == second.stable_json()
    assert first.digest() == second.digest()
    assert restored.stable_json() == first.stable_json()


def test_validation_rejects_stage_order_tamper() -> None:
    payload = harness.run_controlled_harness().to_dict()
    broken = deepcopy(payload)
    broken["stage_order"] = ["PROCESS", "DNS", "SCRIPT", "PERSISTENCE", "DETECTION"]
    validation = harness.validate_report(broken)
    assert validation.passed is False
    assert "attack_chain:stage_order_mismatch" in validation.failures


def test_validation_rejects_authority_or_side_effect_expansion() -> None:
    payload = harness.run_controlled_harness().to_dict()
    broken = deepcopy(payload)
    broken["authority_granted"] = True
    broken["process_execution"] = True
    broken["network_io"] = True
    validation = harness.validate_report(broken)
    assert validation.passed is False
    assert "attack_chain:authority_granted_must_be_false" in validation.failures
    assert "attack_chain:process_execution_must_be_false" in validation.failures
    assert "attack_chain:network_io_must_be_false" in validation.failures


def test_validation_rejects_false_interruption_eligibility() -> None:
    payload = harness.run_controlled_harness().to_dict()
    broken = deepcopy(payload)
    for case in broken["gate_cases"]:
        if case["case_id"] == "b74-case-review":
            case["advisory_interruption_eligible"] = True
    validation = harness.validate_report(broken)
    assert validation.passed is False
    assert any("eligibility_mismatch" in failure for failure in validation.failures)


def test_fixture_contract_is_explicitly_non_executing() -> None:
    assert harness.HARNESS_EXECUTES_PROCESSES is False
    assert harness.HARNESS_WRITES_FILES is False
    assert harness.HARNESS_NETWORK_IO is False
    assert harness.HARNESS_MUTATES_REGISTRY is False
    assert harness.HARNESS_EXECUTES_REMEDIATION is False

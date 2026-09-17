from __future__ import annotations

from copy import deepcopy

from sentinel import beta10_final_acceptance as final
from sentinel import beta10_reversible_response_pilot as reversible
from sentinel import beta10_trust_center as trust


def _trust_report() -> dict:
    return {
        "passed": True,
        "failures": [],
        "profile": trust.PROFILE,
        "coverage_summary": {"PARTIAL": 4, "GAP": 0, "VERIFIED": 2},
        "verified_scenarios": ["B7-POWERSHELL-001", "B7-RANSOMWARE-001"],
        "scenario_count": 6,
        "capability_count": 6,
        "impact_status": "MEASURED",
        "impact_metrics": {
            "repeat_count": 7,
            "p95_wall_ms": 0.5,
            "p95_cpu_ms": 15.625,
            "max_rss_delta_mib": 0.003906,
            "max_user_interruptions": 0,
        },
        "presentation_can_promote_coverage": False,
        "general_response_execution_available": False,
        "reversible_response_scope": "DISPOSABLE_TEMP_WORKSPACE_ONLY",
        "new_authority_expanded": False,
        "broad_protection_claimed": False,
        "ui_smoke": {
            "passed": True,
            "page_count": 7,
            "trust_center_selected": True,
            "horizontal_overflow": {"560": 0, "680": 0, "960": 0, "1440": 0},
        },
    }


def _pilot_result() -> dict:
    return {
        "passed": True,
        "profile": reversible.PROFILE,
        "quarantine_state": "QUARANTINED",
        "final_state": "ROLLED_BACK",
        "journal_record_count": 4,
        "automatic_action": False,
        "broad_home_execution": False,
        "delete_authority": False,
        "repair_authority": False,
        "terminate_process_authority": False,
        "privileged_system_mutation": False,
        "pilot_quarantine_authority": True,
        "pilot_rollback_authority": True,
        "authority_expanded": True,
        "broad_remediation_claimed": False,
        "coverage_summary": {"PARTIAL": 4, "GAP": 0, "VERIFIED": 2},
    }


def test_b109_contract_preserves_exact_b108_checkpoint_and_coverage() -> None:
    c = final.validate_b109_contract()
    assert c["passed"] is True
    assert c["source_predecessor_checkpoint"] == "checkpoint/v011-beta10-b108-pass"
    assert c["source_predecessor_commit"] == "aa0c2b4e4b79381f9a20a5d69e99e972dee46971"
    assert c["coverage_summary"] == {"PARTIAL": 4, "GAP": 0, "VERIFIED": 2}
    assert c["verified_scenarios"] == ["B7-POWERSHELL-001", "B7-RANSOMWARE-001"]


def test_b109_final_report_demonstrates_all_value_pillars_without_market_claim() -> None:
    report = final.build_final_report(_trust_report(), _pilot_result())
    assert report["passed"] is True
    assert report["freeze_eligible"] is True
    assert report["competitive_contract_passed"] is True
    assert report["competitive_contract_scope"] == "BETA10_INTERNAL_VALUE_AND_SAFETY_CONTRACT"
    assert report["external_market_superiority_claimed"] is False
    assert report["pillar_count"] == 6
    assert report["milestone_count"] == 10
    assert report["all_value_pillars_demonstrated"] is True
    assert [row["pillar_id"] for row in report["pillar_evidence"]] == list(final.PILLAR_IDS)
    assert all(row["demonstrated"] is True for row in report["pillar_evidence"])


def test_b109_freeze_report_keeps_general_response_disabled_and_pilot_narrow() -> None:
    report = final.build_final_report(_trust_report(), _pilot_result())
    assert report["general_response_execution_available"] is False
    assert report["reversible_response_scope"] == "DISPOSABLE_TEMP_WORKSPACE_ONLY"
    assert report["reversible_response_final_state"] == "ROLLED_BACK"
    assert report["reversible_response_journal_records"] == 4
    assert report["rescue_continuity_non_executing"] is True
    assert report["new_authority_expanded_in_b109"] is False
    assert report["broad_protection_claimed"] is False
    assert report["presentation_can_promote_coverage"] is False


def test_b109_operational_and_ui_baseline_is_preserved() -> None:
    report = final.build_final_report(_trust_report(), _pilot_result())
    assert report["operational_metrics"]["repeat_count"] == 7
    assert report["max_user_interruptions"] == 0
    assert report["trust_center_page_count"] == 7
    assert report["trust_center_no_horizontal_overflow"] is True


def test_b109_fails_closed_if_trust_report_changes_coverage() -> None:
    trust_report = _trust_report()
    trust_report["coverage_summary"] = {"PARTIAL": 3, "GAP": 0, "VERIFIED": 3}
    report = final.build_final_report(trust_report, _pilot_result())
    assert report["passed"] is False
    assert report["freeze_eligible"] is False
    assert "b109:trust_coverage_invalid" in report["failures"]


def test_b109_fails_closed_if_verified_identity_changes() -> None:
    trust_report = _trust_report()
    trust_report["verified_scenarios"] = ["B7-RANSOMWARE-001"]
    report = final.build_final_report(trust_report, _pilot_result())
    assert report["passed"] is False
    assert "b109:trust_verified_set_invalid" in report["failures"]


def test_b109_fails_closed_if_presentation_claims_promotion() -> None:
    trust_report = _trust_report()
    trust_report["presentation_can_promote_coverage"] = True
    report = final.build_final_report(trust_report, _pilot_result())
    assert report["passed"] is False
    assert "b109:presentation_can_promote_coverage" in report["failures"]


def test_b109_fails_closed_if_general_response_is_enabled() -> None:
    trust_report = _trust_report()
    trust_report["general_response_execution_available"] = True
    report = final.build_final_report(trust_report, _pilot_result())
    assert report["passed"] is False
    assert "b109:general_response_execution_enabled" in report["failures"]


def test_b109_fails_closed_if_pilot_does_not_rollback() -> None:
    pilot = _pilot_result()
    pilot["final_state"] = "QUARANTINED"
    report = final.build_final_report(_trust_report(), pilot)
    assert report["passed"] is False
    assert "b109:pilot_not_rolled_back" in report["failures"]


def test_b109_fails_closed_if_pilot_scope_or_authority_changes() -> None:
    trust_report = _trust_report()
    trust_report["reversible_response_scope"] = "GENERAL_HOME"
    report = final.build_final_report(trust_report, _pilot_result())
    assert report["passed"] is False
    assert "b109:reversible_response_scope_changed" in report["failures"]


def test_b109_fails_closed_on_performance_budget_regression() -> None:
    trust_report = _trust_report()
    trust_report["impact_metrics"]["p95_wall_ms"] = 999999.0
    report = final.build_final_report(trust_report, _pilot_result())
    assert report["passed"] is False
    assert "b109:impact_wall_budget_failed" in report["failures"]


def test_b109_fails_closed_on_user_interruption_regression() -> None:
    trust_report = _trust_report()
    trust_report["impact_metrics"]["max_user_interruptions"] = 1
    report = final.build_final_report(trust_report, _pilot_result())
    assert report["passed"] is False
    assert "b109:impact_interruption_budget_failed" in report["failures"]


def test_b109_fails_closed_on_ui_overflow() -> None:
    trust_report = _trust_report()
    trust_report["ui_smoke"]["horizontal_overflow"]["560"] = 1
    report = final.build_final_report(trust_report, _pilot_result())
    assert report["passed"] is False
    assert "b109:trust_ui_horizontal_overflow" in report["failures"]


def test_b109_fails_closed_on_missing_ui_width() -> None:
    trust_report = _trust_report()
    del trust_report["ui_smoke"]["horizontal_overflow"]["680"]
    report = final.build_final_report(trust_report, _pilot_result())
    assert report["passed"] is False
    assert "b109:trust_ui_width_inventory_invalid" in report["failures"]


def test_b109_input_objects_are_not_mutated() -> None:
    trust_report = _trust_report()
    pilot = _pilot_result()
    before_trust = deepcopy(trust_report)
    before_pilot = deepcopy(pilot)
    final.build_final_report(trust_report, pilot)
    assert trust_report == before_trust
    assert pilot == before_pilot

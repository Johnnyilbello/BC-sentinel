from __future__ import annotations

from copy import deepcopy

import pytest

from sentinel import beta12_final_freeze as b129
from sentinel import beta12_low_noise_performance as b127
from sentinel import beta12_product_integration as b128


def _impact_report() -> dict:
    return {
        "schema": b127.SCHEMA,
        "profile": b127.PROFILE,
        "passed": True,
        "failures": [],
        "source_checkpoint": b127.SOURCE_CHECKPOINT,
        "source_checkpoint_commit": b127.SOURCE_CHECKPOINT_COMMIT,
        "coverage_summary": {"PARTIAL": 4, "GAP": 0, "VERIFIED": 7},
        "coverage_promoted": False,
        "verified_count_preserved": 7,
        "operational_metrics": {
            "repeat_count": 20,
            "p95_wall_ms": 1.5,
            "p95_cpu_ms": 15.625,
            "max_rss_delta_mib": 0.0625,
            "max_false_positive_detections": 0,
            "max_outcome_drift": 0,
            "max_user_interruptions": 0,
        },
        "budgets": dict(b127.BUDGETS),
        "expected_outcomes": dict(b127.EXPECTED_OUTCOMES),
        "false_positive_gate_passed": True,
        "outcome_stability_gate_passed": True,
        "performance_gate_passed": True,
        "user_interruption_gate_passed": True,
        "new_verified_scenario_earned": False,
        "authority_expanded": False,
        "network_required": False,
        "cloud_required": False,
        "boundaries": dict(b127.BOUNDARIES),
    }


def _snapshot() -> dict:
    return b128.build_product_snapshot(impact_report=_impact_report())


def _ui_smoke() -> dict:
    return {
        "passed": True,
        "page_count": 7,
        "trust_center_selected": True,
        "scenario_card_count": 11,
        "capability_card_count": 7,
        "action_button_count": 0,
        "horizontal_overflow": {"1440": 0, "560": 0, "680": 0, "960": 0},
        "nav_enabled": True,
    }


def test_self_check_binds_exact_b128_checkpoint():
    report = b129.self_check()
    assert report["passed"] is True
    assert report["source_checkpoint"] == "checkpoint/v012-beta12-b128-pass"
    assert report["source_checkpoint_commit"] == "88a7f3df43ba329cb632252ef03928b069cbcc3d"
    assert report["accepted_checkpoint_count"] == 9


def test_all_nine_beta12_predecessor_checkpoints_are_frozen():
    c = b129.contract()
    assert len(c["accepted_beta12_checkpoints"]) == 9
    assert c["accepted_beta12_checkpoints"][0] == {
        "checkpoint": "checkpoint/v012-beta12-b120-pass",
        "commit": "0015feb80c550b9c67707f24f4042a45412e7af3",
    }
    assert c["accepted_beta12_checkpoints"][-1] == {
        "checkpoint": "checkpoint/v012-beta12-b128-pass",
        "commit": "88a7f3df43ba329cb632252ef03928b069cbcc3d",
    }


def test_b127_and_b128_digests_are_bound():
    report = b129.self_check()
    assert report["source_b127_contract_digest"] == "81d9c55313fcd3720e40c53980150f6684844d35cf61e5e1794a8b7fbfc2c8c9"
    assert report["source_b128_contract_digest"] == "2e3029c2d222ad13488d5cbf10e9224eff8b1b8100fc2062ac1ba8009bf2618d"
    assert report["source_b128_product_evidence_digest"] == "91d812eb9bd41cd00402c39f03c61e61a11081ba46e21d993bff258b92f60fa0"


def test_final_coverage_and_verified_set_are_exact():
    report = b129.self_check()
    assert report["coverage_summary"] == {"PARTIAL": 4, "GAP": 0, "VERIFIED": 7}
    assert report["verified_scenarios"] == [
        "B7-POWERSHELL-001",
        "B7-RANSOMWARE-001",
        "B12-SCRIPT-ABUSE-001",
        "B12-AUTOSTART-LINK-001",
        "B12-PROCESS-TREE-001",
        "B12-RANSOMWARE-PROCESS-001",
        "B12-LOCAL-REPUTATION-001",
    ]
    assert report["new_verified_scenario_earned"] is False


def test_final_report_is_freeze_eligible_with_accepted_evidence():
    report = b129.build_final_report(
        impact_report=_impact_report(),
        product_snapshot=_snapshot(),
        ui_smoke=_ui_smoke(),
    )
    assert report["passed"] is True
    assert report["freeze_eligible"] is True
    assert report["freeze_state"] == "ELIGIBLE_AFTER_EXACT_CI_AND_LOCAL_ACCEPTANCE"
    assert report["accepted_checkpoint_count"] == 9
    assert len(report["freeze_evidence_digest"]) == 64


def test_final_report_preserves_product_inventory():
    report = b129.build_final_report(
        impact_report=_impact_report(),
        product_snapshot=_snapshot(),
        ui_smoke=_ui_smoke(),
    )
    assert report["scenario_count"] == 11
    assert report["capability_count"] == 7
    assert report["trust_center_page_count"] == 7
    assert report["trust_center_read_only"] is True
    assert report["trust_center_no_horizontal_overflow"] is True


def test_final_report_does_not_install_sign_publish_or_expand_authority():
    report = b129.build_final_report(
        impact_report=_impact_report(),
        product_snapshot=_snapshot(),
        ui_smoke=_ui_smoke(),
    )
    assert report["installer_execution_performed"] is False
    assert report["artifact_signing_performed"] is False
    assert report["release_publication_performed"] is False
    assert report["coverage_promoted"] is False
    assert report["authority_expanded"] is False
    assert report["network_required"] is False
    assert report["cloud_required"] is False


def test_failed_false_positive_gate_blocks_freeze():
    impact = _impact_report()
    impact["false_positive_gate_passed"] = False
    impact["operational_metrics"]["max_false_positive_detections"] = 1
    report = b129.build_final_report(
        impact_report=impact,
        product_snapshot=b128.build_product_snapshot(impact_report=impact),
        ui_smoke=_ui_smoke(),
    )
    assert report["passed"] is False
    assert report["freeze_eligible"] is False


def test_failed_performance_budget_blocks_freeze():
    impact = _impact_report()
    impact["operational_metrics"]["p95_wall_ms"] = float(b127.BUDGETS["p95_wall_ms"]) + 1.0
    impact["performance_gate_passed"] = False
    report = b129.build_final_report(
        impact_report=impact,
        product_snapshot=b128.build_product_snapshot(impact_report=impact),
        ui_smoke=_ui_smoke(),
    )
    assert report["passed"] is False
    assert report["freeze_eligible"] is False


def test_product_coverage_promotion_blocks_freeze():
    snapshot = _snapshot()
    snapshot["coverage_summary"] = {"PARTIAL": 3, "GAP": 0, "VERIFIED": 8}
    report = b129.build_final_report(
        impact_report=_impact_report(),
        product_snapshot=snapshot,
        ui_smoke=_ui_smoke(),
    )
    assert report["passed"] is False
    assert report["freeze_eligible"] is False


def test_product_evidence_tampering_blocks_freeze():
    snapshot = _snapshot()
    snapshot["capabilities"][0]["summary"] = "tampered"
    report = b129.build_final_report(
        impact_report=_impact_report(),
        product_snapshot=snapshot,
        ui_smoke=_ui_smoke(),
    )
    assert report["passed"] is False
    assert "b129:product_evidence_digest_mismatch" in report["failures"]


def test_ui_action_button_blocks_freeze():
    smoke = _ui_smoke()
    smoke["action_button_count"] = 1
    report = b129.build_final_report(
        impact_report=_impact_report(),
        product_snapshot=_snapshot(),
        ui_smoke=smoke,
    )
    assert report["passed"] is False
    assert "b129:ui_action_button_count_invalid" in report["failures"]


def test_ui_overflow_blocks_freeze():
    smoke = _ui_smoke()
    smoke["horizontal_overflow"]["560"] = 1
    report = b129.build_final_report(
        impact_report=_impact_report(),
        product_snapshot=_snapshot(),
        ui_smoke=smoke,
    )
    assert report["passed"] is False
    assert "b129:ui_horizontal_overflow" in report["failures"]


def test_freeze_digest_ignores_environment_specific_metrics_when_all_gates_pass():
    impact_a = _impact_report()
    impact_b = deepcopy(impact_a)
    impact_b["operational_metrics"]["p95_wall_ms"] = 12.0
    impact_b["operational_metrics"]["p95_cpu_ms"] = 31.25
    impact_b["operational_metrics"]["max_rss_delta_mib"] = 1.0

    report_a = b129.build_final_report(
        impact_report=impact_a,
        product_snapshot=b128.build_product_snapshot(impact_report=impact_a),
        ui_smoke=_ui_smoke(),
    )
    report_b = b129.build_final_report(
        impact_report=impact_b,
        product_snapshot=b128.build_product_snapshot(impact_report=impact_b),
        ui_smoke=_ui_smoke(),
    )
    assert report_a["passed"] is True
    assert report_b["passed"] is True
    assert report_a["freeze_evidence_digest"] == report_b["freeze_evidence_digest"]


def test_contract_is_deterministic():
    assert b129.contract() == b129.contract()
    assert b129.self_check()["deterministic_contract"] is True


def test_input_objects_are_not_mutated():
    impact = _impact_report()
    snapshot = _snapshot()
    smoke = _ui_smoke()
    before = (deepcopy(impact), deepcopy(snapshot), deepcopy(smoke))
    b129.build_final_report(
        impact_report=impact,
        product_snapshot=snapshot,
        ui_smoke=smoke,
    )
    assert impact == before[0]
    assert snapshot == before[1]
    assert smoke == before[2]

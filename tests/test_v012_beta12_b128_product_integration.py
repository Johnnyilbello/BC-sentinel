from __future__ import annotations

from copy import deepcopy

import pytest

from sentinel import beta12_low_noise_performance as b127
from sentinel import beta12_product_integration as b128
from sentinel import beta12_product_integration_ui as ui


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
            "p95_wall_ms": 1.25,
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


def test_self_check_binds_exact_b127_checkpoint():
    report = b128.self_check()
    assert report["passed"] is True
    assert report["source_checkpoint"] == "checkpoint/v012-beta12-b127-pass"
    assert report["source_checkpoint_commit"] == "8e5614c919611a7b072dd0a4f462c56751ba331d"
    assert report["coverage_summary"] == {"PARTIAL": 4, "GAP": 0, "VERIFIED": 7}
    assert report["new_verified_scenario_earned"] is False


def test_product_snapshot_reconciles_exact_coverage():
    snapshot = b128.build_product_snapshot()
    assert snapshot["passed"] is True
    assert snapshot["coverage_summary"] == {"PARTIAL": 4, "GAP": 0, "VERIFIED": 7}
    assert len(snapshot["scenarios"]) == 11
    assert sum(row["status"] == "VERIFIED" for row in snapshot["scenarios"]) == 7
    assert sum(row["status"] == "PARTIAL" for row in snapshot["scenarios"]) == 4


def test_verified_set_is_exact_and_ordered():
    snapshot = b128.build_product_snapshot()
    assert snapshot["verified_scenarios"] == [
        "B7-POWERSHELL-001",
        "B7-RANSOMWARE-001",
        "B12-SCRIPT-ABUSE-001",
        "B12-AUTOSTART-LINK-001",
        "B12-PROCESS-TREE-001",
        "B12-RANSOMWARE-PROCESS-001",
        "B12-LOCAL-REPUTATION-001",
    ]


def test_partial_scenarios_remain_partial():
    snapshot = b128.build_product_snapshot()
    partial = {
        row["scenario_id"]
        for row in snapshot["scenarios"]
        if row["status"] == "PARTIAL"
    }
    assert partial == {
        "B7-PERSISTENCE-001",
        "B7-DEFENSE-EVASION-001",
        "B7-C2-DNS-001",
        "B7-CREDENTIAL-001",
    }


def test_snapshot_is_read_only_and_does_not_expand_authority():
    snapshot = b128.build_product_snapshot()
    assert snapshot["product_ui_read_only"] is True
    assert snapshot["coverage_promoted_by_presentation"] is False
    assert snapshot["broad_protection_claimed"] is False
    assert snapshot["automatic_remediation_claimed"] is False
    assert snapshot["maliciousness_verdict_for_unknown_files_claimed"] is False
    assert snapshot["trust_allowlist_mutated"] is False
    assert snapshot["remediation_performed"] is False
    assert snapshot["system_mutation_performed"] is False
    assert snapshot["authority"]["new_authority_expanded"] is False


def test_snapshot_without_impact_does_not_invent_metrics():
    snapshot = b128.build_product_snapshot()
    impact = snapshot["operational_impact"]
    assert impact["status"] == "NOT_LOADED"
    assert impact["measured"] is False
    assert impact["metrics"] is None


def test_snapshot_accepts_passed_b127_measurement():
    snapshot = b128.build_product_snapshot(impact_report=_impact_report())
    impact = snapshot["operational_impact"]
    assert snapshot["passed"] is True
    assert impact["status"] == "MEASURED"
    assert impact["measured"] is True
    assert impact["metrics"]["max_false_positive_detections"] == 0
    assert impact["metrics"]["max_outcome_drift"] == 0
    assert impact["performance_gate_passed"] is True


@pytest.mark.parametrize(
    "field",
    [
        "false_positive_gate_passed",
        "outcome_stability_gate_passed",
        "performance_gate_passed",
        "user_interruption_gate_passed",
    ],
)
def test_failed_b127_gate_is_rejected(field):
    report = _impact_report()
    report[field] = False
    snapshot = b128.build_product_snapshot(impact_report=report)
    assert snapshot["passed"] is False
    assert snapshot["operational_impact"]["status"] == "INVALID"


def test_impact_coverage_promotion_is_rejected():
    report = _impact_report()
    report["coverage_promoted"] = True
    snapshot = b128.build_product_snapshot(impact_report=report)
    assert snapshot["passed"] is False
    assert "impact:coverage_promoted" in snapshot["failures"]


def test_validation_rejects_verified_set_tampering():
    snapshot = b128.build_product_snapshot()
    snapshot["verified_scenarios"] = snapshot["verified_scenarios"][:-1]
    result = b128.validate_snapshot(snapshot)
    assert result["passed"] is False
    assert "snapshot:verified_set_invalid" in result["failures"]


def test_validation_rejects_scenario_promotion_by_ui():
    snapshot = b128.build_product_snapshot()
    tampered = deepcopy(snapshot)
    next(row for row in tampered["scenarios"] if row["scenario_id"] == "B7-PERSISTENCE-001")["status"] = "VERIFIED"
    result = b128.validate_snapshot(tampered)
    assert result["passed"] is False
    assert "snapshot:scenario_facts_changed" in result["failures"]


def test_validation_rejects_authority_change():
    snapshot = b128.build_product_snapshot()
    snapshot["authority"]["automatic_quarantine"] = True
    result = b128.validate_snapshot(snapshot)
    assert result["passed"] is False
    assert "snapshot:authority_changed" in result["failures"]


@pytest.mark.parametrize(
    "field",
    [
        "coverage_promoted_by_presentation",
        "broad_protection_claimed",
        "automatic_remediation_claimed",
        "maliciousness_verdict_for_unknown_files_claimed",
        "trust_allowlist_mutated",
        "remediation_performed",
        "system_mutation_performed",
    ],
)
def test_validation_rejects_unsafe_claim_or_mutation_flag(field):
    snapshot = b128.build_product_snapshot()
    snapshot[field] = True
    result = b128.validate_snapshot(snapshot)
    assert result["passed"] is False
    assert f"snapshot:{field}_invalid" in result["failures"]


def test_capabilities_are_all_non_executing():
    snapshot = b128.build_product_snapshot()
    assert len(snapshot["capabilities"]) == 7
    assert all(item["execution_authority"] is False for item in snapshot["capabilities"])


def test_snapshot_is_deterministic():
    assert b128.build_product_snapshot() == b128.build_product_snapshot()


def test_ui_smoke_is_read_only_responsive():
    snapshot = b128.build_product_snapshot(impact_report=_impact_report())
    report = ui.smoke_test_window(snapshot)
    assert report["passed"] is True
    assert report["page_count"] == 7
    assert report["trust_center_selected"] is True
    assert report["scenario_card_count"] == 11
    assert report["capability_card_count"] == 7
    assert report["action_button_count"] == 0
    assert report["nav_enabled"] is True
    assert all(value == 0 for value in report["horizontal_overflow"].values())

from __future__ import annotations

import os

import pytest
from PySide6.QtWidgets import QApplication

from sentinel import beta10_trust_center as b108
from sentinel import beta10_trust_center_ui as trust_ui


@pytest.fixture(scope="module")
def app() -> QApplication:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    instance = QApplication.instance() or QApplication([])
    return instance


def _valid_impact_report() -> dict:
    return {
        "schema": "bc-sentinel-beta10-operational-impact-v1",
        "profile": "v0.11.0-beta.10-b107-live-coverage-expansion-ii",
        "passed": True,
        "coverage_summary": {"PARTIAL": 4, "GAP": 0, "VERIFIED": 2},
        "coverage_promoted": False,
        "new_authority_expanded": False,
        "false_positive_controls_passed": True,
        "user_interruption_budget_passed": True,
        "performance_budget_passed": True,
        "operational_metrics": {
            "repeat_count": 7,
            "p95_wall_ms": 0.5493,
            "p95_cpu_ms": 15.625,
            "max_rss_delta_mib": 0.003906,
            "max_user_interruptions": 0,
        },
    }


def test_b108_contract_is_bound_to_exact_b107_checkpoint() -> None:
    contract = b108.validate_b108_contract()
    assert contract["passed"] is True
    assert contract["source_predecessor_commit"] == "2428817e99b9e0969fc00e4c76e383a1004ba26c"
    assert contract["source_predecessor_checkpoint"] == "checkpoint/v011-beta10-b107-pass"
    assert contract["coverage_summary"] == {"PARTIAL": 4, "GAP": 0, "VERIFIED": 2}
    assert contract["verified_scenarios"] == ["B7-POWERSHELL-001", "B7-RANSOMWARE-001"]
    assert contract["scenario_count"] == 6
    assert contract["capability_count"] == 6


def test_trust_center_snapshot_preserves_exact_coverage_and_limitations() -> None:
    snapshot = b108.build_trust_center_snapshot()
    assert snapshot["passed"] is True
    assert b108.validate_snapshot(snapshot)["passed"] is True
    assert snapshot["coverage_summary"] == {"PARTIAL": 4, "GAP": 0, "VERIFIED": 2}
    statuses = {row["scenario_id"]: row["status"] for row in snapshot["scenarios"]}
    assert statuses["B7-POWERSHELL-001"] == "VERIFIED"
    assert statuses["B7-RANSOMWARE-001"] == "VERIFIED"
    assert statuses["B7-PERSISTENCE-001"] == "PARTIAL"
    assert statuses["B7-DEFENSE-EVASION-001"] == "PARTIAL"
    assert statuses["B7-C2-DNS-001"] == "PARTIAL"
    assert statuses["B7-CREDENTIAL-001"] == "PARTIAL"
    assert all(row["limitation"] for row in snapshot["scenarios"])


def test_presentation_cannot_promote_coverage_or_claim_broad_protection() -> None:
    snapshot = b108.build_trust_center_snapshot()
    assert snapshot["coverage_promoted_by_presentation"] is False
    assert snapshot["broad_protection_claimed"] is False
    assert snapshot["remediation_performed"] is False
    assert snapshot["system_mutation_performed"] is False
    assert snapshot["incident_story"] == {
        "status": "NO_INCIDENT_LOADED",
        "observed_stages_claimed": 0,
        "unknown_stages_preserved": True,
        "invented_entry_point": False,
    }


def test_response_section_preserves_general_execution_boundary() -> None:
    response = b108.build_trust_center_snapshot()["response"]
    assert response["planning_available"] is True
    assert response["general_execution_available"] is False
    assert response["automatic_remediation"] is False
    assert response["reversible_pilot_available"] is True
    assert response["reversible_pilot_scope"] == "DISPOSABLE_TEMP_WORKSPACE_ONLY"
    assert response["explicit_confirmation_required"] is True
    assert response["target_identity_binding_required"] is True
    assert response["journal_required"] is True
    assert response["rollback_required"] is True


def test_privacy_and_authority_are_local_first_and_narrow() -> None:
    snapshot = b108.build_trust_center_snapshot()
    assert snapshot["privacy"]["local_only"] is True
    assert snapshot["privacy"]["credential_access"] is False
    assert snapshot["privacy"]["network_io"] is False
    assert snapshot["privacy"]["powershell_content_read"] is False
    assert snapshot["authority"]["automatic_quarantine"] is False
    assert snapshot["authority"]["general_home_execution"] is False
    assert snapshot["authority"]["network_test_authority"] is False
    assert snapshot["authority"]["new_authority_expanded"] is False


def test_valid_b107_impact_report_is_projected_without_changing_coverage() -> None:
    snapshot = b108.build_trust_center_snapshot(impact_report=_valid_impact_report())
    assert snapshot["passed"] is True
    assert snapshot["operational_impact"]["status"] == "MEASURED"
    assert snapshot["operational_impact"]["measured"] is True
    assert snapshot["operational_impact"]["metrics"]["p95_wall_ms"] == 0.5493
    assert snapshot["coverage_summary"] == {"PARTIAL": 4, "GAP": 0, "VERIFIED": 2}


def test_invalid_impact_report_fails_closed() -> None:
    report = _valid_impact_report()
    report["coverage_summary"] = {"PARTIAL": 3, "GAP": 0, "VERIFIED": 3}
    snapshot = b108.build_trust_center_snapshot(impact_report=report)
    assert snapshot["passed"] is False
    assert "impact:coverage_changed" in snapshot["failures"]
    assert snapshot["operational_impact"]["status"] == "INVALID"
    assert snapshot["operational_impact"]["measured"] is False
    assert snapshot["operational_impact"]["metrics"] is None


def test_snapshot_validation_rejects_promoted_coverage() -> None:
    snapshot = b108.build_trust_center_snapshot()
    snapshot["coverage_summary"] = {"PARTIAL": 3, "GAP": 0, "VERIFIED": 3}
    validation = b108.validate_snapshot(snapshot)
    assert validation["passed"] is False
    assert "snapshot:coverage_invalid" in validation["failures"]


def test_snapshot_validation_rejects_authority_change() -> None:
    snapshot = b108.build_trust_center_snapshot()
    snapshot["authority"]["automatic_quarantine"] = True
    validation = b108.validate_snapshot(snapshot)
    assert validation["passed"] is False
    assert "snapshot:authority_changed" in validation["failures"]


def test_trust_center_page_renders_all_scenarios_and_capabilities(app: QApplication) -> None:
    page = trust_ui.TrustCenterPage(b108.build_trust_center_snapshot())
    try:
        assert len(page.scenario_cards) == 6
        assert len(page.capability_cards) == 6
        assert len(page.summary_cards) == 3
        page.set_compact(True, False)
        app.processEvents()
        page.set_compact(False, False)
        app.processEvents()
    finally:
        page.deleteLater()
        app.processEvents()


def test_trust_center_window_adds_seventh_read_only_surface(app: QApplication) -> None:
    window = trust_ui.TrustCenterWindow(trust_snapshot=b108.build_trust_center_snapshot())
    try:
        window.show()
        app.processEvents()
        assert window.stack.count() == 7
        assert window.trust_center_nav_button.isEnabled() is True
        window._navigate("Trust Center")
        app.processEvents()
        assert window.stack.currentWidget() is window.trust_center_scroll
        assert "Trust Center" in window.topbar_title.text()
    finally:
        window.close()
        app.processEvents()


def test_trust_center_has_no_horizontal_overflow_at_acceptance_widths(app: QApplication) -> None:
    snapshot = b108.build_trust_center_snapshot(impact_report=_valid_impact_report())
    window = trust_ui.TrustCenterWindow(trust_snapshot=snapshot)
    try:
        window.show()
        window._navigate("Trust Center")
        for width in (1440, 960, 680, 560):
            window.resize(width, 820)
            window._apply_responsive_layout(force=True)
            app.processEvents()
            window.trust_center_scroll.sync_width()
            app.processEvents()
            assert window.trust_center_scroll.horizontalScrollBar().maximum() == 0
    finally:
        window.close()
        app.processEvents()

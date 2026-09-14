from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("BC_SENTINEL_REDUCED_MOTION", "1")

from PySide6.QtWidgets import QApplication, QSpinBox

from sentinel import home_smart_scan as smart
from sentinel import home_threat_cards as threat
from sentinel import ui_quality_refinement as quality
from sentinel.home_guided_resolution_ui import B65ThreatCardWidget
from sentinel.home_guided_resolution_window import B65SecurityOverviewWindow
from sentinel.home_smart_scan_ui import SmartScanPage
from sentinel.home_threat_cards_ui import ThreatCardWidget


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


def _card_model() -> threat.ThreatCardModel:
    finding = smart.SmartScanFinding(
        finding_id="ui-quality-fixture",
        title="Elemento di test",
        severity=smart.SEVERITY_HIGH,
        category="fixture",
        reason="Motivazione di test non operativa",
        source_check_id="files",
        path=r"C:\Fixture\quality.test",
        confidence=None,
        evidence={"fixture": True},
    )
    result = smart.SmartScanResult(
        session_id="ui-quality-session",
        correlation_id="ui-quality-correlation",
        state=smart.STATE_COMPLETED_FINDINGS,
        started_at=1.0,
        finished_at=2.0,
        elapsed_ms=1000.0,
        coverage=smart.COVERAGE_COMPLETE,
        completed_checks=1,
        total_checks=1,
        findings=(finding,),
        highest_severity=smart.SEVERITY_HIGH,
        summary="Fixture",
        recommendation="Verifica il contesto prima di agire.",
        provider_name="ui-quality-provider",
        provider_profile="ui-quality-v1",
        provider_provenance="ui_quality_test",
        plan=smart.SmartScanPlan(
            provider_name="ui-quality-provider",
            provider_profile="ui-quality-v1",
            provider_provenance="ui_quality_test",
            checks=(smart.SmartScanCheck("files", "Files", "Fixture", True, "ui_quality_test"),),
        ),
        check_results=(
            smart.SmartScanCheckResult(
                "files",
                smart.CHECK_COMPLETED,
                "Fixture complete",
                findings=(finding,),
                evidence={"fixture": True},
            ),
        ),
        raw_evidence={"fixture": True},
    )
    return threat.build_threat_card(result, finding)


def test_ui_quality_contract_prioritizes_task_clarity_without_new_authority() -> None:
    contract = quality.validate_ui_quality_contract()
    assert contract["passed"] is True
    assert contract["progressive_disclosure"] is True
    assert contract["native_windows_typography"] is True
    assert contract["minimum_control_height_px"] == 40
    assert contract["decorative_product_imagery"] is False
    assert contract["quantity_selector_present"] is False
    assert contract["automatic_quarantine"] is False
    assert contract["automatic_repair"] is False
    assert contract["automatic_destructive_action"] is False


def test_smart_scan_exposes_visual_progress_and_secondary_advanced_evidence() -> None:
    _app()
    page = SmartScanPage(provider_available=True)
    page.set_running()
    assert page.progress_bar.isHidden() is False
    assert page.progress_bar.value() == 0
    assert page.advanced_button.objectName() == "AdvancedToggle"

    progress = smart.SmartScanProgress(42, 1, 3, "files", "Analisi in corso")
    page.set_progress(progress)
    assert page.progress_bar.value() == 42
    assert "42%" in page.progress_label.text()


def test_threat_card_uses_plain_language_hierarchy_and_progressive_details() -> None:
    _app()
    widget = ThreatCardWidget(_card_model())
    assert widget.objectName() == "ThreatCard"
    assert widget.property("severity") == smart.SEVERITY_HIGH
    assert widget.severity_badge.text().startswith("Alta")
    assert "HIGH" in widget.severity_badge.text()
    assert widget.reason_heading.text() == "Perché è stato segnalato"
    assert widget.recommendation_heading.text() == "Cosa fare adesso"
    assert widget.advanced_text.isHidden() is True

    widget.advanced_button.setChecked(True)
    assert widget.advanced_text.isHidden() is False
    assert widget.advanced_button.text() == "Nascondi dettagli avanzati"


def test_guided_resolution_keeps_internal_state_out_of_primary_copy() -> None:
    _app()
    widget = B65ThreatCardWidget(_card_model())
    panel = widget.resolution_panel
    assert panel.authority_badge.text() == "Solo verifica"
    assert "REPORT_ONLY" not in panel.authority_badge.text()
    assert "B6-5" not in panel.next_step_label.text()
    assert panel.state_label.isHidden() is True
    assert "REPORT_ONLY" in panel.state_label.text()
    assert panel.details_text.isHidden() is True
    assert panel.model.execution_available is False


def test_current_home_applies_quality_layer_without_quantity_controls_or_overflow() -> None:
    app = _app()
    window = B65SecurityOverviewWindow()
    try:
        window.resize(760, 760)
        window.show()
        app.processEvents()
        window._apply_responsive_layout(force=True)
        window._navigate("Scansione")
        window._sync_all_scroll_widths()
        app.processEvents()

        stylesheet = window.styleSheet()
        assert "#ThreatCard" in stylesheet
        assert "#ScanProgressBar" in stylesheet
        assert window.findChildren(QSpinBox) == []
        assert window.scan_scroll.horizontalScrollBar().maximum() == 0
        assert window.full_scan_button.isEnabled() is False
    finally:
        window.close()

from __future__ import annotations

import os
import warnings

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("BC_SENTINEL_REDUCED_MOTION", "1")

from PySide6.QtWidgets import QApplication, QLabel, QSizePolicy, QSpinBox

from sentinel import home_smart_scan as smart
from sentinel import home_threat_cards as threat
from sentinel import ui_live_polish
from sentinel import ui_quality_refinement as quality
from sentinel.home_guided_resolution_ui import B65ThreatCardWidget
from sentinel.home_guided_resolution_window import B65SecurityOverviewWindow
from sentinel.home_smart_scan_ui import SmartScanPage
from sentinel.home_threat_cards_ui import ThreatCardWidget
from sentinel.ui_motion_components import AnimatedNumberLabel, StatusOrb, reduced_motion_enabled


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
    assert contract["motion_is_state_relevant_only"] is True
    assert contract["reduced_motion_supported"] is True
    assert "number_flow_to_scan_progress" in contract["reference_patterns_adapted"]
    assert "thinking_orb_to_scan_status" in contract["reference_patterns_adapted"]
    assert "cursor_attractor" in contract["reference_patterns_intentionally_not_used"]
    assert "gooey_filter" in contract["reference_patterns_intentionally_not_used"]
    assert contract["decorative_product_imagery"] is False
    assert contract["quantity_selector_present"] is False
    assert contract["automatic_quarantine"] is False
    assert contract["automatic_repair"] is False
    assert contract["automatic_destructive_action"] is False


def test_motion_primitives_respect_reduced_motion_and_plain_state_semantics() -> None:
    _app()
    assert reduced_motion_enabled() is True

    number = AnimatedNumberLabel(0)
    number.set_target(42)
    assert number.text() == "42%"

    orb = StatusOrb(48)
    assert orb.state == "idle"
    orb.set_state("working")
    assert orb.state == "working"
    assert "scansione in corso" in orb.accessibleName()
    assert orb._timer.isActive() is False
    orb.set_state("clean")
    assert "senza rilevamenti" in orb.accessibleName()


def test_smart_scan_exposes_visual_progress_and_secondary_advanced_evidence() -> None:
    _app()
    page = SmartScanPage(provider_available=True)
    assert page.mark.state == "idle"
    page.set_running()
    assert page.mark.state == "working"
    assert page.progress_value.isHidden() is False
    assert page.progress_value.text() == "0%"
    assert page.progress_bar.isHidden() is False
    assert page.progress_bar.value() == 0
    assert page.advanced_button.objectName() == "AdvancedToggle"

    progress = smart.SmartScanProgress(42, 1, 3, "files", "Analisi in corso")
    page.set_progress(progress)
    assert page.progress_value.text() == "42%"
    assert page.progress_bar.value() == 42
    assert "1/3 controlli" in page.progress_label.text()


def test_threat_card_uses_plain_language_hierarchy_and_progressive_details() -> None:
    _app()
    widget = ThreatCardWidget(_card_model())
    assert widget.objectName() == "ThreatCard"
    assert widget.property("severity") == smart.SEVERITY_HIGH
    assert widget.severity_badge.text().startswith("Alta")
    assert smart.SEVERITY_HIGH in widget.severity_badge.text()
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
        assert "#ScanProgressValue" in stylesheet
        assert "QToolTip" in stylesheet
        assert window.findChildren(QSpinBox) == []
        assert window.scan_scroll.horizontalScrollBar().maximum() == 0
        assert window.full_scan_button.isEnabled() is False
    finally:
        window.close()


def test_live_ui_polish_removes_hard_caps_from_wrapped_primary_copy() -> None:
    app = _app()
    window = B65SecurityOverviewWindow()
    try:
        window.resize(720, 720)
        window.show()
        window._navigate("Scansione")
        window._apply_responsive_layout(force=True)
        app.processEvents()

        assert window.scan_page.panel.maximumHeight() == 16777215
        assert window.scan_page.panel.sizePolicy().verticalPolicy() != QSizePolicy.Policy.Fixed
        assert window.scan_page.task_subtitle.maximumWidth() == 16777215
        assert window.scan_page.task_subtitle.sizePolicy().verticalPolicy() != QSizePolicy.Policy.Fixed

        window._navigate("Quarantena")
        app.processEvents()
        empty = window.quarantine_page.empty
        body = empty.findChild(QLabel, "EmptyBody")
        assert empty.maximumHeight() == 16777215
        assert empty.sizePolicy().verticalPolicy() != QSizePolicy.Policy.Fixed
        assert body is not None
        assert body.maximumWidth() == 16777215
        assert body.sizePolicy().verticalPolicy() != QSizePolicy.Policy.Fixed
    finally:
        window.close()


def test_status_and_quarantine_refresh_controls_use_distinct_semantic_icons() -> None:
    app = _app()
    window = B65SecurityOverviewWindow()
    try:
        window.show()
        app.processEvents()
        status_button = window.refresh_button
        list_button = window.quarantine_page.refresh_button
        assert status_button.property("semanticIcon") == "status_refresh"
        assert list_button.property("semanticIcon") == "list_refresh"
        assert status_button.property("semanticIcon") != list_button.property("semanticIcon")
        assert status_button.icon().isNull() is False
        assert list_button.icon().isNull() is False
    finally:
        window.close()


def test_b653_window_hides_known_pyside_disconnect_noise_from_user_session() -> None:
    _app()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        window = B65SecurityOverviewWindow()
        try:
            assert not any("Failed to disconnect" in str(item.message) for item in caught)
        finally:
            window.close()


def test_live_ui_polish_contract_preserves_security_authority() -> None:
    contract = ui_live_polish.validate_live_ui_polish_contract()
    assert contract["passed"] is True
    assert contract["wrapped_text_uses_content_driven_height"] is True
    assert contract["refresh_icons_semantically_distinct"] is True
    assert contract["automatic_quarantine"] is False
    assert contract["automatic_repair"] is False
    assert contract["automatic_destructive_action"] is False

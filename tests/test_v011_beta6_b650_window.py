from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("BC_SENTINEL_REDUCED_MOTION", "1")

from PySide6.QtWidgets import QApplication

from sentinel import home_guided_resolution as guided
from sentinel import home_guided_resolution_window as b65
from sentinel import home_smart_scan as smart
from sentinel.home_guided_resolution_ui import B65SmartScanPage, B65ThreatCardWidget


def _result() -> smart.SmartScanResult:
    finding = smart.SmartScanFinding(
        finding_id="b650-window-finding",
        title="Guided window fixture",
        severity=smart.SEVERITY_MEDIUM,
        category="fixture",
        reason="Harmless deterministic B6-5.0 window fixture",
        source_check_id="files",
        path=r"C:\Fixture\guided-window.test",
        confidence=None,
        evidence={"fixture": True},
    )
    plan = smart.SmartScanPlan(
        provider_name="b650-window-provider",
        provider_profile="b650-window-v1",
        provider_provenance="b650_window_test",
        checks=(smart.SmartScanCheck("files", "Files", "Fixture", True, "b650_window_test"),),
    )
    check = smart.SmartScanCheckResult(
        "files",
        smart.CHECK_COMPLETED,
        "Fixture complete",
        findings=(finding,),
        evidence={"fixture": True},
    )
    return smart.SmartScanResult(
        session_id="b650-window-session",
        correlation_id="b650-window-correlation",
        state=smart.STATE_COMPLETED_FINDINGS,
        started_at=1.0,
        finished_at=2.0,
        elapsed_ms=1000.0,
        coverage=smart.COVERAGE_COMPLETE,
        completed_checks=1,
        total_checks=1,
        findings=(finding,),
        highest_severity=smart.SEVERITY_MEDIUM,
        summary="Fixture summary",
        recommendation="Review the finding.",
        provider_name="b650-window-provider",
        provider_profile="b650-window-v1",
        provider_provenance="b650_window_test",
        plan=plan,
        check_results=(check,),
        raw_evidence={"fixture": True},
    )


def test_b650_window_preserves_shell_and_adds_guidance_without_dispatch_or_overflow() -> None:
    app = QApplication.instance() or QApplication([])
    window = b65.B65SecurityOverviewWindow()
    assert isinstance(window.scan_page, B65SmartScanPage)
    assert window.stack.count() == 6

    window.scan_page.set_result(_result())
    window._navigate("Scansione")
    window.resize(1180, 760)
    window.show()
    app.processEvents()
    window._apply_responsive_layout(force=True)
    window._sync_all_scroll_widths()
    app.processEvents()

    assert len(window.scan_page.threat_card_widgets) == 1
    widget = window.scan_page.threat_card_widgets[0]
    assert isinstance(widget, B65ThreatCardWidget)
    assert widget.resolution_model.authority_state == guided.AUTHORITY_REPORT_ONLY
    assert widget.resolution_model.execution_available is False
    assert widget.resolution_model.canonical_confidence is None
    assert window.scan_scroll.horizontalScrollBar().maximum() == 0
    assert window.last_smart_scan_result is None
    assert window.smart_scan_coordinator.state == smart.STATE_IDLE

    window.close()


def test_b650_self_check_keeps_b64_green_and_execution_disabled() -> None:
    payload = b65.self_check()
    assert payload["passed"] is True
    assert payload["parent_b64"]["passed"] is True
    assert payload["remediation_provider_boundary_verified"] is False
    assert payload["execution_available"] is False
    assert payload["automatic_quarantine"] is False
    assert payload["automatic_repair"] is False
    assert payload["automatic_destructive_action"] is False

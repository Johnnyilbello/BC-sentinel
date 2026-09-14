from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("BC_SENTINEL_REDUCED_MOTION", "1")

from PySide6.QtWidgets import QApplication

from sentinel import home_smart_scan as smart
from sentinel import home_threat_cards_window as b64
from sentinel.home_threat_cards_ui import B64SmartScanPage


def _result() -> smart.SmartScanResult:
    finding = smart.SmartScanFinding(
        finding_id="b64-window-finding",
        title="Window integration fixture",
        severity=smart.SEVERITY_MEDIUM,
        category="fixture",
        reason="Harmless deterministic window fixture",
        source_check_id="files",
        path=r"C:\Fixture\window.test",
        confidence=0.5,
        evidence={"fixture": True},
    )
    plan = smart.SmartScanPlan(
        provider_name="window-fixture",
        provider_profile="window-fixture-v1",
        provider_provenance="b64_window_test",
        checks=(
            smart.SmartScanCheck("files", "Files", "Fixture", True, "b64_window_test"),
        ),
    )
    check = smart.SmartScanCheckResult(
        "files",
        smart.CHECK_COMPLETED,
        "Fixture complete",
        findings=(finding,),
        evidence={"fixture": True},
    )
    return smart.SmartScanResult(
        session_id="b64-window-session",
        correlation_id="b64-window-correlation",
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
        recommendation="Review the findings before taking action.",
        provider_name="window-fixture",
        provider_profile="window-fixture-v1",
        provider_provenance="b64_window_test",
        plan=plan,
        check_results=(check,),
        raw_evidence={"fixture": True},
    )


def test_b64_window_preserves_shell_and_renders_cards_without_horizontal_overflow() -> None:
    app = QApplication.instance() or QApplication([])
    window = b64.B64SecurityOverviewWindow()
    assert isinstance(window.scan_page, B64SmartScanPage)
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
    assert window.scan_page.threat_section.isVisible()
    assert window.scan_scroll.horizontalScrollBar().maximum() == 0
    assert window.last_smart_scan_result is None
    assert window.smart_scan_coordinator.state == smart.STATE_IDLE

    window.close()

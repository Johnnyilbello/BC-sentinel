from __future__ import annotations

import os
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("BC_SENTINEL_REDUCED_MOTION", "1")

from PySide6.QtWidgets import QApplication

from sentinel import home_security_model as security_model
from sentinel import home_smart_scan as smart
from sentinel import home_smart_scan_window as b63_ui


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


def _evidence() -> dict:
    def item(layer_id: str, status: str, verified: bool = False):
        return security_model.LayerEvidence(
            layer_id=layer_id,
            status=status,
            runtime_verified=verified,
            summary=f"fixture:{layer_id}:{status}",
            raw={"fixture": True},
            provenance="b63_ui_fixture",
        )

    return {
        security_model.LAYER_MALWARE: item(
            security_model.LAYER_MALWARE, security_model.STATUS_ENGINE_AVAILABLE
        ),
        security_model.LAYER_BEHAVIOR: item(
            security_model.LAYER_BEHAVIOR, security_model.STATUS_ENGINE_AVAILABLE
        ),
        security_model.LAYER_WEB: item(
            security_model.LAYER_WEB, security_model.STATUS_ENGINE_AVAILABLE
        ),
        security_model.LAYER_RECOVERY: item(
            security_model.LAYER_RECOVERY, security_model.STATUS_READY, True
        ),
    }


class UiFixtureProvider:
    def __init__(self, *, finding: bool = False, block: bool = False) -> None:
        self.finding = finding
        self.block = block
        self.plan_calls = 0
        self.run_calls = 0
        self.cancel_seen = False

    def capabilities(self):
        return {
            "available": True,
            "accepted": True,
            "provider_name": "ui-fixture",
            "provider_profile": "ui-fixture-v1",
            "provider_provenance": "ui_test",
            "automatic_quarantine": False,
            "automatic_repair": False,
            "automatic_destructive_action": False,
        }

    def build_plan(self):
        self.plan_calls += 1
        return smart.SmartScanPlan(
            provider_name="ui-fixture",
            provider_profile="ui-fixture-v1",
            provider_provenance="ui_test",
            checks=(
                smart.SmartScanCheck(
                    "fixture_check",
                    "Fixture check",
                    "Harmless deterministic UI fixture",
                    True,
                    "ui_test",
                ),
            ),
            raw={"ui_fixture": True},
        )

    def run(self, plan, progress_callback, cancel_check):
        self.run_calls += 1
        progress_callback(smart.SmartScanProgress(25, 0, 1, "fixture_check", "Starting"))
        if self.block:
            deadline = time.monotonic() + 1.5
            while time.monotonic() < deadline:
                if cancel_check():
                    self.cancel_seen = True
                    return smart.SmartScanProviderResult(
                        (
                            smart.SmartScanCheckResult(
                                "fixture_check", smart.CHECK_CANCELLED, "Cancelled"
                            ),
                        ),
                        {"cancelled": True},
                    )
                time.sleep(0.01)
        findings = ()
        if self.finding:
            findings = (
                smart.SmartScanFinding(
                    finding_id="ui-fixture-finding",
                    title="Harmless fixture finding",
                    severity=smart.SEVERITY_MEDIUM,
                    category="fixture",
                    reason="UI test",
                    source_check_id="fixture_check",
                    evidence={"raw": "preserved"},
                ),
            )
        progress_callback(smart.SmartScanProgress(100, 1, 1, "fixture_check", "Done"))
        return smart.SmartScanProviderResult(
            (
                smart.SmartScanCheckResult(
                    "fixture_check",
                    smart.CHECK_COMPLETED,
                    "Fixture complete",
                    findings=findings,
                    evidence={"check_raw": True},
                ),
            ),
            {"provider_raw": True},
        )


def _wait_worker(window: b63_ui.B63SecurityOverviewWindow, timeout: float = 2.0) -> None:
    app = _app()
    deadline = time.monotonic() + timeout
    while window.smart_scan_worker is not None and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.01)
    app.processEvents()
    assert window.smart_scan_worker is None


def test_b63_self_check_is_passive_and_parent_b62_green() -> None:
    payload = b63_ui.self_check()
    assert payload["passed"] is True
    assert payload["profile"] == smart.PROFILE
    assert payload["window_created"] is False
    assert payload["startup_scan_dispatch"] is False
    assert payload["navigation_scan_dispatch"] is False
    assert payload["refresh_scan_dispatch"] is False
    assert payload["full_scan_enabled"] is False
    assert payload["parent_b62"]["passed"] is True


def test_default_window_never_fakes_provider_or_scan_authority() -> None:
    _app()
    window = b63_ui.B63SecurityOverviewWindow(status_provider=_evidence)
    try:
        assert window.smart_scan_coordinator.is_available() is False
        assert window.smart_scan_button.isEnabled() is False
        assert window.sidebar_scan_button.isEnabled() is False
        assert window.scan_page.quick_scan.isEnabled() is False
        assert window.full_scan_button.isEnabled() is False
        assert window.scan_page.full_scan.isEnabled() is False
        assert window.smart_scan_coordinator.state == smart.STATE_IDLE
        assert window.last_smart_scan_result is None
    finally:
        window.close()


def test_available_provider_enables_only_smart_scan_entry_points() -> None:
    _app()
    provider = UiFixtureProvider()
    window = b63_ui.B63SecurityOverviewWindow(status_provider=_evidence, smart_scan_provider=provider)
    try:
        assert window.smart_scan_button.isEnabled() is True
        assert window.sidebar_scan_button.isEnabled() is True
        assert window.scan_page.quick_scan.isEnabled() is True
        assert window.full_scan_button.isEnabled() is False
        assert window.scan_page.full_scan.isEnabled() is False
        assert provider.plan_calls == 0
        assert provider.run_calls == 0
    finally:
        window.close()


def test_navigation_and_refresh_remain_passive_with_available_provider() -> None:
    app = _app()
    provider = UiFixtureProvider()
    status_calls = []

    def status_provider():
        status_calls.append("status")
        return _evidence()

    window = b63_ui.B63SecurityOverviewWindow(
        status_provider=status_provider, smart_scan_provider=provider
    )
    try:
        for page in b63_ui.base_ui.PAGE_ORDER:
            window._navigate(page)
            app.processEvents()
        window.refresh_button.click()
        app.processEvents()
        assert provider.plan_calls == 0
        assert provider.run_calls == 0
        assert len(status_calls) == 2
        assert window.smart_scan_coordinator.state == smart.STATE_IDLE
    finally:
        window.close()


def test_explicit_dashboard_click_runs_one_scan_and_renders_real_result() -> None:
    app = _app()
    provider = UiFixtureProvider(finding=True)
    window = b63_ui.B63SecurityOverviewWindow(status_provider=_evidence, smart_scan_provider=provider)
    try:
        window.smart_scan_button.click()
        app.processEvents()
        _wait_worker(window)
        assert provider.plan_calls == 1
        assert provider.run_calls == 1
        assert window.last_smart_scan_result is not None
        assert window.last_smart_scan_result.state == smart.STATE_COMPLETED_FINDINGS
        assert window.stack.currentIndex() == 1
        assert window.scan_page.advanced_button.isVisible() is True
        assert "provider_raw" in window.scan_page.advanced_text.toPlainText()
        assert window.smart_scan_button.isEnabled() is True
        assert window.scan_page.quick_scan.isEnabled() is True
    finally:
        window.close()


def test_sidebar_and_scan_page_use_same_coordinator_contract() -> None:
    app = _app()
    provider = UiFixtureProvider()
    window = b63_ui.B63SecurityOverviewWindow(status_provider=_evidence, smart_scan_provider=provider)
    try:
        window.sidebar_scan_button.click()
        app.processEvents()
        _wait_worker(window)
        assert provider.run_calls == 1
        assert window.last_smart_scan_result.state == smart.STATE_COMPLETED_CLEAN

        window.scan_page.quick_scan.click()
        app.processEvents()
        _wait_worker(window)
        assert provider.run_calls == 2
        assert window.last_smart_scan_result.state == smart.STATE_COMPLETED_CLEAN
    finally:
        window.close()


def test_cancel_button_requests_safe_cancellation_without_remediation() -> None:
    app = _app()
    provider = UiFixtureProvider(block=True)
    window = b63_ui.B63SecurityOverviewWindow(status_provider=_evidence, smart_scan_provider=provider)
    try:
        window.smart_scan_button.click()
        deadline = time.monotonic() + 1.0
        while provider.run_calls == 0 and time.monotonic() < deadline:
            app.processEvents()
            time.sleep(0.01)
        assert provider.run_calls == 1
        window.scan_page.cancel_scan.click()
        _wait_worker(window)
        assert provider.cancel_seen is True
        result = window.last_smart_scan_result
        assert result is not None
        assert result.state == smart.STATE_CANCELLED
        assert result.automatic_quarantine is False
        assert result.automatic_repair is False
        assert result.automatic_destructive_action is False
    finally:
        window.close()


def test_b63_window_keeps_six_page_shell_and_no_horizontal_overflow() -> None:
    app = _app()
    window = b63_ui.B63SecurityOverviewWindow(status_provider=_evidence)
    try:
        for width, height in ((1600, 980), (1080, 820), (760, 760), (560, 620)):
            window.resize(width, height)
            window.show()
            app.processEvents()
            window._apply_responsive_layout(force=True)
            app.processEvents()
            window._sync_all_scroll_widths()
            app.processEvents()
            assert window.stack.count() == 6
            assert window.page_scroll.horizontalScrollBar().maximum() == 0
            for page in b63_ui.base_ui.PAGE_ORDER:
                window._navigate(page)
                app.processEvents()
                window._sync_all_scroll_widths()
                app.processEvents()
                current = window.stack.currentWidget()
                if hasattr(current, "horizontalScrollBar"):
                    assert current.horizontalScrollBar().maximum() == 0
    finally:
        window.close()


def test_full_scan_stays_disabled_after_completed_smart_scan() -> None:
    app = _app()
    provider = UiFixtureProvider()
    window = b63_ui.B63SecurityOverviewWindow(status_provider=_evidence, smart_scan_provider=provider)
    try:
        window.smart_scan_button.click()
        app.processEvents()
        _wait_worker(window)
        assert window.full_scan_button.isEnabled() is False
        assert window.scan_page.full_scan.isEnabled() is False
    finally:
        window.close()

from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QLabel

from sentinel import rescue_home_ui as ui
from sentinel import rescue_target_discovery as discovery
from sentinel.ui_design_system import COLORS


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


def _live_system_payload() -> dict:
    return {
        "schema": discovery.RESULT_SCHEMA,
        "profile": discovery.PROFILE,
        "session_id": "B61-LIVE-UI",
        "correlation_id": "B61-LIVE-UI-CORRELATION",
        "created_utc": "2026-09-12T00:00:00Z",
        "candidates": [
            {
                "root": "C:\\",
                "normalized_root": "C:\\",
                "discovery_source": "windows_volume",
                "state": discovery.STATE_UNSUPPORTED,
                "reason": "live_system_volume_refused",
                "markers_present": [],
                "markers_missing": list(discovery.WINDOWS_MARKERS),
                "target_fingerprint": "",
                "bitlocker": {"provider": "skipped", "available": False, "locked": None, "reason": "live_system_volume"},
                "write_attempted": False,
                "elapsed_ms": 1.0,
            }
        ],
        "safety": {
            "read_only_discovery": True,
            "write_attempted": False,
            "unlock_attempted": False,
            "mount_mutation": False,
            "format_disk": False,
            "partition_write": False,
            "bcd_write": False,
            "filesystem_repair": False,
            "target_execution": False,
            "service_install": False,
            "driver_install": False,
            "network_required": False,
            "cloud_required": False,
        },
    }


def test_live_windows_is_presented_as_current_system_not_unsupported() -> None:
    app = _app()
    window = ui.HomeWindow(discovery_provider=_live_system_payload)
    try:
        window.show()
        app.processEvents()
        window.discovery_button.click()
        app.processEvents()

        assert window.state_label.text() == "This PC detected"
        assert "currently running" in window.summary_label.text()
        assert len(window.target_widgets) == 1
        widget = next(iter(window.target_widgets.values()))
        title = widget.findChild(QLabel, "TargetTitle")
        status = widget.findChild(QLabel, "TargetStatus")
        assert title is not None and title.text() == "This PC"
        assert status is not None and status.text() == "Current system"
        assert widget.select_button.isEnabled() is False
        assert widget.select_button.text() == "Rescue unavailable"
        assert widget.details_button.isEnabled() is True
    finally:
        window.close()


def test_rescue_surface_uses_shared_stitch_dark_theme() -> None:
    _app()
    window = ui.HomeWindow(discovery_provider=_live_system_payload)
    try:
        assert window.scroll.objectName() == "TargetScroll"
        assert window.scroll.viewport().objectName() == "TargetViewport"
        assert window.target_root.objectName() == "TargetRoot"
        stylesheet = window.styleSheet()
        assert "#TargetViewport" in stylesheet
        assert "#TargetRoot" in stylesheet
        assert COLORS["canvas"] in stylesheet
        assert COLORS["accent"] in stylesheet
        assert "#0b0e12" not in stylesheet
    finally:
        window.close()


def test_rescue_startup_remains_passive_after_visual_migration() -> None:
    calls: list[str] = []

    def provider() -> dict:
        calls.append("discover")
        return _live_system_payload()

    _app()
    window = ui.HomeWindow(discovery_provider=provider)
    try:
        assert calls == []
        assert window.discovery_view is None
        assert window.ui_state.state == "IDLE"
    finally:
        window.close()

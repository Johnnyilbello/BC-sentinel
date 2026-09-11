from __future__ import annotations

import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QPushButton

from sentinel import rescue_target_discovery as b50
from sentinel import rescue_technician_target_selection as selection
from sentinel import rescue_technician_ui_b61 as ui


def _candidate(state: str, root: str, *, reason: str | None = None, fingerprint: str = "") -> dict:
    if reason is None:
        reason = {
            b50.STATE_READY: "validated_by_rr6_target_contract",
            b50.STATE_LOCKED: "bitlocker_volume_locked",
            b50.STATE_ACCESS_DENIED: "permission_denied",
            b50.STATE_INCOMPLETE: "windows_markers_incomplete",
            b50.STATE_UNSUPPORTED: "no_windows_markers",
            b50.STATE_ERROR: "OSError:fixture",
        }[state]
    return {
        "root": root,
        "normalized_root": root,
        "discovery_source": "fixture",
        "state": state,
        "reason": reason,
        "markers_present": [],
        "markers_missing": [],
        "target_fingerprint": fingerprint,
        "bitlocker": {"provider": "fixture", "available": state == b50.STATE_LOCKED, "locked": state == b50.STATE_LOCKED},
        "write_attempted": False,
        "elapsed_ms": 1.0,
    }


def _result(candidates: list[dict]) -> dict:
    counts = {state: sum(1 for item in candidates if item["state"] == state) for state in selection.TARGET_STATES}
    return {
        "schema": b50.RESULT_SCHEMA,
        "profile": b50.PROFILE,
        "session_id": "B50-FIXTURE0000001",
        "correlation_id": "0123456789abcdef01234567",
        "created_utc": "2026-09-11T00:00:00Z",
        "limits": {},
        "roots_considered": len(candidates),
        "counts": counts,
        "candidates": candidates,
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
        "elapsed_ms": 1.0,
    }


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


def test_profile_schema_and_target_states() -> None:
    assert selection.PROFILE == "v0.11.0-beta.6-b61"
    assert selection.SCHEMA == "bc-sentinel-beta6-target-selection-ui-v1"
    assert selection.TARGET_STATES == ("READY", "LOCKED", "ACCESS_DENIED", "INCOMPLETE", "UNSUPPORTED", "ERROR")


def test_ready_target_is_selectable_with_fingerprint() -> None:
    result = _result([_candidate(b50.STATE_READY, "X:/offline", fingerprint="a" * 64)])
    snap = selection.snapshot_from_result(result)
    assert snap.targets[0].selectable is True
    assert snap.targets[0].target_fingerprint == "a" * 64


def test_locked_target_is_visible_but_not_selectable() -> None:
    snap = selection.snapshot_from_result(_result([_candidate(b50.STATE_LOCKED, "L:/locked")]))
    assert snap.targets[0].selectable is False
    assert "Unlock is not offered" in snap.targets[0].guidance


def test_access_denied_target_is_not_selectable() -> None:
    snap = selection.snapshot_from_result(_result([_candidate(b50.STATE_ACCESS_DENIED, "P:/restricted")]))
    assert snap.targets[0].selectable is False


def test_incomplete_target_is_not_selectable() -> None:
    snap = selection.snapshot_from_result(_result([_candidate(b50.STATE_INCOMPLETE, "I:/partial")]))
    assert snap.targets[0].selectable is False


def test_live_system_refusal_must_be_unsupported() -> None:
    bad = _candidate(b50.STATE_READY, "C:/", reason="live_system_volume_refused", fingerprint="b" * 64)
    checked = selection.validate_discovery_result(_result([bad]))
    assert checked["passed"] is False
    assert any("live_system_not_unsupported" in reason for reason in checked["failures"])


def test_error_target_is_not_selectable() -> None:
    snap = selection.snapshot_from_result(_result([_candidate(b50.STATE_ERROR, "E:/broken")]))
    assert snap.targets[0].selectable is False


def test_wrong_discovery_schema_is_refused() -> None:
    result = _result([])
    result["schema"] = "wrong"
    with pytest.raises(ValueError, match="discovery_schema_mismatch"):
        selection.snapshot_from_result(result)


def test_wrong_discovery_profile_is_refused() -> None:
    result = _result([])
    result["profile"] = "wrong"
    with pytest.raises(ValueError, match="discovery_profile_mismatch"):
        selection.snapshot_from_result(result)


def test_safety_drift_is_refused() -> None:
    result = _result([])
    result["safety"]["unlock_attempted"] = True
    with pytest.raises(ValueError, match="safety_not_false:unlock_attempted"):
        selection.snapshot_from_result(result)


def test_ready_without_valid_fingerprint_is_refused() -> None:
    result = _result([_candidate(b50.STATE_READY, "X:/offline", fingerprint="bad")])
    with pytest.raises(ValueError, match="ready_fingerprint_invalid"):
        selection.snapshot_from_result(result)


def test_candidate_write_attempt_is_refused() -> None:
    item = _candidate(b50.STATE_READY, "X:/offline", fingerprint="c" * 64)
    item["write_attempted"] = True
    with pytest.raises(ValueError, match="write_attempted"):
        selection.snapshot_from_result(_result([item]))


def test_duplicate_normalized_root_is_refused() -> None:
    first = _candidate(b50.STATE_READY, "X:/offline", fingerprint="d" * 64)
    second = _candidate(b50.STATE_UNSUPPORTED, "x:/OFFLINE")
    with pytest.raises(ValueError, match="duplicate_root"):
        selection.snapshot_from_result(_result([first, second]))


def test_nonready_target_selection_is_refused() -> None:
    snap = selection.snapshot_from_result(_result([_candidate(b50.STATE_LOCKED, "L:/locked")]))
    with pytest.raises(ValueError, match="target_not_selectable:LOCKED"):
        selection.select_target(snap, 0)


def test_ready_target_selection_binds_state_and_ids() -> None:
    snap = selection.snapshot_from_result(_result([_candidate(b50.STATE_READY, "X:/offline", fingerprint="e" * 64)]))
    state = selection.select_target(snap, 0)
    assert state.state == "READY"
    assert state.selected_target == "X:/offline"
    assert state.target_fingerprint == "e" * 64
    assert state.session_id == snap.session_id
    assert state.correlation_id == snap.correlation_id
    assert state.last_command == "discover"


def test_safety_contract_exposes_no_unlock_or_mount_write() -> None:
    contract = selection.safety_contract()
    assert contract["unlock_offered"] is False
    assert contract["mount_write_offered"] is False
    assert contract["automatic_target_selection"] is False
    assert contract["automatic_destructive_action"] is False


def test_window_construction_does_not_start_discovery(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def forbidden(*args, **kwargs):
        calls.append("discover")
        raise AssertionError("discovery started at window construction")

    monkeypatch.setattr(selection, "run_discovery", forbidden)
    _app()
    window = ui.TechnicianTargetSelectionWindow()
    try:
        assert calls == []
        assert window.target_panel.discover_button.isEnabled() is True
        assert window.target_panel.use_button.isEnabled() is False
    finally:
        window.close()


def test_window_contains_no_unlock_or_mount_write_action() -> None:
    _app()
    window = ui.TechnicianTargetSelectionWindow()
    try:
        texts = {button.text().casefold() for button in window.findChildren(QPushButton)}
        assert "unlock" not in texts
        assert "mount write" not in texts
        properties = {str(button.property("engineCommand")) for button in window.findChildren(QPushButton) if button.property("engineCommand")}
        assert "unlock" not in properties
        assert "mount-write" not in properties
    finally:
        window.close()


def test_loading_snapshot_populates_all_states_and_ready_gate() -> None:
    candidates = [
        _candidate(b50.STATE_READY, "R:/ready", fingerprint="f" * 64),
        _candidate(b50.STATE_LOCKED, "L:/locked"),
        _candidate(b50.STATE_INCOMPLETE, "I:/partial"),
        _candidate(b50.STATE_UNSUPPORTED, "U:/data"),
    ]
    _app()
    window = ui.TechnicianTargetSelectionWindow()
    try:
        snap = window.load_discovery_result(_result(candidates))
        assert window.target_panel.table.rowCount() == 4
        assert window.ui_state.state == "REVIEW"
        assert snap.counts[b50.STATE_READY] == 1
        window.target_panel.table.selectRow(1)
        QApplication.processEvents()
        assert window.target_panel.use_button.isEnabled() is False
        window.target_panel.table.selectRow(0)
        QApplication.processEvents()
        assert window.target_panel.use_button.isEnabled() is True
    finally:
        window.close()


def test_explicit_ui_selection_updates_ready_state() -> None:
    result = _result([_candidate(b50.STATE_READY, "R:/ready", fingerprint="1" * 64)])
    _app()
    window = ui.TechnicianTargetSelectionWindow()
    try:
        window.load_discovery_result(result)
        window.target_panel.table.selectRow(0)
        QApplication.processEvents()
        window._use_selected_target()
        assert window.ui_state.state == "READY"
        assert window.ui_state.selected_target == "R:/ready"
        assert window.status_pill.text() == "READY"
    finally:
        window.close()

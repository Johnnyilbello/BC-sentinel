from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QPlainTextEdit

from sentinel import rescue_home_ui as ui
from sentinel import rescue_home_ui_model as model
from sentinel import rescue_target_discovery as discovery


def _safe_flags() -> dict:
    return {
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
    }


def _candidate(
    *,
    root: str,
    state: str = discovery.STATE_READY,
    fingerprint: str = "FP-001",
    reason: str = "validated_by_rr6_target_contract",
    locked: bool | None = False,
) -> dict:
    markers = list(discovery.WINDOWS_MARKERS) if state == discovery.STATE_READY else []
    return {
        "root": root,
        "normalized_root": root,
        "discovery_source": "fixture",
        "state": state,
        "reason": reason,
        "markers_present": markers,
        "markers_missing": [] if state == discovery.STATE_READY else list(discovery.WINDOWS_MARKERS),
        "target_fingerprint": fingerprint,
        "bitlocker": {
            "provider": "fixture",
            "available": locked is not None,
            "locked": locked,
        },
        "write_attempted": False,
        "elapsed_ms": 1.0,
    }


def _payload(candidates: list[dict]) -> dict:
    return {
        "schema": discovery.RESULT_SCHEMA,
        "profile": discovery.PROFILE,
        "session_id": "B61-FIXTURE",
        "correlation_id": "B61-CORRELATION",
        "created_utc": "2026-09-12T00:00:00Z",
        "candidates": candidates,
        "safety": _safe_flags(),
    }


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


def test_profile_and_parent_contract_are_b61_and_passive() -> None:
    assert model.PROFILE == "v0.11.0-beta.6-b61"
    assert model.SCHEMA == "bc-sentinel-beta6-home-target-model-v1"
    contract = model.validate_engine_contract()
    assert contract["passed"] is True
    assert contract["startup_dispatch"] is False
    assert contract["automatic_discovery"] is False
    assert contract["automatic_selection"] is False
    assert contract["automatic_rescue_dispatch"] is False


def test_discovery_safety_refuses_any_write_signal() -> None:
    payload = _payload([_candidate(root="D:\\")])
    payload["safety"]["write_attempted"] = True
    with pytest.raises(model.DiscoverySafetyError, match="unsafe_discovery_flag:write_attempted"):
        model.build_discovery_view(payload)


def test_one_valid_target_is_recommended_but_not_auto_selected() -> None:
    view = model.build_discovery_view(_payload([_candidate(root="D:\\")]))
    assert len(view.targets) == 1
    target = view.targets[0]
    assert target.status == model.STATUS_RECOMMENDED
    assert target.selectable is True
    assert view.recommended_target_id == target.target_id
    assert view.explicit_selection_required is False
    state = model.initial_state()
    assert state.state == "IDLE"
    assert state.selected_target_id == ""


def test_two_distinct_valid_targets_require_explicit_choice() -> None:
    view = model.build_discovery_view(_payload([
        _candidate(root="D:\\", fingerprint="FP-D"),
        _candidate(root="E:\\", fingerprint="FP-E"),
    ]))
    assert [target.status for target in view.targets] == [model.STATUS_AVAILABLE, model.STATUS_AVAILABLE]
    assert all(target.selectable for target in view.targets)
    assert view.recommended_target_id == ""
    assert view.explicit_selection_required is True


def test_locked_target_needs_attention_and_is_not_selectable() -> None:
    locked = _candidate(
        root="E:\\",
        state=discovery.STATE_LOCKED,
        fingerprint="",
        reason="bitlocker_volume_locked",
        locked=True,
    )
    view = model.build_discovery_view(_payload([locked]))
    target = view.targets[0]
    assert target.status == model.STATUS_NEEDS_ATTENTION
    assert target.selectable is False
    assert target.advanced_details["encryption_bitlocker_state"]["locked"] is True
    assert target.advanced_details["unlock_state"] == "LOCKED"


def test_non_windows_target_is_unsupported() -> None:
    record = _candidate(
        root="F:\\",
        state=discovery.STATE_UNSUPPORTED,
        fingerprint="",
        reason="no_windows_markers",
        locked=None,
    )
    view = model.build_discovery_view(_payload([record]))
    assert view.targets[0].status == model.STATUS_UNSUPPORTED
    assert view.targets[0].selectable is False


def test_duplicate_fingerprint_is_ambiguous_and_blocked() -> None:
    view = model.build_discovery_view(_payload([
        _candidate(root="D:\\WindowsOffline", fingerprint="SAME-FP"),
        _candidate(root="E:\\WindowsOffline", fingerprint="SAME-FP"),
    ]))
    assert len(view.targets) == 2
    assert all(target.status == model.STATUS_AMBIGUOUS for target in view.targets)
    assert all(target.selectable is False for target in view.targets)
    assert all(target.advanced_details["ambiguity_reason"] == "duplicate_target_fingerprint" for target in view.targets)
    assert len({target.target_id for target in view.targets}) == 2


def test_advanced_details_preserve_complete_raw_discovery_record() -> None:
    record = _candidate(root="D:\\", fingerprint="RAW-FP")
    record["custom_future_evidence"] = {"source": "future-engine", "value": 42}
    target = model.build_discovery_view(_payload([record])).targets[0]
    assert target.advanced_details["raw_record"] == record
    assert target.advanced_details["fingerprint_target_identity"] == "RAW-FP"
    assert target.advanced_details["read_only_state"] is True


def test_explicit_selection_does_not_mark_revalidated_or_start_other_work() -> None:
    view = model.build_discovery_view(_payload([_candidate(root="D:\\", fingerprint="SELECT-FP")]))
    state = model.select_target(model.initial_state(), view, view.targets[0].target_id)
    assert state.state == "TARGET_SELECTED"
    assert state.selected_target_fingerprint == "SELECT-FP"
    assert state.selection_revalidated is False
    assert state.last_reason == "explicit_user_selection"


def test_revalidation_accepts_same_target_identity() -> None:
    original = _payload([_candidate(root="D:\\", fingerprint="STABLE-FP")])
    view = model.build_discovery_view(original)
    state = model.select_target(model.initial_state(), view, view.targets[0].target_id)
    refreshed = _payload([_candidate(root="D:\\", fingerprint="STABLE-FP")])
    state = model.revalidate_selection(state, refreshed)
    assert state.selection_revalidated is True
    assert state.last_reason == "target_identity_revalidated"


def test_revalidation_refuses_changed_identity() -> None:
    view = model.build_discovery_view(_payload([_candidate(root="D:\\", fingerprint="OLD-FP")]))
    state = model.select_target(model.initial_state(), view, view.targets[0].target_id)
    refreshed = _payload([_candidate(root="D:\\", fingerprint="NEW-FP")])
    with pytest.raises(model.TargetSelectionError, match="selected_target_identity_changed"):
        model.revalidate_selection(state, refreshed)


def test_revalidation_refuses_disappeared_target() -> None:
    view = model.build_discovery_view(_payload([_candidate(root="D:\\", fingerprint="OLD-FP")]))
    state = model.select_target(model.initial_state(), view, view.targets[0].target_id)
    with pytest.raises(model.TargetSelectionError, match="selected_target_missing_or_ambiguous"):
        model.revalidate_selection(state, _payload([]))


def test_home_window_startup_is_passive_and_does_not_call_discovery_provider() -> None:
    calls: list[str] = []

    def provider() -> dict:
        calls.append("called")
        raise AssertionError("discovery provider invoked during startup")

    _app()
    window = ui.HomeWindow(discovery_provider=provider)
    try:
        assert window.windowTitle() == ui.WINDOW_TITLE
        assert window.ui_state.state == "IDLE"
        assert calls == []
        assert window.next_button.isEnabled() is False
    finally:
        window.close()


def test_operator_discovery_renders_target_and_advanced_details() -> None:
    calls: list[str] = []

    def provider() -> dict:
        calls.append("discover")
        return _payload([_candidate(root="D:\\", fingerprint="UI-FP")])

    app = _app()
    window = ui.HomeWindow(discovery_provider=provider)
    try:
        window.show()
        app.processEvents()
        window.discovery_button.click()
        app.processEvents()
        assert calls == ["discover"]
        assert window.ui_state.state == "TARGETS_FOUND"
        assert len(window.target_widgets) == 1
        widget = next(iter(window.target_widgets.values()))
        assert widget.card.status == model.STATUS_RECOMMENDED
        assert widget.select_button.isEnabled() is True
        assert widget.details_panel.isHidden() is True
        widget.details_button.click()
        app.processEvents()
        assert widget.details_panel.isHidden() is False
        details = widget.findChild(QPlainTextEdit)
        assert details is not None
        assert "UI-FP" in details.toPlainText()
    finally:
        window.close()


def test_selecting_ui_target_never_enables_continue_or_dispatches_next_step() -> None:
    def provider() -> dict:
        return _payload([_candidate(root="D:\\", fingerprint="UI-SELECT-FP")])

    app = _app()
    window = ui.HomeWindow(discovery_provider=provider)
    try:
        window.show()
        app.processEvents()
        window.discovery_button.click()
        app.processEvents()
        widget = next(iter(window.target_widgets.values()))
        widget.select_button.click()
        app.processEvents()
        assert window.ui_state.state == "TARGET_SELECTED"
        assert window.ui_state.selected_target_fingerprint == "UI-SELECT-FP"
        assert window.next_button.isEnabled() is False
        assert window.next_button.text() == "Next step not enabled in B6-1"
    finally:
        window.close()


def test_self_check_is_passive() -> None:
    result = ui.self_check()
    assert result["passed"] is True
    assert result["startup_dispatch"] is False
    assert result["automatic_discovery"] is False
    assert result["window_created"] is False

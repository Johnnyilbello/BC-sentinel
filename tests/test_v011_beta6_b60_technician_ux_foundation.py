from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QPushButton

from sentinel import rescue_technician_portable as b57
from sentinel import rescue_technician_ui as ui
from sentinel import rescue_technician_ui_model as model


def test_profile_and_schema() -> None:
    assert model.PROFILE == "v0.11.0-beta.6-b60"
    assert model.SCHEMA == "bc-sentinel-beta6-technician-ui-model-v1"


def test_exact_engine_command_inventory() -> None:
    assert tuple(b57.status_payload()["commands"]) == model.EXPECTED_ENGINE_COMMANDS


def test_forbidden_commands_absent() -> None:
    assert not set(model.FORBIDDEN_UI_COMMANDS).intersection(model.EXPECTED_ENGINE_COMMANDS)


def test_contract_passes_against_frozen_b57() -> None:
    result = model.validate_engine_contract()
    assert result["passed"] is True
    assert result["failures"] == []
    assert result["engine_profile"] == b57.PROFILE


def test_contract_has_no_automatic_dispatch_or_destructive_authority() -> None:
    result = model.validate_engine_contract()
    assert result["startup_dispatch"] is False
    assert all(value is False for value in result["safety"].values())


def test_capability_inventory_is_exact_and_operator_gated() -> None:
    assert tuple(model.CAPABILITIES.keys()) == model.EXPECTED_ENGINE_COMMANDS
    assert all(row["operator_action_required"] is True for row in model.CAPABILITIES.values())
    assert model.CAPABILITIES["data-rescue"]["read_only"] is False


def test_initial_state_is_idle_and_empty() -> None:
    state = model.initial_state()
    assert state.state == "IDLE"
    assert state.busy is False
    assert state.selected_target == ""
    assert state.target_fingerprint == ""
    assert state.workspace == ""
    assert state.evidence_path == ""
    assert state.session_id == ""
    assert state.correlation_id == ""
    assert state.last_command == ""


def test_invalid_state_refused() -> None:
    state = model.initial_state()
    state.state = "RECOVERED"
    with pytest.raises(ValueError, match="unknown_ui_state"):
        state.validate()


def test_busy_requires_running_state() -> None:
    state = model.initial_state()
    state.busy = True
    with pytest.raises(ValueError, match="busy_requires_running_state"):
        state.validate()


def test_unknown_last_command_refused() -> None:
    state = model.initial_state()
    state.last_command = "repair-execute"
    with pytest.raises(ValueError, match="unknown_last_command"):
        state.validate()


def test_transition_to_running_sets_busy() -> None:
    state = model.transition(model.initial_state(), "RUNNING", reason="operator_started")
    assert state.state == "RUNNING"
    assert state.busy is True
    assert state.last_reason == "operator_started"


def test_transition_to_refused_clears_busy() -> None:
    state = model.transition(model.initial_state(), "RUNNING")
    state = model.transition(state, "REFUSED", reason="engine_refused")
    assert state.state == "REFUSED"
    assert state.busy is False
    assert state.last_reason == "engine_refused"


def test_self_check_is_passive() -> None:
    result = ui.self_check()
    assert result["passed"] is True
    assert result["startup_dispatch"] is False
    assert result["window_created"] is False
    assert result["initial_state"]["state"] == "IDLE"


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


def test_window_constructs_offscreen() -> None:
    _app()
    window = ui.TechnicianWindow()
    try:
        assert window.windowTitle() == "BC Sentinel — Rescue Technician"
        assert window.ui_state.state == "IDLE"
        assert window.minimumWidth() >= 900
        assert window.minimumHeight() >= 640
    finally:
        window.close()


def test_workflow_actions_are_disabled_at_foundation_startup() -> None:
    _app()
    window = ui.TechnicianWindow()
    try:
        command_buttons = [
            button for button in window.findChildren(QPushButton)
            if button.property("engineCommand")
        ]
        assert len(command_buttons) == 5
        assert all(button.isEnabled() is False for button in command_buttons)
        assert {str(button.property("engineCommand")) for button in command_buttons} == {
            "discover", "assess", "scan", "decide", "report"
        }
    finally:
        window.close()


def test_window_startup_does_not_dispatch_engine_commands(monkeypatch: pytest.MonkeyPatch) -> None:
    invoked: list[str] = []

    def forbidden(*args, **kwargs):
        invoked.append("called")
        raise AssertionError("engine command dispatched during UI startup")

    for command in list(b57.COMMANDS):
        monkeypatch.setitem(b57.COMMANDS, command, forbidden)
    _app()
    window = ui.TechnicianWindow()
    window.close()
    assert invoked == []

from __future__ import annotations

import json
from typing import Callable

import pytest

from sentinel import rescue_technician_portable as b57

EXPECTED_COMMANDS = [
    "plan",
    "scan",
    "repair-handoff",
    "data-rescue",
    "certify",
    "discover",
    "assess",
    "stress",
    "resume",
    "decide",
    "report",
]


def test_profile_and_schema() -> None:
    payload = b57.status_payload()
    assert payload["profile"] == "v0.11.0-beta.5-b57"
    assert payload["schema"] == "bc-sentinel-beta5-portable-technician-release-v1"


def test_command_surface_exact() -> None:
    assert list(b57.COMMANDS) == EXPECTED_COMMANDS
    assert b57.status_payload()["commands"] == EXPECTED_COMMANDS


def test_portable_without_install_service_driver() -> None:
    payload = b57.status_payload()
    assert payload["portable"] is True
    assert payload["installer_required"] is False
    assert payload["service_install"] is False
    assert payload["driver_install"] is False
    assert payload["network_required"] is False
    assert payload["cloud_required"] is False


def test_safety_contract_has_no_new_destructive_authority() -> None:
    safety = b57.status_payload()["safety"]
    assert safety["automatic_repair"] is False
    assert safety["automatic_quarantine"] is False
    assert safety["automatic_destructive_action"] is False
    assert safety["repair_execution_exposed_by_launcher"] is False
    assert safety["repair_handoff_only"] is True
    assert safety["unlock_exposed"] is False
    assert safety["format_exposed"] is False
    assert safety["reimage_execution_exposed"] is False
    assert safety["target_execution"] is False
    assert safety["format_or_reimage_suppressed"] is False


def test_rr6_outcomes_preserved_exactly() -> None:
    assert b57.status_payload()["safety"]["rr6_outcomes_preserved"] == [
        "RECOVERED", "NOT_RECOVERED", "INDETERMINATE_REFUSED"
    ]


def test_component_profiles_are_frozen_profiles() -> None:
    profiles = b57.status_payload()["component_profiles"]
    assert profiles == {
        "portable_base": "v0.11.0-beta.4-b45",
        "plan": "v0.11.0-beta.4-b40",
        "scan": "v0.11.0-beta.4-b41",
        "repair_handoff": "v0.11.0-beta.4-b42",
        "data_rescue": "v0.11.0-beta.4-b43",
        "certification": "v0.11.0-beta.4-b44",
        "discovery": "v0.11.0-beta.5-b50",
        "assessment": "v0.11.0-beta.5-b51",
        "stress": "v0.11.0-beta.5-b52",
        "resume": "v0.11.0-beta.5-b53",
        "decision": "v0.11.0-beta.5-b54",
        "report": "v0.11.0-beta.5-b55",
    }


def test_forbidden_commands_not_exposed() -> None:
    forbidden = {"repair-execute", "unlock", "format", "reimage", "delete", "quarantine-execute"}
    assert forbidden.isdisjoint(b57.COMMANDS)


def test_all_handlers_callable() -> None:
    assert all(isinstance(name, str) and callable(handler) for name, handler in b57.COMMANDS.items())


def test_command_required_refusal(capsys: pytest.CaptureFixture[str]) -> None:
    assert b57.main([]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["reason"] == "command_required"


def test_repair_execute_refused(capsys: pytest.CaptureFixture[str]) -> None:
    assert b57.main(["repair-execute"]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["reason"] == "unknown_command:repair-execute"


def test_unlock_refused(capsys: pytest.CaptureFixture[str]) -> None:
    assert b57.main(["unlock"]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["reason"] == "unknown_command:unlock"


def test_status_roundtrip(capsys: pytest.CaptureFixture[str]) -> None:
    assert b57.main(["status"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["passed"] is True
    assert payload["profile"] == b57.PROFILE
    assert payload["commands"] == EXPECTED_COMMANDS


def test_status_rejects_extra_arguments(capsys: pytest.CaptureFixture[str]) -> None:
    assert b57.main(["status", "extra"]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["reason"] == "status_takes_no_arguments"


@pytest.mark.parametrize("command", ["plan", "discover", "assess", "stress", "resume", "decide", "report"])
def test_representative_command_help_loads(command: str) -> None:
    with pytest.raises(SystemExit) as exc:
        b57.main([command, "--help"])
    assert exc.value.code == 0

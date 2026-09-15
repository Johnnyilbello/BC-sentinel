from __future__ import annotations

from collections import deque
from dataclasses import asdict, dataclass
from typing import Final

from sentinel import rescue_technician_portable as b57

PROFILE: Final[str] = "v0.11.0-beta.6-b60"
SCHEMA: Final[str] = "bc-sentinel-beta6-technician-ui-model-v1"
ACCESSIBILITY_PROFILE: Final[str] = "v0.11.0-beta.6-b66"
MAX_ACTIVITY_ENTRIES: Final[int] = 160
MAX_ACTIVITY_MESSAGE_CHARS: Final[int] = 480

UI_STATES: Final[tuple[str, ...]] = (
    "IDLE",
    "READY",
    "RUNNING",
    "REVIEW",
    "REFUSED",
    "ERROR",
)

EXPECTED_ENGINE_COMMANDS: Final[tuple[str, ...]] = (
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
)

FORBIDDEN_UI_COMMANDS: Final[tuple[str, ...]] = (
    "repair-execute",
    "quarantine-execute",
    "unlock",
    "mount-write",
    "format",
    "reimage",
    "registry-write",
    "boot-write",
)

CAPABILITIES: Final[dict[str, dict[str, object]]] = {
    "plan": {"kind": "planning", "read_only": True, "operator_action_required": True},
    "scan": {"kind": "evidence", "read_only": True, "operator_action_required": True},
    "repair-handoff": {"kind": "handoff", "read_only": True, "operator_action_required": True},
    "data-rescue": {"kind": "explicit_copy", "read_only": False, "operator_action_required": True},
    "certify": {"kind": "certification", "read_only": True, "operator_action_required": True},
    "discover": {"kind": "discovery", "read_only": True, "operator_action_required": True},
    "assess": {"kind": "assessment", "read_only": True, "operator_action_required": True},
    "stress": {"kind": "assessment", "read_only": True, "operator_action_required": True},
    "resume": {"kind": "session", "read_only": True, "operator_action_required": True},
    "decide": {"kind": "advisory", "read_only": True, "operator_action_required": True},
    "report": {"kind": "evidence_export", "read_only": True, "operator_action_required": True},
}


@dataclass
class TechnicianUiState:
    state: str = "IDLE"
    selected_target: str = ""
    target_fingerprint: str = ""
    workspace: str = ""
    evidence_path: str = ""
    session_id: str = ""
    correlation_id: str = ""
    last_command: str = ""
    last_engine_state: str = ""
    last_reason: str = ""
    busy: bool = False

    def validate(self) -> None:
        if self.state not in UI_STATES:
            raise ValueError(f"unknown_ui_state:{self.state}")
        if self.busy and self.state != "RUNNING":
            raise ValueError("busy_requires_running_state")
        if self.last_command and self.last_command not in EXPECTED_ENGINE_COMMANDS:
            raise ValueError(f"unknown_last_command:{self.last_command}")

    def to_dict(self) -> dict:
        self.validate()
        return asdict(self)


def validate_engine_contract() -> dict:
    status = b57.status_payload()
    commands = tuple(status.get("commands", ()))
    safety = dict(status.get("safety", {}))
    failures: list[str] = []

    if str(status.get("profile")) != b57.PROFILE:
        failures.append("engine_profile_mismatch")
    if commands != EXPECTED_ENGINE_COMMANDS:
        failures.append(f"engine_command_inventory_mismatch:{commands!r}")
    if tuple(CAPABILITIES.keys()) != EXPECTED_ENGINE_COMMANDS:
        failures.append("ui_capability_inventory_mismatch")
    if any(command in commands for command in FORBIDDEN_UI_COMMANDS):
        failures.append("forbidden_command_exposed_by_engine")
    if safety.get("automatic_repair") is not False:
        failures.append("automatic_repair_not_false")
    if safety.get("automatic_quarantine") is not False:
        failures.append("automatic_quarantine_not_false")
    if safety.get("automatic_destructive_action") is not False:
        failures.append("automatic_destructive_action_not_false")
    if safety.get("repair_execution_exposed_by_launcher") is not False:
        failures.append("repair_execution_exposed")
    if safety.get("unlock_exposed") is not False:
        failures.append("unlock_exposed")
    if safety.get("format_exposed") is not False:
        failures.append("format_exposed")
    if safety.get("reimage_execution_exposed") is not False:
        failures.append("reimage_execution_exposed")
    if safety.get("target_execution") is not False:
        failures.append("target_execution_exposed")
    if tuple(safety.get("rr6_outcomes_preserved", ())) != (
        "RECOVERED", "NOT_RECOVERED", "INDETERMINATE_REFUSED"
    ):
        failures.append("rr6_outcomes_not_preserved")

    return {
        "schema": SCHEMA,
        "profile": PROFILE,
        "engine_profile": b57.PROFILE,
        "passed": not failures,
        "failures": failures,
        "commands": list(commands),
        "forbidden_commands": list(FORBIDDEN_UI_COMMANDS),
        "capabilities": CAPABILITIES,
        "startup_dispatch": False,
        "safety": {
            "automatic_command_dispatch": False,
            "automatic_repair": False,
            "automatic_quarantine": False,
            "automatic_destructive_action": False,
            "repair_execute_exposed": False,
            "unlock_exposed": False,
            "format_exposed": False,
            "reimage_execution_exposed": False,
            "target_execution": False,
            "installer_required": False,
            "service_install": False,
            "driver_install": False,
            "network_required": False,
            "cloud_required": False,
        },
    }


def initial_state() -> TechnicianUiState:
    state = TechnicianUiState()
    state.validate()
    return state


def transition(current: TechnicianUiState, new_state: str, *, reason: str = "") -> TechnicianUiState:
    if new_state not in UI_STATES:
        raise ValueError(f"unknown_ui_state:{new_state}")
    current.state = new_state
    current.busy = new_state == "RUNNING"
    current.last_reason = reason
    current.validate()
    return current


class BoundedActivityLog:
    """In-memory diagnostic tail for the Technician UI.

    The log is deliberately presentation-only. It is bounded so a damaged host
    cannot make the UI consume unbounded memory while reporting a long-running
    read-only operation.
    """

    def __init__(self, limit: int = MAX_ACTIVITY_ENTRIES) -> None:
        if limit < 1:
            raise ValueError("activity_log_limit_must_be_positive")
        self.limit = int(limit)
        self._entries: deque[str] = deque(maxlen=self.limit)

    def append(self, stage: str, message: str) -> str:
        safe_stage = str(stage or "UI").strip()[:48] or "UI"
        safe_message = " ".join(str(message or "").split())
        if len(safe_message) > MAX_ACTIVITY_MESSAGE_CHARS:
            safe_message = safe_message[: MAX_ACTIVITY_MESSAGE_CHARS - 1] + "…"
        entry = f"{safe_stage}: {safe_message or 'Nessun dettaglio disponibile.'}"
        self._entries.append(entry)
        return entry

    def entries(self) -> tuple[str, ...]:
        return tuple(self._entries)


def validate_b66_accessibility_contract() -> dict:
    """Static guardrail for B6-6; does not enable any engine command."""
    engine = validate_engine_contract()
    failures = list(engine["failures"])
    if any(command in FORBIDDEN_UI_COMMANDS for command in EXPECTED_ENGINE_COMMANDS):
        failures.append("forbidden_command_exposed")
    return {
        "profile": ACCESSIBILITY_PROFILE,
        "schema": SCHEMA,
        "passed": not failures,
        "failures": failures,
        "background_work_is_read_only_fixture_only": True,
        "activity_log_bounded": True,
        "keyboard_contract_visible": True,
        "automatic_command_dispatch": False,
        "automatic_repair": False,
        "automatic_quarantine": False,
        "automatic_restore": False,
        "repair_execute_exposed": False,
        "target_execution": False,
    }

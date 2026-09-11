from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QPushButton

from sentinel import rescue_technician_portable as b57
from sentinel import rescue_technician_ui as ui
from sentinel import rescue_technician_ui_model as model

CHECKPOINT = "B6-0-technician-ux-foundation"


def run_acceptance(output: Path) -> dict:
    contract = model.validate_engine_contract()
    initial = model.initial_state().to_dict()
    app = QApplication.instance() or QApplication([])
    window = ui.TechnicianWindow()
    try:
        command_buttons = [
            button for button in window.findChildren(QPushButton)
            if button.property("engineCommand")
        ]
        exposed = sorted(str(button.property("engineCommand")) for button in command_buttons)
        enabled = [str(button.property("engineCommand")) for button in command_buttons if button.isEnabled()]
        actual_window_title = window.windowTitle()
        expected_window_title = ui.WINDOW_TITLE
        checks = {
            "profile": model.PROFILE == "v0.11.0-beta.6-b60",
            "frozen_engine_profile": contract.get("engine_profile") == b57.PROFILE,
            "engine_contract_passed": contract.get("passed") is True,
            "command_surface_exact": tuple(contract.get("commands", ())) == model.EXPECTED_ENGINE_COMMANDS,
            "forbidden_commands_absent": not set(model.FORBIDDEN_UI_COMMANDS).intersection(contract.get("commands", ())),
            "startup_dispatch_disabled": contract.get("startup_dispatch") is False,
            "initial_state_idle": initial.get("state") == "IDLE",
            "initial_target_empty": initial.get("selected_target") == "" and initial.get("target_fingerprint") == "",
            "initial_session_empty": initial.get("session_id") == "" and initial.get("correlation_id") == "",
            "window_created": actual_window_title == expected_window_title,
            "workflow_actions_disabled": enabled == [],
            "foundation_workflow_surface": exposed == sorted(["discover", "assess", "scan", "decide", "report"]),
            "no_installer_service_driver": all(contract["safety"][key] is False for key in ("installer_required", "service_install", "driver_install")),
            "no_network_cloud": contract["safety"]["network_required"] is False and contract["safety"]["cloud_required"] is False,
            "no_destructive_authority": all(contract["safety"][key] is False for key in (
                "automatic_command_dispatch", "automatic_repair", "automatic_quarantine", "automatic_destructive_action",
                "repair_execute_exposed", "unlock_exposed", "format_exposed", "reimage_execution_exposed", "target_execution",
            )),
            "rr6_outcomes_preserved": tuple(b57.status_payload()["safety"]["rr6_outcomes_preserved"]) == (
                "RECOVERED", "NOT_RECOVERED", "INDETERMINATE_REFUSED"
            ),
        }
    finally:
        window.close()
        app.processEvents()

    payload = {
        "profile": model.PROFILE,
        "checkpoint": CHECKPOINT,
        "passed": all(checks.values()),
        "checks": checks,
        "detail": {
            "engine_profile": b57.PROFILE,
            "ui_states": list(model.UI_STATES),
            "engine_commands": list(model.EXPECTED_ENGINE_COMMANDS),
            "forbidden_commands": list(model.FORBIDDEN_UI_COMMANDS),
            "foundation_workflow_commands": exposed,
            "initial_state": initial,
            "window_title_expected": expected_window_title,
            "window_title_actual": actual_window_title,
            "window_title_expected_length": len(expected_window_title),
            "window_title_actual_length": len(actual_window_title),
        },
        "new_mutation_authority_added": False,
        "automatic_destructive_action_enabled": False,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="acceptance-v011-beta6-b60.json")
    args = parser.parse_args()
    payload = run_acceptance(Path(args.output))
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if payload["passed"] else 4


if __name__ == "__main__":
    raise SystemExit(main())

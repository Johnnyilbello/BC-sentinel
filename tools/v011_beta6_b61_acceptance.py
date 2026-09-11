from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QPushButton

from sentinel import rescue_target_discovery as b50
from sentinel import rescue_technician_target_selection as selection
from sentinel import rescue_technician_ui_b61 as ui

CHECKPOINT = "B6-1-target-discovery-selection-ux"


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _ready_target(root: Path) -> None:
    _write(root / "Windows/System32/ntoskrnl.exe", b"b61-kernel\n")
    _write(root / "Windows/System32/config/SYSTEM", b"b61-system\n")
    _write(root / "Windows/System32/config/SOFTWARE", b"b61-software\n")


def _incomplete_target(root: Path) -> None:
    _write(root / "Windows/System32/config/SYSTEM", b"b61-partial\n")


def _tree_hash(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted((p for p in root.rglob("*") if p.is_file()), key=lambda p: str(p.relative_to(root)).casefold()):
        rel = str(path.relative_to(root)).replace("\\", "/")
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def run_acceptance(output: Path) -> dict:
    app = QApplication.instance() or QApplication([])
    with tempfile.TemporaryDirectory(prefix="bcs-b61-") as temp:
        base = Path(temp)
        ready = base / "ready-offline"
        locked = base / "locked-volume"
        incomplete = base / "incomplete-windows"
        unsupported = base / "data-only"
        _ready_target(ready)
        locked.mkdir(parents=True, exist_ok=True)
        _incomplete_target(incomplete)
        unsupported.mkdir(parents=True, exist_ok=True)

        before = {str(root): _tree_hash(root) for root in (ready, locked, incomplete, unsupported)}

        def bitlocker_probe(path: Path) -> dict:
            is_locked = Path(path).name == locked.name
            return {
                "provider": "b61_controlled_fixture",
                "available": is_locked,
                "locked": is_locked,
                "reason": "controlled_fixture",
            }

        result = b50.discover_targets(
            [ready, locked, incomplete, unsupported],
            include_windows_volumes=False,
            limits=b50.DiscoveryLimits(probe_children=False, max_roots=8),
            bitlocker_probe=bitlocker_probe,
        )
        snapshot = selection.snapshot_from_result(result)

        window = ui.TechnicianTargetSelectionWindow()
        try:
            startup_rows = window.target_panel.table.rowCount()
            startup_state = window.ui_state.state
            window.load_discovery_result(result)

            state_to_row = {target.state: index for index, target in enumerate(snapshot.targets)}
            locked_row = state_to_row[b50.STATE_LOCKED]
            ready_row = state_to_row[b50.STATE_READY]
            window.target_panel.table.selectRow(locked_row)
            app.processEvents()
            locked_use_enabled = window.target_panel.use_button.isEnabled()

            window.target_panel.table.selectRow(ready_row)
            app.processEvents()
            ready_use_enabled = window.target_panel.use_button.isEnabled()
            window._use_selected_target()
            selected_state = window.ui_state.to_dict()

            button_commands = {
                str(button.property("engineCommand"))
                for button in window.findChildren(QPushButton)
                if button.property("engineCommand")
            }
        finally:
            window.close()
            app.processEvents()

        after = {str(root): _tree_hash(root) for root in (ready, locked, incomplete, unsupported)}
        ready_choice = next(item for item in snapshot.targets if item.state == b50.STATE_READY)

        live_state = "NOT_WINDOWS"
        live_reason = "not_windows"
        system_drive = os.environ.get("SystemDrive", "").strip()
        if os.name == "nt" and system_drive:
            live = b50.classify_candidate(
                Path(system_drive.rstrip("\\/") + "\\"),
                discovery_source="b61_live_system_control",
                bitlocker_probe=lambda _: {"provider": "skipped", "available": False, "locked": False},
            )
            live_state = live.state
            live_reason = live.reason

        observed_states = {item.state for item in snapshot.targets}
        checks = {
            "profile": selection.PROFILE == "v0.11.0-beta.6-b61",
            "b50_profile_bound": snapshot.engine_profile == b50.PROFILE,
            "four_controlled_states_present": observed_states == {
                b50.STATE_READY, b50.STATE_LOCKED, b50.STATE_INCOMPLETE, b50.STATE_UNSUPPORTED
            },
            "ready_has_rr6_fingerprint": len(ready_choice.target_fingerprint) == 64,
            "only_ready_selectable": all(item.selectable == (item.state == b50.STATE_READY) for item in snapshot.targets),
            "locked_selection_disabled": locked_use_enabled is False,
            "ready_selection_enabled": ready_use_enabled is True,
            "explicit_selection_ready": selected_state["state"] == "READY",
            "selected_target_exact": selected_state["selected_target"] == ready_choice.normalized_root,
            "selected_fingerprint_exact": selected_state["target_fingerprint"] == ready_choice.target_fingerprint,
            "startup_no_discovery_rows": startup_rows == 0 and startup_state == "IDLE",
            "live_system_refused": live_state == b50.STATE_UNSUPPORTED and live_reason == "live_system_volume_refused",
            "no_unlock_action": "unlock" not in button_commands,
            "no_mount_write_action": "mount-write" not in button_commands,
            "target_byte_identical": before == after,
            "no_write_attempt": result["safety"]["write_attempted"] is False,
            "no_unlock_attempt": result["safety"]["unlock_attempted"] is False,
            "no_mount_mutation": result["safety"]["mount_mutation"] is False,
            "no_destructive_authority": selection.safety_contract()["automatic_destructive_action"] is False,
        }

        payload = {
            "profile": selection.PROFILE,
            "checkpoint": CHECKPOINT,
            "passed": all(checks.values()),
            "checks": checks,
            "detail": {
                "session_id": snapshot.session_id,
                "correlation_id": snapshot.correlation_id,
                "counts": snapshot.counts,
                "states": [item.state for item in snapshot.targets],
                "ready_target": ready_choice.normalized_root,
                "ready_fingerprint": ready_choice.target_fingerprint,
                "selected_state": selected_state,
                "live_system_state": live_state,
                "live_system_reason": live_reason,
                "button_commands": sorted(button_commands),
            },
            "new_mutation_authority_added": False,
            "automatic_destructive_action_enabled": False,
            "unlock_enabled": False,
            "mount_write_enabled": False,
        }

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="acceptance-v011-beta6-b61.json")
    args = parser.parse_args()
    payload = run_acceptance(Path(args.output))
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if payload["passed"] else 4


if __name__ == "__main__":
    raise SystemExit(main())

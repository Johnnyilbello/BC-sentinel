from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

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


def _candidate(root: str, fingerprint: str, *, state: str = discovery.STATE_READY, reason: str = "validated_by_rr6_target_contract", locked: bool | None = False) -> dict:
    return {
        "root": root,
        "normalized_root": root,
        "discovery_source": "acceptance_fixture",
        "state": state,
        "reason": reason,
        "markers_present": list(discovery.WINDOWS_MARKERS) if state == discovery.STATE_READY else [],
        "markers_missing": [] if state == discovery.STATE_READY else list(discovery.WINDOWS_MARKERS),
        "target_fingerprint": fingerprint,
        "bitlocker": {"provider": "fixture", "available": locked is not None, "locked": locked},
        "write_attempted": False,
        "elapsed_ms": 1.0,
    }


def _payload(candidates: list[dict]) -> dict:
    return {
        "schema": discovery.RESULT_SCHEMA,
        "profile": discovery.PROFILE,
        "session_id": "B61-ACCEPTANCE",
        "correlation_id": "B61-ACCEPTANCE-CORRELATION",
        "created_utc": "2026-09-12T00:00:00Z",
        "candidates": candidates,
        "safety": _safe_flags(),
    }


def run_acceptance() -> dict:
    checks: dict[str, bool] = {}
    failures: list[str] = []

    def check(name: str, condition: bool) -> None:
        checks[name] = bool(condition)
        if not condition:
            failures.append(name)

    contract = model.validate_engine_contract()
    check("parent_b60_contract_green", contract.get("passed") is True)
    check("startup_dispatch_false", contract.get("startup_dispatch") is False)
    check("automatic_discovery_false", contract.get("automatic_discovery") is False)
    check("automatic_selection_false", contract.get("automatic_selection") is False)
    check("automatic_rescue_dispatch_false", contract.get("automatic_rescue_dispatch") is False)

    one = model.build_discovery_view(_payload([_candidate("D:\\", "ONE-FP")]))
    check("one_ready_is_recommended", len(one.targets) == 1 and one.targets[0].status == model.STATUS_RECOMMENDED)
    check("recommendation_not_selection", one.recommended_target_id != "" and model.initial_state().selected_target_id == "")

    multi = model.build_discovery_view(_payload([
        _candidate("D:\\", "D-FP"),
        _candidate("E:\\", "E-FP"),
    ]))
    check("multi_target_no_silent_recommendation", multi.recommended_target_id == "")
    check("multi_target_explicit_selection", multi.explicit_selection_required is True and all(row.status == model.STATUS_AVAILABLE for row in multi.targets))

    locked_record = _candidate("F:\\", "", state=discovery.STATE_LOCKED, reason="bitlocker_volume_locked", locked=True)
    locked_view = model.build_discovery_view(_payload([locked_record]))
    check("locked_target_fail_closed", locked_view.targets[0].status == model.STATUS_NEEDS_ATTENTION and not locked_view.targets[0].selectable)

    ambiguous = model.build_discovery_view(_payload([
        _candidate("D:\\OfflineA", "DUP-FP"),
        _candidate("E:\\OfflineB", "DUP-FP"),
    ]))
    check("duplicate_identity_ambiguous", all(row.status == model.STATUS_AMBIGUOUS for row in ambiguous.targets))
    check("ambiguous_not_selectable", all(not row.selectable for row in ambiguous.targets))
    check("ambiguous_cards_have_unique_ids", len({row.target_id for row in ambiguous.targets}) == 2)

    unsafe = _payload([_candidate("D:\\", "UNSAFE-FP")])
    unsafe["safety"]["mount_mutation"] = True
    try:
        model.build_discovery_view(unsafe)
    except model.DiscoverySafetyError:
        check("unsafe_discovery_refused", True)
    else:
        check("unsafe_discovery_refused", False)

    selected = model.select_target(model.initial_state(), one, one.targets[0].target_id)
    check("selection_is_explicit", selected.state == "TARGET_SELECTED" and selected.selection_revalidated is False)
    same = model.revalidate_selection(selected, _payload([_candidate("D:\\", "ONE-FP")]))
    check("same_identity_revalidates", same.selection_revalidated is True)

    changed_view = model.build_discovery_view(_payload([_candidate("G:\\", "OLD-FP")]))
    changed_state = model.select_target(model.initial_state(), changed_view, changed_view.targets[0].target_id)
    try:
        model.revalidate_selection(changed_state, _payload([_candidate("G:\\", "NEW-FP")]))
    except model.TargetSelectionError:
        check("changed_identity_refused", True)
    else:
        check("changed_identity_refused", False)

    calls: list[str] = []

    def forbidden_startup_provider() -> dict:
        calls.append("called")
        raise AssertionError("discovery provider called during startup")

    app = QApplication.instance() or QApplication([])
    window = ui.HomeWindow(discovery_provider=forbidden_startup_provider)
    try:
        check("home_window_constructs", window.windowTitle() == ui.WINDOW_TITLE)
        check("home_startup_passive", calls == [] and window.ui_state.state == "IDLE")
        check("continue_disabled", window.next_button.isEnabled() is False)
    finally:
        window.close()
        app.processEvents()

    return {
        "profile": model.PROFILE,
        "schema": model.SCHEMA,
        "passed": not failures,
        "checks": checks,
        "failures": failures,
        "note": "Synthetic/local B6-1 acceptance only. Real Windows target acceptance remains required before stabilization.",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel B6-1 deterministic Home target UX acceptance")
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    result = run_acceptance()
    text = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0 if result["passed"] else 4


if __name__ == "__main__":
    raise SystemExit(main())

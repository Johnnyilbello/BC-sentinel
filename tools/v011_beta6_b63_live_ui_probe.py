from __future__ import annotations

import argparse
import json
from pathlib import Path
from time import monotonic

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication

from sentinel import home_smart_scan as smart
from sentinel.home_smart_scan_window import B63SecurityOverviewWindow

CHECKPOINT = "B6-3.5-live-home-ui"


def evaluate_evidence(evidence: dict) -> tuple[bool, list[str]]:
    failures: list[str] = []
    initial = dict(evidence.get("initial") or {})
    runtime = dict(evidence.get("runtime") or {})
    final = dict(evidence.get("final") or {})
    mode = str(evidence.get("mode") or "complete")

    if initial.get("provider_available") is not True:
        failures.append("provider_not_available")
    if initial.get("smart_scan_enabled") is not True:
        failures.append("smart_scan_not_enabled_before_start")
    if initial.get("full_scan_enabled") is not False:
        failures.append("full_scan_must_remain_disabled")
    if runtime.get("running_observed") is not True:
        failures.append("running_state_not_observed")
    if runtime.get("scan_page_current_while_running") is not True:
        failures.append("scan_page_not_current_while_running")
    if runtime.get("cancel_visible_while_running") is not True:
        failures.append("cancel_button_not_visible_while_running")
    if runtime.get("launch_disabled_while_running") is not True:
        failures.append("launch_actions_not_disabled_while_running")
    if int(runtime.get("heartbeat_ticks_while_running") or 0) < 5:
        failures.append("ui_heartbeat_insufficient")
    if float(runtime.get("max_heartbeat_gap_ms") or 999999.0) > 1500.0:
        failures.append("ui_event_loop_stall_detected")
    if int(runtime.get("progress_sample_count") or 0) < 2:
        failures.append("insufficient_visible_progress_samples")
    if runtime.get("progress_advanced") is not True:
        failures.append("visible_progress_did_not_advance")
    if final.get("no_destructive_authority") is not True:
        failures.append("destructive_authority_present")
    if final.get("result_rendered") is not True:
        failures.append("result_not_rendered")
    if final.get("advanced_details_available") is not True:
        failures.append("advanced_details_not_available")
    if int(final.get("horizontal_scroll_max") or 0) != 0:
        failures.append("dashboard_horizontal_overflow")
    if int(final.get("scan_page_horizontal_scroll_max") or 0) != 0:
        failures.append("scan_page_horizontal_overflow")

    state = str(final.get("state") or "")
    coverage = str(final.get("coverage") or "")
    if mode == "complete":
        if state not in {smart.STATE_COMPLETED_CLEAN, smart.STATE_COMPLETED_FINDINGS}:
            failures.append(f"unexpected_complete_mode_state:{state or 'missing'}")
        if coverage != smart.COVERAGE_COMPLETE:
            failures.append(f"complete_mode_coverage_not_complete:{coverage or 'missing'}")
    elif mode == "cancel":
        if runtime.get("cancel_click_sent") is not True:
            failures.append("cancel_click_not_sent")
        if state != smart.STATE_CANCELLED:
            failures.append(f"cancel_mode_state_not_cancelled:{state or 'missing'}")
        if coverage != smart.COVERAGE_INCOMPLETE:
            failures.append(f"cancel_mode_coverage_not_incomplete:{coverage or 'missing'}")
    else:
        failures.append(f"unknown_mode:{mode}")

    if evidence.get("timeout") is True:
        failures.append("probe_timeout")
    return not failures, failures


def run_probe(
    *,
    mode: str,
    cancel_after_seconds: float,
    timeout_seconds: float,
    hold_seconds: float,
) -> dict:
    app = QApplication.instance() or QApplication([])
    window = B63SecurityOverviewWindow()
    window.resize(1600, 980)
    window.show()
    app.processEvents()
    window._apply_responsive_layout(force=True)
    window._sync_all_scroll_widths()
    app.processEvents()

    evidence: dict = {
        "checkpoint": CHECKPOINT,
        "mode": mode,
        "timeout": False,
        "initial": {
            "provider_available": window.smart_scan_coordinator.is_available(),
            "provider_contract": dict(window.smart_scan_contract),
            "provider_load": dict(window.smart_scan_provider_load),
            "smart_scan_enabled": window.scan_page.quick_scan.isEnabled(),
            "full_scan_enabled": window.scan_page.full_scan.isEnabled(),
            "page_count": window.stack.count(),
        },
        "runtime": {
            "running_observed": False,
            "scan_page_current_while_running": False,
            "cancel_visible_while_running": False,
            "launch_disabled_while_running": False,
            "heartbeat_ticks_while_running": 0,
            "max_heartbeat_gap_ms": 0.0,
            "progress_samples": [],
            "progress_sample_count": 0,
            "progress_advanced": False,
            "cancel_click_sent": False,
        },
        "final": {},
    }

    started_at = monotonic()
    running_started_at: float | None = None
    last_heartbeat_at: float | None = None
    last_progress_text = ""
    progress_percents: list[int] = []
    finalized = False
    finish_scheduled = False

    heartbeat = QTimer()
    heartbeat.setInterval(100)

    def capture_final() -> None:
        nonlocal finalized
        if finalized:
            return
        finalized = True
        result = window.last_smart_scan_result
        final: dict = {
            "result_rendered": result is not None and window.scan_page.coverage_label.isVisible(),
            "advanced_details_available": window.scan_page.advanced_button.isVisible(),
            "task_title": window.scan_page.task_title.text(),
            "task_subtitle": window.scan_page.task_subtitle.text(),
            "coverage_text": window.scan_page.coverage_label.text(),
            "horizontal_scroll_max": window.page_scroll.horizontalScrollBar().maximum(),
            "scan_page_horizontal_scroll_max": window.scan_scroll.horizontalScrollBar().maximum(),
        }
        if result is not None:
            final.update(
                {
                    "state": result.state,
                    "coverage": result.coverage,
                    "completed_checks": result.completed_checks,
                    "total_checks": result.total_checks,
                    "findings_count": len(result.findings),
                    "highest_severity": result.highest_severity,
                    "elapsed_ms": result.elapsed_ms,
                    "no_destructive_authority": not (
                        result.automatic_quarantine
                        or result.automatic_repair
                        or result.automatic_destructive_action
                    ),
                    "result": result.to_dict(),
                }
            )
        else:
            final["no_destructive_authority"] = True
        evidence["final"] = final
        passed, failures = evaluate_evidence(evidence)
        evidence["passed"] = passed
        evidence["failures"] = failures
        heartbeat.stop()
        window.close()
        app.quit()

    def schedule_finish() -> None:
        nonlocal finish_scheduled
        if finish_scheduled:
            return
        finish_scheduled = True
        QTimer.singleShot(max(0, int(hold_seconds * 1000)), capture_final)

    def tick() -> None:
        nonlocal running_started_at, last_heartbeat_at, last_progress_text
        now = monotonic()
        if now - started_at > timeout_seconds:
            evidence["timeout"] = True
            if window.smart_scan_coordinator.state == smart.STATE_RUNNING:
                window.smart_scan_coordinator.request_cancel()
            schedule_finish()
            return

        state = window.smart_scan_coordinator.state
        if state == smart.STATE_RUNNING:
            if running_started_at is None:
                running_started_at = now
            evidence["runtime"]["running_observed"] = True
            evidence["runtime"]["scan_page_current_while_running"] = bool(
                evidence["runtime"]["scan_page_current_while_running"]
                or window.stack.currentWidget() is window.scan_scroll
            )
            evidence["runtime"]["cancel_visible_while_running"] = bool(
                evidence["runtime"]["cancel_visible_while_running"]
                or (window.scan_page.cancel_scan.isVisible() and window.scan_page.cancel_scan.isEnabled())
            )
            evidence["runtime"]["launch_disabled_while_running"] = bool(
                evidence["runtime"]["launch_disabled_while_running"]
                or (
                    not window.scan_page.quick_scan.isEnabled()
                    and not window.smart_scan_button.isEnabled()
                    and not window.sidebar_scan_button.isEnabled()
                )
            )
            evidence["runtime"]["heartbeat_ticks_while_running"] += 1
            if last_heartbeat_at is not None:
                gap_ms = (now - last_heartbeat_at) * 1000.0
                evidence["runtime"]["max_heartbeat_gap_ms"] = max(
                    float(evidence["runtime"]["max_heartbeat_gap_ms"]), gap_ms
                )
            last_heartbeat_at = now

            label = window.scan_page.progress_label.text()
            if label and label != last_progress_text:
                last_progress_text = label
                sample = {
                    "at_ms": round((now - started_at) * 1000.0, 1),
                    "text": label,
                }
                evidence["runtime"]["progress_samples"].append(sample)
                if label.startswith("Progresso "):
                    try:
                        percent = int(label.split("Progresso ", 1)[1].split("%", 1)[0])
                        progress_percents.append(percent)
                    except (ValueError, IndexError):
                        pass

            if mode == "cancel" and running_started_at is not None:
                if (
                    not evidence["runtime"]["cancel_click_sent"]
                    and now - running_started_at >= cancel_after_seconds
                    and window.scan_page.cancel_scan.isVisible()
                    and window.scan_page.cancel_scan.isEnabled()
                ):
                    window.scan_page.cancel_scan.click()
                    evidence["runtime"]["cancel_click_sent"] = True

        evidence["runtime"]["progress_sample_count"] = len(evidence["runtime"]["progress_samples"])
        evidence["runtime"]["progress_advanced"] = bool(progress_percents and max(progress_percents) > 0)

        if window.last_smart_scan_result is not None:
            schedule_finish()

    def start_via_ui() -> None:
        if not window.smart_scan_coordinator.is_available():
            schedule_finish()
            return
        window.scan_page.quick_scan.click()

    heartbeat.timeout.connect(tick)
    heartbeat.start()
    QTimer.singleShot(500, start_via_ui)
    app.exec()

    if not finalized:
        capture_final()
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser(description="BC Sentinel B6-3.5 live Home UI acceptance probe")
    parser.add_argument("--mode", choices=("complete", "cancel"), default="complete")
    parser.add_argument("--cancel-after-seconds", type=float, default=2.0)
    parser.add_argument("--timeout-seconds", type=float, default=120.0)
    parser.add_argument("--hold-seconds", type=float, default=2.0)
    parser.add_argument("--output", default="acceptance-v011-beta6-b635-live-ui.json")
    args = parser.parse_args()

    evidence = run_probe(
        mode=args.mode,
        cancel_after_seconds=max(0.1, args.cancel_after_seconds),
        timeout_seconds=max(5.0, args.timeout_seconds),
        hold_seconds=max(0.0, args.hold_seconds),
    )
    output = Path(args.output)
    output.write_text(json.dumps(evidence, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")

    final = dict(evidence.get("final") or {})
    runtime = dict(evidence.get("runtime") or {})
    summary = {
        "checkpoint": CHECKPOINT,
        "mode": args.mode,
        "passed": bool(evidence.get("passed")),
        "failures": list(evidence.get("failures") or []),
        "state": final.get("state"),
        "coverage": final.get("coverage"),
        "elapsed_ms": final.get("elapsed_ms"),
        "findings_count": final.get("findings_count"),
        "heartbeat_ticks_while_running": runtime.get("heartbeat_ticks_while_running"),
        "max_heartbeat_gap_ms": runtime.get("max_heartbeat_gap_ms"),
        "progress_sample_count": runtime.get("progress_sample_count"),
        "progress_advanced": runtime.get("progress_advanced"),
        "cancel_click_sent": runtime.get("cancel_click_sent"),
        "output": str(output),
    }
    print(json.dumps(summary, indent=2, ensure_ascii=False, sort_keys=True))
    return 0 if evidence.get("passed") else 4


if __name__ == "__main__":
    raise SystemExit(main())

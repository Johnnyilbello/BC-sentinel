from tools.v011_beta6_b63_live_ui_probe import evaluate_evidence


def _base_evidence(mode: str, state: str, coverage: str) -> dict:
    return {
        "mode": mode,
        "timeout": False,
        "initial": {
            "provider_available": True,
            "smart_scan_enabled": True,
            "full_scan_enabled": False,
        },
        "runtime": {
            "running_observed": True,
            "scan_page_current_while_running": True,
            "cancel_visible_while_running": True,
            "launch_disabled_while_running": True,
            "heartbeat_ticks_while_running": 20,
            "max_heartbeat_gap_ms": 150.0,
            "progress_sample_count": 8,
            "progress_advanced": True,
            "cancel_click_sent": mode == "cancel",
        },
        "final": {
            "state": state,
            "coverage": coverage,
            "no_destructive_authority": True,
            "result_rendered": True,
            "advanced_details_available": True,
            "horizontal_scroll_max": 0,
            "scan_page_horizontal_scroll_max": 0,
        },
    }


def test_complete_live_ui_evidence_contract_accepts_complete_terminal_result():
    evidence = _base_evidence("complete", "COMPLETED_FINDINGS", "COMPLETE")
    passed, failures = evaluate_evidence(evidence)
    assert passed is True
    assert failures == []


def test_cancel_live_ui_evidence_contract_requires_cancelled_incomplete_result():
    evidence = _base_evidence("cancel", "CANCELLED", "INCOMPLETE")
    passed, failures = evaluate_evidence(evidence)
    assert passed is True
    assert failures == []


def test_live_ui_evidence_contract_fails_closed_on_stall_or_false_complete_cancel():
    evidence = _base_evidence("cancel", "COMPLETED_CLEAN", "COMPLETE")
    evidence["runtime"]["max_heartbeat_gap_ms"] = 2500.0
    evidence["runtime"]["progress_advanced"] = False
    passed, failures = evaluate_evidence(evidence)
    assert passed is False
    assert "ui_event_loop_stall_detected" in failures
    assert "visible_progress_did_not_advance" in failures
    assert "cancel_mode_state_not_cancelled:COMPLETED_CLEAN" in failures
    assert "cancel_mode_coverage_not_incomplete:COMPLETE" in failures

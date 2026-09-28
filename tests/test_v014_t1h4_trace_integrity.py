from __future__ import annotations

from sentinel import beta14_safe_adversary_matrix as b141


def _trace() -> dict:
    scenario = b141.SCENARIOS[0]
    return b141.make_trace(
        scenario_id=scenario["scenario_id"],
        signals=scenario["required_signals"],
    )


def test_b141_trace_id_is_bound_to_original_material() -> None:
    trace = _trace()
    assert b141.validate_trace(trace) == ()


def test_b141_rejects_signal_tampering_with_stale_trace_id() -> None:
    trace = _trace()
    trace["signals"] = sorted([*trace["signals"], "UNKNOWN_LOCAL_REPUTATION"])
    assert "b141:trace_id_mismatch" in b141.validate_trace(trace)


def test_b141_rejects_suppressor_tampering_with_stale_trace_id() -> None:
    trace = _trace()
    trace["known_admin_or_user_workflow"] = True
    assert "b141:trace_id_mismatch" in b141.validate_trace(trace)


def test_b141_rejects_valid_scenario_swap_with_stale_trace_id() -> None:
    trace = _trace()
    trace["scenario_id"] = b141.SCENARIOS[1]["scenario_id"]
    assert "b141:trace_id_mismatch" in b141.validate_trace(trace)


def test_b141_rejects_forged_prefixed_trace_id() -> None:
    trace = _trace()
    trace["trace_id"] = "b141:" + ("0" * 24)
    failures = b141.validate_trace(trace)
    assert "b141:trace_id_mismatch" in failures


def test_b141_evaluate_fails_closed_on_tampered_trace_identity() -> None:
    trace = _trace()
    trace["signals"] = sorted([*trace["signals"], "UNKNOWN_LOCAL_REPUTATION"])
    result = b141.evaluate_trace(trace)
    assert result["passed"] is False
    assert "b141:trace_id_mismatch" in result["failures"]


def test_b141_rejects_unhashable_scenario_id_without_crashing() -> None:
    trace = _trace()
    trace["scenario_id"] = ["B14-EMU-SCRIPT-CHAIN-001"]
    failures = b141.validate_trace(trace)
    assert "b141:scenario_unknown" in failures


def test_b141_evaluate_fails_closed_on_unhashable_scenario_id() -> None:
    trace = _trace()
    trace["scenario_id"] = {"unexpected": "object"}
    result = b141.evaluate_trace(trace)
    assert result["passed"] is False
    assert "b141:scenario_unknown" in result["failures"]

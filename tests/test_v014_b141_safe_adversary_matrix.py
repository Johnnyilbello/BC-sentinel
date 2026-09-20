from __future__ import annotations

from sentinel import beta14_safe_adversary_matrix as b141


def test_b141_binds_exact_b140_checkpoint() -> None:
    report = b141.self_check()
    assert report["passed"] is True
    assert report["source_checkpoint"] == "checkpoint/v014-b140-pass"
    assert report["source_checkpoint_commit"] == "a29de186a95d006b83fcb4e1c17992068b216255"


def test_b141_matrix_has_six_multi_stage_families() -> None:
    report = b141.self_check()
    assert report["scenario_count"] == 6
    assert report["control_count"] == 18


def test_b141_positive_controls_alert() -> None:
    matrix = b141.acceptance_matrix()
    assert all(row["positive"]["outcome"] == b141.OUTCOME_ALERT for row in matrix["rows"])


def test_b141_admin_controls_review_instead_of_alert() -> None:
    matrix = b141.acceptance_matrix()
    assert all(
        row["administrative"]["outcome"] == b141.OUTCOME_REVIEW
        for row in matrix["rows"]
    )


def test_b141_benign_controls_do_not_alert() -> None:
    matrix = b141.acceptance_matrix()
    assert all(row["benign"]["outcome"] == b141.OUTCOME_BENIGN for row in matrix["rows"])


def test_b141_inert_trace_rejects_real_execution() -> None:
    scenario = b141.SCENARIOS[0]
    trace = b141.make_trace(
        scenario_id=scenario["scenario_id"],
        signals=scenario["required_signals"],
    )
    trace["real_execution"] = True
    assert "b141:real_execution_forbidden" in b141.validate_trace(trace)


def test_b141_inert_trace_rejects_network_activity() -> None:
    scenario = b141.SCENARIOS[0]
    trace = b141.make_trace(
        scenario_id=scenario["scenario_id"],
        signals=scenario["required_signals"],
    )
    trace["real_network_activity"] = True
    assert "b141:real_network_activity_forbidden" in b141.validate_trace(trace)


def test_b141_inert_trace_rejects_real_persistence_mutation() -> None:
    scenario = b141.SCENARIOS[2]
    trace = b141.make_trace(
        scenario_id=scenario["scenario_id"],
        signals=scenario["required_signals"],
    )
    trace["real_persistence_mutation"] = True
    assert "b141:real_persistence_mutation_forbidden" in b141.validate_trace(trace)


def test_b141_inert_trace_rejects_credential_access() -> None:
    scenario = b141.SCENARIOS[4]
    trace = b141.make_trace(
        scenario_id=scenario["scenario_id"],
        signals=scenario["required_signals"],
    )
    trace["real_credential_access"] = True
    assert "b141:real_credential_access_forbidden" in b141.validate_trace(trace)


def test_b141_inert_trace_rejects_real_data_encryption() -> None:
    scenario = b141.SCENARIOS[3]
    trace = b141.make_trace(
        scenario_id=scenario["scenario_id"],
        signals=scenario["required_signals"],
    )
    trace["real_data_encryption"] = True
    assert "b141:real_data_encryption_forbidden" in b141.validate_trace(trace)


def test_b141_requires_disposable_workspace_model() -> None:
    scenario = b141.SCENARIOS[1]
    trace = b141.make_trace(
        scenario_id=scenario["scenario_id"],
        signals=scenario["required_signals"],
        disposable_workspace=False,
    )
    assert "b141:disposable_workspace_required" in b141.validate_trace(trace)


def test_b141_no_coverage_promotion_or_authority_expansion() -> None:
    report = b141.self_check()
    assert report["source_coverage"] == {"PARTIAL": 4, "GAP": 0, "VERIFIED": 7}
    assert report["coverage_promoted"] is False
    assert report["authority_expanded"] is False


def test_b141_safety_boundaries_remain_non_destructive() -> None:
    boundaries = b141.matrix_contract()["safety_boundaries"]
    assert boundaries["metadata_only"] is True
    assert boundaries["harmless_fixtures_only"] is True
    assert boundaries["disposable_workspace_model_only"] is True
    assert boundaries["real_malware_execution"] is False
    assert boundaries["real_data_encryption"] is False
    assert boundaries["credential_access"] is False
    assert boundaries["network_io"] is False
    assert boundaries["propagation"] is False
    assert boundaries["security_control_disabling"] is False
    assert boundaries["real_registry_persistence"] is False
    assert boundaries["service_driver_mutation"] is False


def test_b141_contract_is_deterministic() -> None:
    first = b141.self_check()
    second = b141.self_check()
    assert first["passed"] is True
    assert first["deterministic_contract"] is True
    assert first["contract_digest"] == second["contract_digest"]

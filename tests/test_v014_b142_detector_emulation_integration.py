from __future__ import annotations

from sentinel import beta14_detector_emulation_integration as b142
from sentinel import beta14_safe_adversary_matrix as b141


def test_b142_binds_exact_b141_checkpoint() -> None:
    report = b142.self_check()
    assert report["passed"] is True
    assert report["source_checkpoint"] == "checkpoint/v014-b141-pass"
    assert report["source_checkpoint_commit"] == "b2a00aac183905ec7f5988ef558dcf5612761ad5"


def test_b142_runtime_detector_bindings_are_callable() -> None:
    assert b142.validate_runtime_bindings() == ()


def test_b142_has_five_real_detector_bindings_and_one_explicit_gap() -> None:
    report = b142.self_check()
    assert report["binding_count"] == 6
    assert report["bound_count"] == 5
    assert report["explicit_gap_count"] == 1
    assert report["explicit_gap_family"] == "ARCHIVE_METADATA"


def test_b142_archive_family_is_not_faked_as_supported() -> None:
    scenario = next(item for item in b141.SCENARIOS if item["family"] == "ARCHIVE_METADATA")
    trace = b141.make_trace(
        scenario_id=scenario["scenario_id"],
        signals=list(scenario["required_signals"]) + list(scenario["supporting_signals"]),
    )
    result = b142.integrate_trace(trace)
    assert result["passed"] is True
    assert result["integration_status"] == "EXPLICIT_GAP"
    assert result["detector_available"] is False
    assert result["gap_reason"] == "NO_ACCEPTED_ARCHIVE_CHAIN_DETECTOR"


def test_b142_script_family_maps_to_real_script_detector() -> None:
    scenario = next(item for item in b141.SCENARIOS if item["family"] == "SCRIPT_FILE_CHAIN")
    trace = b141.make_trace(
        scenario_id=scenario["scenario_id"],
        signals=list(scenario["required_signals"]) + list(scenario["supporting_signals"]),
    )
    result = b142.integrate_trace(trace)
    assert result["integration_status"] == "DETECTOR_BOUND"
    assert result["detector_module"] == "sentinel.beta12_script_abuse_controls"
    assert result["detector_entrypoint"] == "detect_control"


def test_b142_process_family_maps_to_real_process_tree_detector() -> None:
    scenario = next(item for item in b141.SCENARIOS if item["family"] == "PROCESS_ANCESTRY")
    trace = b141.make_trace(
        scenario_id=scenario["scenario_id"],
        signals=scenario["required_signals"],
    )
    result = b142.integrate_trace(trace)
    assert result["integration_status"] == "DETECTOR_BOUND"
    assert result["detector_module"] == "sentinel.beta12_process_tree_intelligence"


def test_b142_persistence_family_maps_to_real_autostart_detector() -> None:
    scenario = next(item for item in b141.SCENARIOS if item["family"] == "PERSISTENCE_METADATA")
    trace = b141.make_trace(
        scenario_id=scenario["scenario_id"],
        signals=scenario["required_signals"],
    )
    result = b142.integrate_trace(trace)
    assert result["integration_status"] == "DETECTOR_BOUND"
    assert result["detector_module"] == "sentinel.beta12_autostart_detection"


def test_b142_ransomware_family_maps_to_read_only_detector() -> None:
    scenario = next(item for item in b141.SCENARIOS if item["family"] == "RANSOMWARE_LIKE_WORKSPACE")
    trace = b141.make_trace(
        scenario_id=scenario["scenario_id"],
        signals=list(scenario["required_signals"]) + list(scenario["supporting_signals"]),
    )
    result = b142.integrate_trace(trace)
    assert result["integration_status"] == "DETECTOR_BOUND"
    assert result["detector_module"] == "sentinel.ransomware_detector"
    assert result["detector_entrypoint"] == "detect"


def test_b142_reputation_family_maps_to_local_classifier() -> None:
    scenario = next(item for item in b141.SCENARIOS if item["family"] == "LOCAL_REPUTATION")
    trace = b141.make_trace(
        scenario_id=scenario["scenario_id"],
        signals=scenario["required_signals"],
    )
    result = b142.integrate_trace(trace)
    assert result["integration_status"] == "DETECTOR_BOUND"
    assert result["detector_module"] == "sentinel.beta12_local_reputation"
    assert result["detector_entrypoint"] == "classify"


def test_b142_does_not_invoke_attack_payload_or_promote_coverage() -> None:
    matrix = b142.integration_matrix()
    assert matrix["coverage_promoted"] is False
    assert matrix["authority_expanded"] is False
    assert all(row["detector_invoked_with_attack_payload"] is False for row in matrix["rows"])
    assert all(row["real_execution"] is False for row in matrix["rows"])


def test_b142_preserves_canonical_coverage_and_authority() -> None:
    report = b142.self_check()
    assert report["source_coverage"] == {"PARTIAL": 4, "GAP": 0, "VERIFIED": 7}
    assert report["coverage_promoted"] is False
    assert report["authority_expanded"] is False
    assert report["detector_threshold_mutation"] is False


def test_b142_preserves_non_destructive_safety_boundaries() -> None:
    report = b142.self_check()
    assert report["real_attack_execution"] is False
    assert report["real_malware_executed"] is False
    assert report["network_io"] is False
    assert report["credential_access"] is False
    assert report["real_persistence_mutation"] is False
    assert report["real_data_encryption"] is False


def test_b142_contract_is_deterministic() -> None:
    first = b142.self_check()
    second = b142.self_check()
    assert first["passed"] is True
    assert first["deterministic_contract"] is True
    assert first["contract_digest"] == second["contract_digest"]
